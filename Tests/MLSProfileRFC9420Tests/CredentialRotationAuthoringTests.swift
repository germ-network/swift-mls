import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeKEM
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// Authoring a leaf credential / signature-key rotation (RFC 9420 §5.3.1) on the
/// two paths `NewSigningIdentity` opens: an Update proposal's leaf, and the
/// committer's own UpdatePath leaf. Post-seam (ADR 0002): `NewSigningIdentity`
/// carries no secret — the caller's role-tagged `sign:` closure routes
/// `.leafNode`/`.groupInfo` to the new key and `.framedContent` to the current
/// one (`MLS.RFC9420.signingClosure(_:current:new:)`). Both paths must
/// round-trip through the EXISTING receive path unchanged — a peer sees
/// `.credentialReplaced`, installs the new leaf, and later signatures verify
/// only under the new key, never the old one.
@Suite("Author a credential / signature-key rotation (§5.3.1)")
struct CredentialRotationAuthoringTests {
	static let provider = SelfInteropTests.provider

	enum TestSetupError: Error {
		case expectedProposalMessage
		case expectedProposalContent
		case expectedPublicCommit
	}

	/// A caller-authored rotation target: `NewSigningIdentity` (no secret,
	/// post-seam) plus the new SECRET a test's own closure needs to answer
	/// `.leafNode`/`.groupInfo` with — a fresh, really-signed key pair (so a
	/// self-verify failure would be caught, not assumed away) and a
	/// distinguishable credential.
	struct RotationTarget {
		let identity: MLS.RFC9420.NewSigningIdentity
		let signingKey: MLS.SignatureSecretKey
	}

	static func rotatedIdentity(_ name: String) throws -> RotationTarget {
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(provider)
		return RotationTarget(
			identity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: Data(name.utf8)),
				signatureKey: signatureKey),
			signingKey: signingKey)
	}

	// MARK: - Update-path rotation

	/// Bob authors `proposeUpdate(newIdentity:)` in the given framing, signing
	/// via the rotation ring (`current: bob's key, new: target.signingKey`);
	/// Alice verifies + commits by reference; both sides apply. Shared by the
	/// round-trip and key-enforcement tests so each only asserts its own
	/// property against a common, real two-step handshake.
	private static func rotateBobViaUpdate(
		framing: MLS.RFC9420.Group.HandshakeFraming
	) throws -> (
		t: PerMembershipReceiveTests.Trio, target: RotationTarget,
		bobLeaf: MLS.LeafIndex, oldPresentation: MLS.RFC9420.CredentialPresentation,
		events: [MLS.RFC9420.CommitEffect]
	) {
		var t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex
		let target = try Self.rotatedIdentity("bob-rotated")

		let oldRecord = try #require(t.bobView.tree.leaf(at: bobLeaf))
		let oldLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: oldRecord.encoded)
		let oldPresentation = MLS.RFC9420.CredentialPresentation(
			credential: oldLeaf.credential, signatureKey: oldLeaf.signatureKey)

		let (message, ref) = try t.bobView.proposeUpdate(
			provider,
			sign: MLS.RFC9420.signingClosure(
				provider, current: t.bob.signingKey, new: target.signingKey),
			framing: framing, newIdentity: target.identity)

		var store = MLS.RFC9420.ProposalStore()
		switch message {
		case .publicMessage(let proposalMessage):
			let verified = try t.aliceView.verifying(
				provider, proposal: proposalMessage)
			_ = try store.insert(verified, provider)
		case .privateMessage(let proposalMessage):
			let opened = try t.aliceView.unprotect(provider, message: proposalMessage)
			guard case .proposal(let verified) = opened.content else {
				throw TestSetupError.expectedProposalContent
			}
			_ = try store.insert(verified, provider)
		default:
			throw TestSetupError.expectedProposalMessage
		}

		let transition = try t.aliceView.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: t.alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		t.aliceView = transition.group
		let sent = transition.takeOutput()
		guard case .publicMessage(let commitMessage) = sent.message else {
			throw TestSetupError.expectedPublicCommit
		}
		let pending = sent.takePending()
		let events = pending.effects.events
		let applied = try pending.apply(onto: t.aliceView)
		t.aliceView = applied.group

		try t.bobView.process(
			provider, commit: commitMessage, proposals: store, psk: { _ in nil })

		return (t, target, bobLeaf, oldPresentation, events)
	}

	private static func assertUpdateRotationRoundTrips(
		framing: MLS.RFC9420.Group.HandshakeFraming
	) throws {
		let result = try rotateBobViaUpdate(framing: framing)
		let new = MLS.RFC9420.CredentialPresentation(
			credential: result.target.identity.credential,
			signatureKey: result.target.identity.signatureKey)
		#expect(
			result.events.contains(
				.credentialReplaced(
					leaf: result.bobLeaf, old: result.oldPresentation, new: new)
			))

		// Installation, not just the reported effect -- on both sides.
		for group in [result.t.aliceView, result.t.bobView] {
			let record = try #require(group.tree.leaf(at: result.bobLeaf))
			let installed = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			#expect(installed.credential == result.target.identity.credential)
			#expect(installed.signatureKey == result.target.identity.signatureKey)
		}
	}

	@Test(
		"an Update rotation, publicly framed, round-trips to credentialReplaced and installs the new leaf"
	)
	func updateRotationRoundTripsPublic() throws {
		try Self.assertUpdateRotationRoundTrips(framing: .publicMessage)
	}

	@Test(
		"an Update rotation, privately framed, round-trips to credentialReplaced and installs the new leaf"
	)
	func updateRotationRoundTripsPrivate() throws {
		try Self.assertUpdateRotationRoundTrips(framing: .privateMessage)
	}

	@Test(
		"after an Update rotation, the new key verifies application messages and the old key is rejected"
	)
	func updateRotationKeyEnforcement() throws {
		let provider = Self.provider
		let result = try Self.rotateBobViaUpdate(framing: .publicMessage)
		var t = result.t

		let plaintext = Data("hello-from-rotated-bob".utf8)
		let sealed = try t.bobView.protect(
			provider, applicationData: plaintext,
			signingKey: result.target.signingKey)
		let opened = try t.aliceView.unprotect(provider, message: sealed)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == plaintext)

		let sealedOld = try t.bobView.protect(
			provider, applicationData: plaintext, signingKey: t.bob.signingKey)
		#expect {
			_ = try t.aliceView.unprotect(provider, message: sealedOld)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	// MARK: - Commit-path (committer UpdatePath) rotation

	/// Alice authors `committing(newIdentity:)` (optionally alongside an Add),
	/// signing via the rotation ring; Bob validates + applies. Shared by the
	/// round-trip, key-enforcement, and rotation-plus-Add tests.
	private static func rotateAliceViaCommit(
		addingProposals: [MLS.RFC9420.ProposalOrRef] = []
	) throws -> (
		t: PerMembershipReceiveTests.Trio, target: RotationTarget,
		aliceLeaf: MLS.LeafIndex, oldPresentation: MLS.RFC9420.CredentialPresentation,
		events: [MLS.RFC9420.CommitEffect], welcome: MLS.RFC9420.Welcome?,
		peerEvents: [MLS.RFC9420.CommitEffect]
	) {
		var t = try PerMembershipReceiveTests.trio()
		let aliceLeaf = t.aliceView.myLeafIndex
		let target = try Self.rotatedIdentity("alice-rotated")

		let oldRecord = try #require(t.aliceView.tree.leaf(at: aliceLeaf))
		let oldLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: oldRecord.encoded)
		let oldPresentation = MLS.RFC9420.CredentialPresentation(
			credential: oldLeaf.credential, signatureKey: oldLeaf.signatureKey)

		let transition = try t.aliceView.committing(
			provider, proposals: addingProposals,
			sign: MLS.RFC9420.signingClosure(
				provider, current: t.alice.signingKey, new: target.signingKey),
			randomness: .generate(provider), framing: .publicMessage,
			newIdentity: target.identity)
		t.aliceView = transition.group
		let sent = transition.takeOutput()
		guard case .publicMessage(let commitMessage) = sent.message else {
			throw TestSetupError.expectedPublicCommit
		}
		let welcome = sent.welcome
		let pending = sent.takePending()
		let events = pending.effects.events
		let applied = try pending.apply(onto: t.aliceView)
		t.aliceView = applied.group

		let bobPending = try t.bobView.validating(
			provider, commit: commitMessage, proposals: .init(), psk: { _ in nil })
		// SC-3b: captured before `apply` consumes `bobPending` (`~Copyable`) --
		// the PEER's own view of this commit's effects, not the committer's.
		let peerEvents = bobPending.effects.events
		let bobApplied = try bobPending.apply(onto: t.bobView)
		t.bobView = bobApplied.group

		return (t, target, aliceLeaf, oldPresentation, events, welcome, peerEvents)
	}

	@Test(
		"a committer path-leaf rotation round-trips to credentialReplaced and installs the new leaf"
	)
	func commitRotationRoundTrips() throws {
		let result = try Self.rotateAliceViaCommit()
		let new = MLS.RFC9420.CredentialPresentation(
			credential: result.target.identity.credential,
			signatureKey: result.target.identity.signatureKey)
		#expect(
			result.events.contains(
				.credentialReplaced(
					leaf: result.aliceLeaf, old: result.oldPresentation,
					new: new)))
		// SC-3b: the suite header promises "a peer sees `.credentialReplaced`" --
		// pin the PEER's own pending-commit effects, not just the committer's.
		#expect(
			result.peerEvents.contains(
				.credentialReplaced(
					leaf: result.aliceLeaf, old: result.oldPresentation,
					new: new)))

		let record = try #require(result.t.bobView.tree.leaf(at: result.aliceLeaf))
		let installed = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
		#expect(installed.credential == result.target.identity.credential)
		#expect(installed.signatureKey == result.target.identity.signatureKey)
	}

	@Test(
		"after a committer path-leaf rotation, the new key verifies application messages and the old key is rejected"
	)
	func commitRotationKeyEnforcement() throws {
		let provider = Self.provider
		let result = try Self.rotateAliceViaCommit()
		var t = result.t

		let plaintext = Data("hello-from-rotated-alice".utf8)
		let sealed = try t.aliceView.protect(
			provider, applicationData: plaintext,
			signingKey: result.target.signingKey)
		let opened = try t.bobView.unprotect(provider, message: sealed)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == plaintext)

		let sealedOld = try t.aliceView.protect(
			provider, applicationData: plaintext, signingKey: t.alice.signingKey)
		#expect {
			_ = try t.bobView.unprotect(provider, message: sealedOld)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	@Test(
		"a commit that rotates the committer AND adds a member: the Welcome joins under the new key"
	)
	func rotationPlusAddWelcomeJoins() throws {
		let provider = Self.provider
		let dave = try SelfInteropTests.member("rotation-dave")
		let result = try Self.rotateAliceViaCommit(
			addingProposals: [.proposal(.add(dave.keyPackage))])
		let welcome = try #require(result.welcome)

		// `joining` verifies GroupInfo against the POST-commit tree's leaf for
		// `signer` -- if the Welcome were (wrongly) signed with Alice's OLD key,
		// this throws `signatureVerificationFailed` before ever returning a
		// roster to inspect. (This is also the end-to-end proof for M2/S3's
		// GroupInfo/new leg: the real join path, not a shortcut.)
		let pendingJoin = try MLS.RFC9420.Group.joining(
			provider, welcome: welcome, credentials: dave.joinCredentials,
			psk: { _ in nil })
		#expect(
			pendingJoin.roster.contains {
				$0.leaf == result.aliceLeaf
					&& $0.presentation.credential
						== result.target.identity.credential
					&& $0.presentation.signatureKey
						== result.target.identity.signatureKey
			})
		_ = pendingJoin.apply()
	}

	// MARK: - No-rotation regression

	@Test(
		"proposeUpdate/committing without newIdentity still report `.updated`, never `.credentialReplaced`"
	)
	func noRotationRegression() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex
		let aliceLeaf = t.aliceView.myLeafIndex

		var bob = t.bobView
		let (message, ref) = try bob.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: .publicMessage)
		guard case .publicMessage(let proposalMessage) = message else {
			Issue.record("expected a public proposal")
			return
		}
		let verified = try t.aliceView.verifying(provider, proposal: proposalMessage)
		var store = MLS.RFC9420.ProposalStore()
		_ = try store.insert(verified, provider)
		let updateTransition = try t.aliceView.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: t.alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		let updateEvents = updateTransition.takeOutput().pending.effects.events
		#expect(updateEvents.contains(.updated(leaf: bobLeaf)))
		#expect(
			!updateEvents.contains {
				if case .credentialReplaced = $0 { true } else { false }
			})

		let commitTransition = try t.aliceView.committing(
			provider, proposals: [], signingKey: t.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		let commitEvents = commitTransition.takeOutput().pending.effects.events
		#expect(commitEvents.contains(.updated(leaf: aliceLeaf)))
		#expect(
			!commitEvents.contains {
				if case .credentialReplaced = $0 { true } else { false }
			})
	}

	// MARK: - M1: credential-only rotation via the `signingKey:` sugar

	@Test(
		"M1: a credential-only rotation (same key, new credential) round-trips via the signingKey: sugar"
	)
	func credentialOnlyRotationViaSigningKeySugar() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let aliceLeaf = t.aliceView.myLeafIndex

		let oldRecord = try #require(t.aliceView.tree.leaf(at: aliceLeaf))
		let oldLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: oldRecord.encoded)
		let oldPresentation = MLS.RFC9420.CredentialPresentation(
			credential: oldLeaf.credential, signatureKey: oldLeaf.signatureKey)

		// SAME key, only the credential changes -- coherent under the single-key
		// `signingKey:` sugar because the leaf still declares the key that
		// actually signs it, so the self-verify guard has nothing to catch.
		let newIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: Data("alice-renewed-cert".utf8)),
			signatureKey: t.alice.signatureKey)

		let transition = try t.aliceView.committing(
			provider, proposals: [], signingKey: t.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage,
			newIdentity: newIdentity)
		t.aliceView = transition.group
		let sent = transition.takeOutput()
		guard case .publicMessage(let commitMessage) = sent.message else {
			Issue.record("expected a public commit")
			return
		}
		let pending = sent.takePending()
		let events = pending.effects.events
		let applied = try pending.apply(onto: t.aliceView)
		t.aliceView = applied.group

		let bobPending = try t.bobView.validating(
			provider, commit: commitMessage, proposals: .init(), psk: { _ in nil })
		t.bobView = try bobPending.apply(onto: t.bobView).group

		let new = MLS.RFC9420.CredentialPresentation(
			credential: newIdentity.credential, signatureKey: newIdentity.signatureKey)
		#expect(
			events.contains(
				.credentialReplaced(leaf: aliceLeaf, old: oldPresentation, new: new)
			))
		for group in [t.aliceView, t.bobView] {
			let record = try #require(group.tree.leaf(at: aliceLeaf))
			let installed = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			#expect(installed.credential == newIdentity.credential)
			#expect(installed.signatureKey == t.alice.signatureKey)
		}
	}

	// MARK: - S2: a mis-routed leaf trips self-verify, on both authoring paths

	@Test(
		"S2: committing -- a closure that answers .leafNode with the CURRENT key instead of the new one trips self-verify"
	)
	func commitMisroutedLeafSignatureTripsSelfVerify() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let target = try Self.rotatedIdentity("alice-rotated")

		// A broken ring: every role answers with the CURRENT key, so the new
		// leaf declares `target.identity.signatureKey` but is actually signed
		// by `t.alice.signingKey`.
		let misrouted: MLS.RFC9420.SigningClosure = { request in
			try provider.sign(
				privateKey: t.alice.signingKey, content: request.signContent)
		}

		#expect {
			_ = try t.aliceView.committing(
				provider, proposals: [], sign: misrouted,
				randomness: .generate(provider), newIdentity: target.identity)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	@Test(
		"S2: proposeUpdate -- a closure that answers .leafNode with the CURRENT key instead of the new one trips self-verify"
	)
	func proposeUpdateMisroutedLeafSignatureTripsSelfVerify() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let target = try Self.rotatedIdentity("bob-rotated")
		// Captured as a plain local, not read from `t` inside the closure --
		// `proposeUpdate` is mutating, so a closure that captured `t.bob`
		// itself would read overlapping storage while `t.bobView`'s
		// exclusive-access window is open.
		let bobCurrentKey = t.bob.signingKey

		let misrouted: MLS.RFC9420.SigningClosure = { request in
			try provider.sign(
				privateKey: bobCurrentKey, content: request.signContent)
		}

		#expect {
			_ = try t.bobView.proposeUpdate(
				provider, sign: misrouted, newIdentity: target.identity)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	// MARK: - SC-1: a mis-routed envelope trips self-verify, on both authoring paths

	@Test(
		"SC-1: committing -- a closure that mis-routes .framedContent to an unrelated key is caught at authoring, before the commit is ever sealed"
	)
	func commitMisroutedEnvelopeSignatureTripsSelfVerify() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		// Unrelated to Alice's real leaf key -- no rotation is happening here at
		// all, so `.leafNode` (still requested every commit that carries a path,
		// §12.4.1) answers correctly with Alice's own key and passes the
		// existing leaf self-verify; only `.framedContent` is mis-routed, so
		// only the NEW envelope self-verify (SC-1) can be what catches this.
		let (wrongKey, _) = try GroupMutationTests.signingKeyPair(provider)

		let misrouted: MLS.RFC9420.SigningClosure = { request in
			switch request.role {
			case .framedContent:
				try provider.sign(
					privateKey: wrongKey, content: request.signContent)
			case .leafNode, .groupInfo:
				try provider.sign(
					privateKey: t.alice.signingKey, content: request.signContent
				)
			}
		}

		#expect {
			_ = try t.aliceView.committing(
				provider, proposals: [], sign: misrouted,
				randomness: .generate(provider))
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	@Test(
		"SC-1: proposeUpdate -- a closure that mis-routes .framedContent to an unrelated key is caught at authoring, before the proposal is ever sent"
	)
	func proposeUpdateMisroutedEnvelopeSignatureTripsSelfVerify() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		// See the analogous S2 test above for why this is captured as a plain
		// local rather than read from `t` inside the closure.
		let bobCurrentKey = t.bob.signingKey
		let (wrongKey, _) = try GroupMutationTests.signingKeyPair(provider)

		let misrouted: MLS.RFC9420.SigningClosure = { request in
			switch request.role {
			case .framedContent:
				try provider.sign(
					privateKey: wrongKey, content: request.signContent)
			case .leafNode, .groupInfo:
				try provider.sign(
					privateKey: bobCurrentKey, content: request.signContent)
			}
		}

		#expect {
			_ = try t.bobView.proposeUpdate(provider, sign: misrouted)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	// MARK: - M2: a mis-routed GroupInfo is caught at authoring

	@Test(
		"M2: a closure that mis-routes .groupInfo to an unrelated key is caught at authoring by makeWelcome's self-verify, not left to wedge the joiner"
	)
	func groupInfoMisroutingCaughtAtAuthoring() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let dave = try SelfInteropTests.member("rotation-dave")
		// Unrelated to Alice's current key or anything the post-commit tree's
		// signer leaf could ever declare -- no rotation is happening here at all.
		let (wrongKey, _) = try GroupMutationTests.signingKeyPair(provider)

		let misrouted: MLS.RFC9420.SigningClosure = { request in
			switch request.role {
			case .groupInfo:
				try provider.sign(
					privateKey: wrongKey, content: request.signContent)
			case .framedContent, .leafNode:
				try provider.sign(
					privateKey: t.alice.signingKey, content: request.signContent
				)
			}
		}

		// An Add alone never forces a path (§7.2.1), so this is pathless --
		// pinning that the GroupInfo self-verify catches the mis-route even
		// when no `.leafNode` signature is ever requested to catch it first.
		#expect {
			_ = try t.aliceView.committing(
				provider, proposals: [.proposal(.add(dave.keyPackage))],
				sign: misrouted, randomness: .generate(provider),
				includePath: false)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	// MARK: - S3: each emitted signature verifies under its EXPECTED key

	@Test(
		"S3: a rotation commit's leaf signature verifies under the NEW key and its envelope signature under the OLD key -- captured, not byte-compared"
	)
	func rotationSignaturesVerifyUnderExpectedKeys() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let dave = try SelfInteropTests.member("rotation-dave")
		let target = try Self.rotatedIdentity("alice-rotated")

		final class CapturingRing {
			private(set) var captured: [MLS.RFC9420.SignatureRole: Data] = [:]
			private let provider: any MLS.CipherSuiteProvider
			private let current: MLS.SignatureSecretKey
			private let new: MLS.SignatureSecretKey
			init(
				provider: any MLS.CipherSuiteProvider,
				current: MLS.SignatureSecretKey,
				new: MLS.SignatureSecretKey
			) {
				self.provider = provider
				self.current = current
				self.new = new
			}
			func sign(_ request: MLS.RFC9420.SigningRequest) throws -> Data {
				captured[request.role] = request.signContent
				switch request.role {
				case .framedContent:
					return try provider.sign(
						privateKey: current, content: request.signContent)
				case .leafNode, .groupInfo:
					return try provider.sign(
						privateKey: new, content: request.signContent)
				}
			}
		}

		let ring = CapturingRing(
			provider: provider, current: t.alice.signingKey, new: target.signingKey)
		let transition = try t.aliceView.committing(
			provider, proposals: [.proposal(.add(dave.keyPackage))], sign: ring.sign,
			randomness: .generate(provider), framing: .publicMessage,
			newIdentity: target.identity)

		guard case .publicMessage(let pub) = transition.output.message,
			case .commit(let commit) = pub.content.content,
			let path = commit.path
		else {
			Issue.record("expected a public commit with a path")
			return
		}

		// leaf: the WIRE signature verifies under the NEW key, not the old one.
		// `captured[.leafNode]` is the exact `Encode(SignContent)` bytes
		// `sign(_:role:label:content:)` computed once and handed the closure --
		// the same bytes the embedded field was produced over -- so this checks
		// the actual emitted signature, not an independently recomputed one.
		let leafContent = try #require(ring.captured[.leafNode])
		#expect(
			try provider.verify(
				publicKey: target.identity.signatureKey, content: leafContent,
				signature: path.leafNode.signature))
		#expect(
			try !provider.verify(
				publicKey: t.alice.signatureKey, content: leafContent,
				signature: path.leafNode.signature))

		// envelope (FramedContent): verifies under the CURRENT/old key.
		let framedContent = try #require(ring.captured[.framedContent])
		let envelopeSignature = try #require(pub.auth.signature)
		#expect(
			try provider.verify(
				publicKey: t.alice.signatureKey, content: framedContent,
				signature: envelopeSignature.data))
		#expect(
			try !provider.verify(
				publicKey: target.identity.signatureKey, content: framedContent,
				signature: envelopeSignature.data))

		// GroupInfo/new is pinned end-to-end by `rotationPlusAddWelcomeJoins`
		// via the real `Group.joining` verify -- not repeated here.
	}

	// MARK: - S1 / uniqueness guard

	@Test(
		"S1: rotating the committer into another member's current signature key is refused BEFORE any .leafNode signature is requested"
	)
	func sendSideDuplicateSignatureKeyGuard() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex
		let bobRecord = try #require(t.aliceView.tree.leaf(at: bobLeaf))
		let bobLeafNode = try MLS.RFC9420.LeafNode(mlsEncoded: bobRecord.encoded)

		// Self-consistent (so the self-verify guard doesn't mask this one): Bob's
		// current signature key, colliding with Bob's own current leaf.
		let collidingIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: Data("alice-rotated".utf8)),
			signatureKey: bobLeafNode.signatureKey)

		let recorder = SignerSeamTests.RoleRecorder(
			provider: provider, key: t.alice.signingKey)
		#expect(throws: MLS.RFC9420.GroupError.duplicateSignatureKey(leaf: bobLeaf)) {
			_ = try t.aliceView.committing(
				provider, proposals: [], sign: recorder.sign,
				randomness: .generate(provider), newIdentity: collidingIdentity)
		}
		// The reorder (S1): policy + uniqueness run BEFORE signing, so a
		// rejected rotation never burns a `.leafNode` ticket -- the closure
		// was never asked for ANY signature at all.
		#expect(recorder.roles.isEmpty)
	}

	@Test(
		"send-side: rotating into the signature key of a member added in the SAME commit is refused"
	)
	func sendSideDuplicateSignatureKeyWithConcurrentAdd() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let dave = try SelfInteropTests.member("rotation-dave")

		// Alice rotates into Dave's key while Dave is being added in the same
		// commit: the sweep runs over the post-apply tree, so Dave's freshly added
		// leaf is present and the collision is caught.
		let collidingIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: Data("alice-rotated".utf8)),
			signatureKey: dave.signatureKey)

		#expect {
			_ = try t.aliceView.committing(
				provider, proposals: [.proposal(.add(dave.keyPackage))],
				signingKey: t.alice.signingKey, randomness: .generate(provider),
				newIdentity: collidingIdentity)
		} throws: { error in
			guard case MLS.RFC9420.GroupError.duplicateSignatureKey = error else {
				return false
			}
			return true
		}
	}

	@Test(
		"a rotation forces a path: `includePath: false` with a newIdentity is refused, never silently dropped"
	)
	func rotationForcesPath() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let dave = try SelfInteropTests.member("rotation-dave")
		let target = try Self.rotatedIdentity("alice-rotated")

		// An Add-only list does NOT force a path (§7.2.1), so `pathRequired` is true
		// here for exactly one reason: the rotation. This pins the `newIdentity`
		// term of the predicate, not the incidental empty-commit path requirement.
		#expect(throws: MLS.RFC9420.GroupError.pathRequired) {
			_ = try t.aliceView.committing(
				provider, proposals: [.proposal(.add(dave.keyPackage))],
				signingKey: t.alice.signingKey, randomness: .generate(provider),
				includePath: false, newIdentity: target.identity)
		}
	}

	/// The receive-side twin of the guard above, genuinely constructed: a commit
	/// hand-assembled from the same `MLSTreeKEM` primitives `committing` itself
	/// uses (`beginCommitPath`/`finishCommitPath`/`applyUpdatePath`), bypassing
	/// the send-side guard entirely (this never calls `committing`), so the
	/// receiver's own §12.4.2/§7.6 sweep is what has to catch it. The forged path
	/// leaf's `signatureKey` collides with Carol's; only constructible here
	/// because the test harness holds Carol's real signing key -- a leaf's
	/// self-signature is checked against its own embedded `signatureKey`, so a
	/// colliding leaf must be signed by whoever actually holds that key's secret
	/// half. The path's encrypted secrets are never decrypted: the sweep this
	/// test pins runs immediately after the leaf merges and before decap, so
	/// their ciphertexts need not be meaningful.
	@Test(
		"receive-side: a crafted commit whose path leaf collides with another member's signature key is rejected"
	)
	func receiveSideDuplicateSignatureKeyGuard() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let committerLeaf = t.aliceView.myLeafIndex
		let carolLeaf = t.carolView.myLeafIndex

		let aliceRecord = try #require(t.aliceView.tree.leaf(at: committerLeaf))
		let aliceLeafNode = try MLS.RFC9420.LeafNode(mlsEncoded: aliceRecord.encoded)

		var newTree = t.aliceView.tree
		let pathStage = try newTree.beginCommitPath(
			sender: committerLeaf,
			firstPathSecret: SecretBytes(randomByteCount: provider.hashSize),
			provider)

		let (_, freshEncryptionKey) = try provider.hpkeGenerateKeyPair()
		var forgedLeaf = MLS.RFC9420.LeafNode(
			encryptionKey: freshEncryptionKey, signatureKey: t.carol.signatureKey,
			credential: aliceLeafNode.credential,
			capabilities: aliceLeafNode.capabilities,
			source: .commit(parentHash: pathStage.leafParentHash),
			extensions: aliceLeafNode.extensions, signature: Data())
		forgedLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: t.carol.signingKey, label: "LeafNodeTBS",
			content: try forgedLeaf.toBeSigned(
				placement: .inGroup(
					groupID: t.aliceView.context.groupID,
					leafIndex: committerLeaf)))

		let (pathNodes, _) = try newTree.finishCommitPath(
			pathStage, groupContext: Data(), excluding: [], provider)
		let updatePath = MLS.RFC9420.UpdatePath(
			leafNode: forgedLeaf,
			nodes: pathNodes.map(MLS.RFC9420.UpdatePathNode.init))

		let framed = MLS.RFC9420.FramedContent(
			groupID: t.aliceView.context.groupID, epoch: t.aliceView.context.epoch,
			sender: .member(committerLeaf), authenticatedData: Data(),
			content: .commit(.init(proposals: [], path: updatePath)))
		let forgedCommit = try MLS.RFC9420.protectPublic(
			provider, content: framed, groupContext: t.aliceView.context,
			confirmationTag: MLS.ConfirmationTag(
				Data(repeating: 0xAB, count: provider.hashSize)),
			signingKey: t.alice.signingKey,
			membershipKey: t.aliceView.epoch.membershipKey)

		#expect(throws: MLS.RFC9420.GroupError.duplicateSignatureKey(leaf: carolLeaf)) {
			_ = try t.bobView.validating(
				provider, commit: forgedCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}

	// MARK: - SC-2: a policy-invalid rotation is rejected before signing

	/// A member built like `SelfInteropTests.member`, but whose OWN leaf
	/// capabilities additionally admit x509 -- SC-2's guard needs a rotation
	/// target whose OWN capabilities admit the new credential type, so the
	/// guard reaches the "some OTHER member doesn't support it" branch
	/// instead of tripping the leaf's own-capability check first.
	private static func memberSupportingX509(_ name: String) throws -> SelfInteropTests.Member {
		let provider = Self.provider
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(provider)
		let (leafSecret, leafPublic) = try provider.hpkeGenerateKeyPair()
		let (initSecret, initPublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublic, signatureKey: signatureKey,
			credential: .basic(identity: Data(name.utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [],
				credentials: [.init(.basic), .init(.x509)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: .curve25519Aes128, initKey: initPublic,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return SelfInteropTests.Member(
			identity: Data(name.utf8), signingKey: signingKey,
			signatureKey: signatureKey, leafSecretKey: leafSecret,
			initSecretKey: initSecret, keyPackage: keyPackage)
	}

	@Test(
		"SC-2: proposeUpdate(newIdentity:) rejects a rotation into a credential type a member doesn't support, BEFORE any .leafNode signature is requested"
	)
	func proposeUpdatePolicyGuardRejectsUnsupportedCredentialType() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice-sc2")
		let bob = try Self.memberSupportingX509("bob-sc2")

		var groupA = try SelfInteropTests.createGroup(alice)
		let addBob = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		groupA = addBob.group
		var bobView = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(addBob.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Self-consistent (Bob's own capabilities admit x509), but Alice -- the
		// only other member -- doesn't: `credentialTypeUnsupportedByMember`.
		let (_, freshSignatureKey) = try GroupMutationTests.signingKeyPair(provider)
		let newIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .other(type: .init(.x509), data: Data("bob-x509-cert".utf8)),
			signatureKey: freshSignatureKey)

		let recorder = SignerSeamTests.RoleRecorder(provider: provider, key: bob.signingKey)
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember) {
			_ = try bobView.proposeUpdate(
				provider, sign: recorder.sign, newIdentity: newIdentity)
		}
		// The reorder (SC-2): policy runs BEFORE signing, so a rejected rotation
		// never burns a `.leafNode` ticket -- the closure was never asked for
		// ANY signature at all.
		#expect(recorder.roles.isEmpty)
	}

	// MARK: - SC-3a: a signature-key rotation via the single-key `signingKey:`
	// sugar is rejected (the key-rotation counterpart to M1's credential-only
	// sugar test above)

	@Test(
		"SC-3a: committing(signingKey:newIdentity:) -- a signature-KEY rotation attempted through the single-key sugar is rejected by the leaf self-verify"
	)
	func committingSigningKeySugarRejectsKeyRotation() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let target = try Self.rotatedIdentity("alice-sugar-key-rotation")

		// The single-key sugar answers EVERY role (including `.leafNode`) with
		// `t.alice.signingKey`, but `target.identity.signatureKey` is a
		// DIFFERENT key -- incoherent, per `signingClosure(_:_:)`'s own doc
		// comment ("A signature-KEY rotation is incoherent under this
		// adapter").
		#expect {
			_ = try t.aliceView.committing(
				provider, proposals: [], signingKey: t.alice.signingKey,
				randomness: .generate(provider), newIdentity: target.identity)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	@Test(
		"SC-3a: proposeUpdate(signingKey:newIdentity:) -- a signature-KEY rotation attempted through the single-key sugar is rejected by the leaf self-verify"
	)
	func proposeUpdateSigningKeySugarRejectsKeyRotation() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let target = try Self.rotatedIdentity("bob-sugar-key-rotation")

		#expect {
			_ = try t.bobView.proposeUpdate(
				provider, signingKey: t.bob.signingKey, newIdentity: target.identity
			)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}
}
