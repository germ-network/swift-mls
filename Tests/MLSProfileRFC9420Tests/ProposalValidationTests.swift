import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Phase 6a's §12.1/§12.2 validation pass, exercised through a synthetic
/// committer→receiver flow rather than official vectors: every rule here
/// runs inside `validateProposalList`/`applyProposals`, code shared
/// verbatim by `committing` (construct) and `processing` (receive) — so a
/// crafted invalid proposal reaches the SAME rule on both sides, and a
/// receiver's rejection is exactly what a conforming committer's own
/// construction would also refuse.
///
/// Two hand-crafting techniques, chosen per case by what the rule actually
/// checks:
/// - **Inline**, when a rule is about the proposal itself or is
///   necessarily committer-attributed (an Add's KeyPackage, a PSK, GCE, or
///   an Update/Remove naming the committer) — the crafted commit carries
///   `.proposal(p)` directly.
/// - **By reference**, when the rule needs a sender distinct from the
///   committer (an Update authored by a non-committer member) — a real
///   member genuinely frames the proposal (`framedProposal`) and
///   `ProposalStore.insert`s it, then the commit references it.
///
/// Every commit is built by `craftedCommit`, which signs and
/// membership-tags for real (mirroring `ConstructedRejectionTests`) but
/// skips `committing()`'s own validation — the receiver's `processing` is
/// what each test targets, not the sender's construction-time gate.
@Suite("Proposal validation (§7.3 policy, §10.1, §12.1, §12.2)")
struct ProposalValidationTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	// MARK: fixtures — fresh, synthetic groups

	struct Pair {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
	}

	/// Alice (committer) + Bob (receiver), converged at epoch 1.
	static func pair() throws -> Pair {
		let alice = try SelfInteropTests.member("pv-alice")
		let bob = try SelfInteropTests.member("pv-bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		return Pair(alice: alice, bob: bob, groupA: groupA, groupB: groupB)
	}

	struct Trio {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var carol: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
		var groupC: MLS.RFC9420.Group
	}

	/// Alice (committer) + Bob (receiver) + Carol (a third member, for
	/// rules that need a victim distinct from both), converged at epoch 1.
	static func trio() throws -> Trio {
		let alice = try SelfInteropTests.member("pv-alice3")
		let bob = try SelfInteropTests.member("pv-bob3")
		let carol = try SelfInteropTests.member("pv-carol3")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			provider,
			proposals: [
				.proposal(.add(bob.keyPackage)), .proposal(.add(carol.keyPackage)),
			],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		let groupC = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: carol.joinCredentials, psk: { _ in nil })
		return Trio(
			alice: alice, bob: bob, carol: carol, groupA: groupA, groupB: groupB,
			groupC: groupC)
	}

	/// A commit really signed and membership-tagged by `signingKey` in
	/// `group`'s own current epoch — genuinely authenticated, so a
	/// receiver's `processing` reaches every §12.1/§12.2 rule exactly as it
	/// would for a real peer, without going through the validating
	/// `committing()` (which would refuse the very proposal each test
	/// crafts, since it runs the same checks). Mirrors
	/// `ConstructedRejectionTests.craftedCommit`. `path` stays `nil` in
	/// every test below: every rule under test throws inside
	/// `validateProposalList` or `applyProposals`, both of which run
	/// before `processing`'s own path-required check.
	static func craftedCommit(
		group: MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey,
		proposals: [MLS.RFC9420.ProposalOrRef]
	) throws -> MLS.RFC9420.PublicMessage {
		let content = MLS.RFC9420.FramedContent(
			groupID: group.context.groupID, epoch: group.context.epoch,
			sender: .member(group.myLeafIndex), authenticatedData: Data(),
			content: .commit(.init(proposals: proposals, path: nil)))
		return try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: group.context,
			confirmationTag: MLS.ConfirmationTag(
				Data(repeating: 0xAB, count: provider.hashSize)),
			signingKey: signingKey, membershipKey: group.epoch.membershipKey)
	}

	/// A genuinely framed (publicly signed and membership-tagged) proposal
	/// from `group`'s own current member, run through `Group.verifying(proposal:)`
	/// exactly as a real by-reference proposal is before it enters the store —
	/// the by-reference half of the technique above. The *framing* is valid; a
	/// malformed *inner* leaf (the point of several tests below) still passes
	/// `verify` and is caught later by `processing`.
	static func verifiedProposal(
		_ proposal: MLS.RFC9420.Proposal, framedBy group: MLS.RFC9420.Group,
		signingKey: MLS.SignatureSecretKey
	) throws -> MLS.RFC9420.VerifiedProposal {
		let content = MLS.RFC9420.FramedContent(
			groupID: group.context.groupID, epoch: group.context.epoch,
			sender: .member(group.myLeafIndex), authenticatedData: Data(),
			content: .proposal(proposal))
		let message = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: group.context,
			confirmationTag: nil, signingKey: signingKey,
			membershipKey: group.epoch.membershipKey)
		return try group.verifying(provider, proposal: message)
	}

	// MARK: §10.1 — the KeyPackage signature reading, settled against vectors

	/// The RFC's literal text says the KeyPackage signature verifies "using
	/// the public key in leaf_node.credential" — which a basic credential
	/// does not contain. This test settles the reading against official
	/// vector bytes: `leaf_node.signature_key` verifies, so that is the
	/// reading this library ships. If this test ever fails, the reading is
	/// wrong — not the test.
	@Test("a vector KeyPackage's signature verifies under leaf_node.signature_key")
	func keyPackageSignatureReading() throws {
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(let kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}
		try kp.verifySignature(Self.provider)

		var tampered = kp
		tampered.signature[0] ^= 1
		#expect(throws: MLS.CryptoError.self) {
			try tampered.verifySignature(Self.provider)
		}
	}

	// MARK: §12.2 list rules — inline, committer-attributed by construction

	@Test("an Update attributed to the committer is rejected")
	func updateByCommitter() throws {
		let p = try Self.pair()
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.update(p.alice.keyPackage.leafNode))])
		#expect(throws: MLS.RFC9420.GroupError.updateByCommitter) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("a Remove naming the committer is rejected")
	func removeOfCommitter() throws {
		let p = try Self.pair()
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.remove(p.groupA.myLeafIndex))])
		#expect(throws: MLS.RFC9420.GroupError.removeOfCommitter) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("two Removes naming one leaf are rejected")
	func duplicateProposalForLeaf() throws {
		let t = try Self.trio()
		let commit = try Self.craftedCommit(
			group: t.groupA, signingKey: t.alice.signingKey,
			proposals: [
				.proposal(.remove(t.groupC.myLeafIndex)),
				.proposal(.remove(t.groupC.myLeafIndex)),
			])
		#expect(
			throws: MLS.RFC9420.GroupError.duplicateProposalForLeaf(
				leaf: t.groupC.myLeafIndex)
		) {
			_ = try t.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("two PreSharedKey proposals naming one id are rejected")
	func duplicatePreSharedKey() throws {
		let p = try Self.pair()
		let psk = MLS.RFC9420.Proposal.preSharedKey(
			.external(
				pskID: Data("id".utf8),
				nonce: Data(repeating: 7, count: Self.provider.hashSize)))
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(psk), .proposal(psk)])
		#expect(throws: MLS.RFC9420.GroupError.duplicatePreSharedKey) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("a psk_nonce that isn't KDF.Nh long is rejected")
	func wrongPskNonceLength() throws {
		let p = try Self.pair()
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [
				.proposal(
					.preSharedKey(
						.external(
							pskID: Data("id".utf8),
							nonce: Data([1, 2, 3]))))
			])
		#expect(
			throws: MLS.RFC9420.GroupError.wrongPskNonceLength(
				expected: Self.provider.hashSize, actual: 3)
		) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("two GroupContextExtensions proposals are rejected")
	func multipleGroupContextExtensions() throws {
		let p = try Self.pair()
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [
				.proposal(.groupContextExtensions([])),
				.proposal(.groupContextExtensions([])),
			])
		#expect(throws: MLS.RFC9420.GroupError.multipleGroupContextExtensions) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	// MARK: the authenticity payload — signatures on installed leaves

	@Test("an Add whose KeyPackage signature is tampered is rejected")
	func addSignatureChecked() throws {
		let p = try Self.pair()
		let stranger = try SelfInteropTests.member("pv-tamper")
		var kp = stranger.keyPackage
		kp.signature[0] ^= 1
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.add(kp))])
		#expect(throws: MLS.CryptoError.self) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	/// The harvest defense the `Placement` doc comment demands: a
	/// `key_package`-sourced leaf signs *unbound* bytes, so its signature
	/// verifies at any index in any group — the §7.3 source check is the
	/// only thing standing between a harvested KeyPackage signature and an
	/// Update at an arbitrary leaf. By reference, and framed by Bob
	/// himself: an inline Update is always committer-attributed
	/// (`updateByCommitter` above), so only a non-committer sender can
	/// reach this rule.
	@Test("an Update carrying a key_package-sourced leaf is rejected, not verified unbound")
	func updateSourceChecked() throws {
		let p = try Self.pair()
		let verified = try Self.verifiedProposal(
			.update(p.bob.keyPackage.leafNode), framedBy: p.groupB,
			signingKey: p.bob.signingKey)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.reference(ref)])
		#expect(throws: MLS.RFC9420.GroupError.wrongLeafNodeSource) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: store, psk: { _ in nil })
		}
	}

	@Test("an Update that reuses the replaced leaf's encryption key is rejected")
	func updateMustChangeEncryptionKey() throws {
		let p = try Self.pair()
		let replaced = p.bob.keyPackage.leafNode

		// A real update-sourced leaf, signed with a fresh key — signature
		// verification uses the *new* leaf's own signature_key, so a test
		// can construct one — deliberately reusing the old encryption key.
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(
			Self.provider)
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: replaced.encryptionKey, signatureKey: signatureKey,
			credential: .basic(identity: Data("upd".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .update, extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			Self.provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(
					groupID: p.groupB.context.groupID,
					leafIndex: p.groupB.myLeafIndex)))

		let verified = try Self.verifiedProposal(
			.update(leaf), framedBy: p.groupB, signingKey: p.bob.signingKey)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.reference(ref)])
		#expect(throws: MLS.RFC9420.GroupError.updateDidNotChangeEncryptionKey) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: store, psk: { _ in nil })
		}
	}

	/// The Update half of the authenticity payload: a leaf whose signature
	/// does not verify must not be installed, however well-formed. By
	/// reference, for the same reason `updateSourceChecked` is.
	@Test("an Update whose leaf signature is garbage is rejected")
	func updateSignatureChecked() throws {
		let p = try Self.pair()
		let (_, signatureKey) = try GroupMutationTests.signingKeyPair(Self.provider)
		let leaf = MLS.RFC9420.LeafNode(
			encryptionKey: MLS.HpkePublicKey(Data([9, 9])), signatureKey: signatureKey,
			credential: .basic(identity: Data("upd".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .update, extensions: [], signature: Data("garbage".utf8))
		let verified = try Self.verifiedProposal(
			.update(leaf), framedBy: p.groupB, signingKey: p.bob.signingKey)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.reference(ref)])
		#expect(throws: MLS.CryptoError.self) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: store, psk: { _ in nil })
		}
	}

	// MARK: §12.3 provisional wiring — GCE requirements bind same-commit Adds

	/// The §12.3 sentence with teeth: "The new extensions MUST be used when
	/// evaluating other proposals in this list." A GroupContextExtensions
	/// proposal adding a required_capabilities that names a credential type
	/// must reject an Add (in the same commit) whose KeyPackage doesn't
	/// support it.
	@Test("a same-commit GCE's required_capabilities binds the Add that follows")
	func provisionalRequirementsBindAdds() throws {
		let p = try Self.pair()
		let filler = try SelfInteropTests.member("pv-filler")  // basic credential only
		var writer = MLS.Writer()
		try writer.encode(MLS.RFC9420.RequiredCapabilities(credentialTypes: [.init(.x509)]))
		let requirement = MLS.RFC9420.Extension(
			type: .init(.requiredCapabilities), data: Data(writer.bytes))
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [
				.proposal(.groupContextExtensions([requirement])),
				.proposal(.add(filler.keyPackage)),
			])
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	/// §7.3's other uniqueness half, post-application: two Adds with
	/// distinct signature keys but one shared leaf encryption key — each
	/// valid alone, and pre-fix accepted by both sides.
	@Test("two Adds sharing an encryption key are rejected after application")
	func postCommitEncryptionKeyUniqueness() throws {
		let p = try Self.pair()
		let first = try SelfInteropTests.member("pv-enc-a")
		let second = try SelfInteropTests.member("pv-enc-b")
		// Give the second KeyPackage the first's leaf encryption key,
		// re-signing leaf and KeyPackage so everything else is valid.
		var kp = second.keyPackage
		kp.leafNode.encryptionKey = first.keyPackage.leafNode.encryptionKey
		kp.leafNode.signature = try MLS.signWithLabel(
			Self.provider, privateKey: second.signingKey, label: "LeafNodeTBS",
			content: try kp.leafNode.toBeSigned(placement: .keyPackage))
		kp.signature = try MLS.signWithLabel(
			Self.provider, privateKey: second.signingKey, label: "KeyPackageTBS",
			content: try kp.toBeSigned())

		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.add(first.keyPackage)), .proposal(.add(kp))])
		// The specific case, not `TreeError.self`: with the sweep removed
		// the substituted Adds provoke a *different* TreeError downstream
		// (a path-structure count mismatch), and a type-level expectation
		// passed right through it -- caught when this test's own mutation
		// run came back green against the deleted check.
		#expect {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		} throws: { error in
			guard case MLS.TreeKEM.TreeError.duplicateEncryptionKey = error else {
				return false
			}
			return true
		}
	}

	/// §12.2's closing rule: two Adds, each individually valid, sharing a
	/// signature key. Only the post-application tree can see it -- the
	/// per-proposal pass validates each leaf alone, and join-side
	/// uniqueness runs once, at join.
	@Test("two Adds sharing a signature key are rejected after application")
	func postCommitUniqueness() throws {
		let p = try Self.pair()
		let stranger = try SelfInteropTests.member("pv-sigdup")
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [
				.proposal(.add(stranger.keyPackage)),
				.proposal(.add(stranger.keyPackage)),
			])
		#expect {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		} throws: { error in
			guard case MLS.RFC9420.GroupError.duplicateSignatureKey = error else {
				return false
			}
			return true
		}
	}

	/// §10.1's match-the-GroupContext bullet on the commit path — these
	/// two errors were only ever exercised at join before.
	@Test("an Add whose KeyPackage disagrees with the GroupContext is rejected")
	func addSuiteAndVersionMismatch() throws {
		let p = try Self.pair()
		let member = try SelfInteropTests.member("pv-mismatch")

		var wrongSuite = member.keyPackage
		wrongSuite.cipherSuite = .init(id: 2)
		let suiteCommit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.add(wrongSuite))])
		#expect(throws: MLS.RFC9420.GroupError.cipherSuiteMismatch) {
			_ = try p.groupB.processing(
				Self.provider, commit: suiteCommit, proposals: .init(),
				psk: { _ in nil })
		}

		var wrongVersion = member.keyPackage
		wrongVersion.version = .init(id: 2)
		let versionCommit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.add(wrongVersion))])
		#expect(throws: MLS.RFC9420.GroupError.protocolVersionMismatch) {
			_ = try p.groupB.processing(
				Self.provider, commit: versionCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}

	@Test("a KeyPackage whose init_key equals the leaf encryption key is rejected")
	func initKeyReuse() throws {
		let p = try Self.pair()
		let member = try SelfInteropTests.member("pv-initreuse")
		var kp = member.keyPackage
		kp.initKey = kp.leafNode.encryptionKey
		let commit = try Self.craftedCommit(
			group: p.groupA, signingKey: p.alice.signingKey,
			proposals: [.proposal(.add(kp))])
		#expect(throws: MLS.RFC9420.GroupError.keyPackageInitKeyReused) {
			_ = try p.groupB.processing(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	// MARK: the structural invariant itself

	/// The store gate refuses non-proposal content at `verify`: a
	/// `commit`- or `application`-content message has no business in a
	/// proposal store. (The private path never wraps one — `unprotect`
	/// returns `.application`/`.commit`, never a `VerifiedProposal` — and
	/// `insert`'s own `notAProposal` guard survives as a defensive invariant.)
	@Test("verify refuses a non-proposal (application) message")
	func verifyRejectsNonProposal() throws {
		let p = try Self.pair()
		let message = MLS.RFC9420.PublicMessage(
			content: .init(
				groupID: p.groupA.context.groupID, epoch: p.groupA.context.epoch,
				sender: .member(p.groupA.myLeafIndex), authenticatedData: Data(),
				content: .application(Data("hi".utf8))),
			auth: .init(signature: nil, confirmationTag: nil),
			membershipTag: nil)
		#expect(throws: MLS.RFC9420.GroupError.notAProposal) {
			_ = try p.groupA.verifying(Self.provider, proposal: message)
		}
	}

	/// The impersonation the store gate closes: a member (Alice) frames a
	/// public Update claiming another member (Bob) as `sender`, signing with
	/// her own key. `verify` checks the framing signature under Bob's *current*
	/// leaf key — which Alice cannot produce — so the forged attribution is
	/// rejected before it can enter the store. The membership key is
	/// group-shared, so its tag would verify; only the per-sender framing
	/// signature does not, and that is checked first.
	@Test("verify rejects a public proposal forged under another member's leaf")
	func verifyRejectsForgedSenderAttribution() throws {
		let p = try Self.pair()
		let content = MLS.RFC9420.FramedContent(
			groupID: p.groupA.context.groupID, epoch: p.groupA.context.epoch,
			sender: .member(p.groupB.myLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(p.bob.keyPackage.leafNode)))
		let forged = try MLS.RFC9420.protectPublic(
			Self.provider, content: content, groupContext: p.groupA.context,
			confirmationTag: nil, signingKey: p.alice.signingKey,
			membershipKey: p.groupA.epoch.membershipKey)
		#expect(throws: MLS.CryptoError.self) {
			_ = try p.groupA.verifying(Self.provider, proposal: forged)
		}
	}

	/// §6.2 makes the membership tag a MUST for member senders — a valid
	/// framing signature with the tag stripped (an attacker holding the leaf
	/// signing key but no group secrets) must still be rejected.
	@Test("verify rejects a member proposal whose membership tag is missing")
	func verifyRejectsMissingMembershipTag() throws {
		let p = try Self.pair()
		let content = MLS.RFC9420.FramedContent(
			groupID: p.groupB.context.groupID, epoch: p.groupB.context.epoch,
			sender: .member(p.groupB.myLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(p.bob.keyPackage.leafNode)))
		let signed = try MLS.RFC9420.protectPublic(
			Self.provider, content: content, groupContext: p.groupB.context,
			confirmationTag: nil, signingKey: p.bob.signingKey,
			membershipKey: p.groupB.epoch.membershipKey)
		let untagged = MLS.RFC9420.PublicMessage(
			content: signed.content, auth: signed.auth, membershipTag: nil)
		#expect(throws: MLS.FramingError.self) {
			_ = try p.groupB.verifying(Self.provider, proposal: untagged)
		}
	}

	/// `verify`'s pre-signature guards: an external sender is rejected
	/// (`unsupportedSender`, external senders are descoped) and a wrong epoch is
	/// rejected before any crypto.
	@Test("verify rejects an external-sender proposal and a wrong-epoch proposal")
	func verifyRejectsExternalSenderAndWrongEpoch() throws {
		let p = try Self.pair()
		func message(epoch: UInt64, sender: MLS.Sender) -> MLS.RFC9420.PublicMessage {
			MLS.RFC9420.PublicMessage(
				content: .init(
					groupID: p.groupB.context.groupID, epoch: epoch,
					sender: sender, authenticatedData: Data(),
					content: .proposal(.update(p.bob.keyPackage.leafNode))),
				auth: .init(signature: MLS.Signature(Data()), confirmationTag: nil),
				membershipTag: nil)
		}
		#expect(throws: MLS.RFC9420.GroupError.unsupportedSender) {
			_ = try p.groupB.verifying(
				Self.provider,
				proposal: message(
					epoch: p.groupB.context.epoch, sender: .external(0)))
		}
		#expect(
			throws: MLS.RFC9420.GroupError.wrongEpoch(
				expected: p.groupB.context.epoch, actual: 999)
		) {
			_ = try p.groupB.verifying(
				Self.provider,
				proposal: message(
					epoch: 999, sender: .member(p.groupB.myLeafIndex)))
		}
	}

	/// A proposal verified in one epoch must not be applied by reference in a
	/// later one — its `sender` leaf index may name a different member after a
	/// Remove+Add reuses the leaf. The store binds each entry to its framing
	/// epoch and re-checks at resolution, so carrying a stale entry across an
	/// epoch is rejected even though the proposal was genuinely verified.
	@Test("a by-reference proposal from a stale epoch is rejected at resolution")
	func staleEpochReferenceRejected() throws {
		let p = try Self.pair()
		let verified = try Self.verifiedProposal(
			.update(p.bob.keyPackage.leafNode), framedBy: p.groupB,
			signingKey: p.bob.signingKey)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)

		// Alice advances a full epoch (an empty commit carries a path).
		let advanced = try p.groupA.committing(
			Self.provider, proposals: [], signingKey: p.alice.signingKey,
			randomness: .generate(Self.provider)
		).group

		#expect(
			throws: MLS.RFC9420.GroupError.referencedProposalWrongEpoch(
				expected: advanced.context.epoch, actual: p.groupB.context.epoch)
		) {
			_ = try advanced.committing(
				Self.provider, proposals: [.reference(ref)], proposalStore: store,
				signingKey: p.alice.signingKey,
				randomness: .generate(Self.provider))
		}
	}

	// MARK: direct §7.3 policy units

	static func policyLeaf(
		extensions: [MLS.RFC9420.Extension] = [],
		capabilityExtensions: [MLS.RFC9420.ExtensionType] = []
	) -> MLS.RFC9420.LeafNode {
		.init(
			encryptionKey: MLS.HpkePublicKey(Data([1])),
			signatureKey: MLS.SignaturePublicKey(Data([2])),
			credential: .basic(identity: Data([3])),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: capabilityExtensions, proposals: [],
				credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 10, notAfter: 20)),
			extensions: extensions, signature: Data())
	}

	@Test("a non-default leaf extension missing from capabilities is rejected")
	func unsupportedExtension() throws {
		let leaf = Self.policyLeaf(extensions: [
			.init(type: .init(rawValue: 99), data: Data())
		])
		#expect(
			throws: MLS.RFC9420.GroupError.unsupportedExtensionInLeaf(
				.init(rawValue: 99))
		) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [])
		}
	}

	/// The §7.2/§7.3 tension, resolved toward §7.2: a default-type
	/// extension (application_id) is *forbidden* from appearing in
	/// capabilities, so §7.3's subset rule must exempt it or no leaf
	/// carrying one could ever validate. All vector leaf extensions are
	/// empty, so only this test notices the difference.
	@Test("a default-type leaf extension passes without a capabilities listing")
	func defaultExtensionExempt() throws {
		let leaf = Self.policyLeaf(
			extensions: [.init(type: .init(.applicationID), data: Data())])
		try leaf.validatePolicy(
			.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
			memberCapabilities: [])
	}

	@Test(
		"required_capabilities: non-default unmet rejects; default-type requirement is exempt"
	)
	func requiredCapabilitiesExemption() throws {
		let leaf = Self.policyLeaf()
		// Default extension/proposal types: exempt, passes.
		try leaf.validatePolicy(
			.keyPackage,
			groupRequirements: .init(
				extensionTypes: [.init(.ratchetTree)], proposalTypes: [.init(.add)]),
			memberCredentialTypes: [], memberCapabilities: [])
		// Non-default extension type: not exempt.
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			try leaf.validatePolicy(
				.keyPackage,
				groupRequirements: .init(extensionTypes: [.init(rawValue: 99)]),
				memberCredentialTypes: [], memberCapabilities: [])
		}
		// Credential types are never exempt -- §11.1 says so explicitly.
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			try leaf.validatePolicy(
				.keyPackage,
				groupRequirements: .init(credentialTypes: [.init(.x509)]),
				memberCredentialTypes: [], memberCapabilities: [])
		}
	}

	@Test("a leaf whose capabilities omit its own credential type is rejected")
	func ownCredentialCapability() throws {
		var leaf = Self.policyLeaf()
		leaf.capabilities.credentials = []
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeNotInOwnCapabilities) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [])
		}
	}

	@Test("mutual credential support fails in both directions")
	func mutualCredentialSupport() throws {
		let leaf = Self.policyLeaf()
		// A member that doesn't support basic.
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [
					.init(
						versions: [], cipherSuites: [], extensions: [],
						proposals: [], credentials: [.init(.x509)])
				])
		}
		// A credential type in use that this leaf doesn't support.
		#expect(throws: MLS.RFC9420.GroupError.memberCredentialUnsupportedByLeaf) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil,
				memberCredentialTypes: [.init(.x509)], memberCapabilities: [])
		}
	}

	@Test("lifetime bounds fire only when the caller opts in")
	func lifetimeOptIn() throws {
		let leaf = Self.policyLeaf()  // lifetime (10, 20)
		try leaf.validatePolicy(
			.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
			memberCapabilities: [])
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [], currentTime: 30)
		}
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeTooLong) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [], maxTotalLifetime: 5)
		}
	}
}
