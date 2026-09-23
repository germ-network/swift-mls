import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import Testing

@testable import MLSProfileRFC9420

/// `authenticatedData` on a self-Update proposal (RFC 9420 §6): the caller's
/// bytes ride in the proposal's `FramedContent` alongside the leaf, so a
/// receiver sees them back unchanged on BOTH wire formats, they are covered
/// by the framing signature, and they fold into `ProposalRef` -- the same
/// contract `protect`'s own `authenticatedData:` already gives application
/// messages. Sent UNENCRYPTED either way: even under `.privateMessage`, they
/// ride in `PrivateMessage`'s own plaintext field (RFC 9420 §6.3), bound only
/// as AEAD associated data, not inside the ciphertext.
@Suite("Update proposal authenticatedData (RFC 9420 §6)")
struct UpdateProposalAuthenticatedDataTests {
	static let provider = SelfInteropTests.provider
	static let ad = Data("caller-supplied-authenticated-data".utf8)

	enum TestSetupError: Error {
		case expectedPublicProposal
		case expectedPrivateProposal
		case expectedProposalContent
		case expectedProposalMessage
		case expectedPublicCommit
	}

	// MARK: - Round trip (both framings; the message crosses the wire for real)

	/// `mlsEncoded()`/`Message(mlsEncoded:)` round-trips the proposal before the
	/// receiver ever looks at it -- proving `authenticatedData` survives the
	/// wire, not just an in-memory copy of the sender's own struct (the same
	/// discipline `CustomProposalTests`' wire tests follow).
	private static func roundTrips(framing: MLS.RFC9420.Group.HandshakeFraming) throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		let (message, ref) = try t.bobView.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: framing,
			authenticatedData: Self.ad)
		let received = try MLS.RFC9420.Message(mlsEncoded: try message.mlsEncoded())

		var store = MLS.RFC9420.ProposalStore()
		let receivedRef: MLS.HashReference
		switch received {
		case .publicMessage(let sealed):
			#expect(sealed.content.authenticatedData == Self.ad)
			let verified = try t.aliceView.verifying(provider, proposal: sealed)
			receivedRef = try store.insert(verified, provider)
		case .privateMessage(let sealed):
			let opened = try t.aliceView.unprotect(provider, message: sealed)
			#expect(opened.authenticatedData == Self.ad)
			guard case .proposal(let verified) = opened.content else {
				throw TestSetupError.expectedProposalContent
			}
			receivedRef = try store.insert(verified, provider)
		default:
			throw TestSetupError.expectedProposalMessage
		}
		#expect(receivedRef == ref)

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
		#expect(pending.effects.events.contains(.updated(leaf: bobLeaf)))
		let applied = try pending.apply(onto: t.aliceView)
		t.aliceView = applied.group

		try t.bobView.process(
			provider, commit: commitMessage, proposals: store, psk: { _ in nil })
	}

	@Test(
		"publicMessage: authenticatedData survives the wire, the receiver reads it back, its ProposalRef matches, and a commit folding it by reference applies"
	)
	func roundTripsPublic() throws {
		try Self.roundTrips(framing: .publicMessage)
	}

	@Test(
		"privateMessage: authenticatedData survives the wire, the receiver reads it back via unprotect, its ProposalRef matches, and a commit folding it by reference applies"
	)
	func roundTripsPrivate() throws {
		try Self.roundTrips(framing: .privateMessage)
	}

	// MARK: - Default

	@Test("omitting authenticatedData: still yields an empty FramedContent.authenticated_data")
	func defaultsToEmpty() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()

		let (message, _) = try t.bobView.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: .publicMessage)
		guard case .publicMessage(let sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		#expect(sealed.content.authenticatedData.isEmpty)
	}

	// MARK: - Forwarding: each overload gets its own check, none silently drops it

	/// `proposeUpdate(_:sign:)`, the base closure form -- `signingKey:` sugar
	/// over it is already exercised (and would fail the same way) by the round
	/// trips above, so this is the one overload those don't otherwise touch.
	@Test("proposeUpdate(_:sign:) forwards authenticatedData")
	func closureFormForwardsAuthenticatedData() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()

		let (message, _) = try t.bobView.proposeUpdate(
			provider, sign: MLS.RFC9420.signingClosure(provider, t.bob.signingKey),
			framing: .publicMessage, authenticatedData: Self.ad)
		guard case .publicMessage(let sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		#expect(sealed.content.authenticatedData == Self.ad)
	}

	@Test("proposingUpdate(as:sign:) forwards authenticatedData")
	func proposingUpdateClosureFormForwardsAuthenticatedData() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		let (message, _) = try t.bobView.proposingUpdate(
			as: bobLeaf, provider,
			sign: MLS.RFC9420.signingClosure(provider, t.bob.signingKey),
			framing: .publicMessage, authenticatedData: Self.ad)
		guard case .publicMessage(let sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		#expect(sealed.content.authenticatedData == Self.ad)
	}

	@Test("proposingUpdate(as:signingKey:) forwards authenticatedData")
	func proposingUpdateSigningKeySugarForwardsAuthenticatedData() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		let (message, _) = try t.bobView.proposingUpdate(
			as: bobLeaf, provider, signingKey: t.bob.signingKey,
			framing: .publicMessage, authenticatedData: Self.ad)
		guard case .publicMessage(let sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		#expect(sealed.content.authenticatedData == Self.ad)
	}

	// MARK: - Alongside a credential rotation

	@Test("a credential rotation (newIdentity:) still carries authenticatedData")
	func newIdentityCarriesAuthenticatedData() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()
		let target = try CredentialRotationAuthoringTests.rotatedIdentity("bob-rotated-ad")

		let (message, _) = try t.bobView.proposeUpdate(
			provider,
			sign: MLS.RFC9420.signingClosure(
				provider, current: t.bob.signingKey, new: target.signingKey),
			framing: .publicMessage, newIdentity: target.identity,
			authenticatedData: Self.ad)
		guard case .publicMessage(let sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		#expect(sealed.content.authenticatedData == Self.ad)
	}

	// MARK: - Tamper

	/// `Group.verifying(proposal:)` folds a signature failure and a membership-tag
	/// failure into the SAME `signatureVerificationFailed` error (see
	/// `CustomProposalTests.wireTamperFailsSignature`'s doc comment on the same
	/// conflation), so that alone can't prove the SIGNATURE specifically covers
	/// `authenticatedData`. Check it directly first -- recompute `FramedContentTBS`
	/// over the tampered content and verify the ORIGINAL signature against it --
	/// then also pin the end-to-end API rejection.
	@Test(
		"a flipped authenticatedData byte fails the FramedContentTBS signature, and verifying(proposal:) rejects it"
	)
	func tamperedAuthenticatedDataFailsSignature() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()

		let (message, _) = try t.bobView.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: .publicMessage,
			authenticatedData: Self.ad)
		guard case .publicMessage(var sealed) = message else {
			throw TestSetupError.expectedPublicProposal
		}
		let signature = try #require(sealed.auth.signature)
		sealed.content.authenticatedData[0] ^= 1

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: try sealed.content.mlsEncoded(),
			encodedGroupContext: sealed.content.sender.bindsGroupContext
				? try t.bobView.context.mlsEncoded() : nil)
		let signatureValid = try MLS.verifyWithLabel(
			provider, publicKey: t.bob.signatureKey, label: "FramedContentTBS",
			content: signedContent.toBeSigned(), signature: signature.data)
		#expect(!signatureValid)

		#expect {
			_ = try t.aliceView.verifying(provider, proposal: sealed)
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	/// The privateMessage counterpart: `authenticatedData` rides in
	/// `PrivateMessage`'s own plaintext field (RFC 9420 §6.3) and only ever
	/// binds the AEAD as associated data (§6.3.1's `PrivateContentAAD`), so a
	/// wire-level tamper there is caught by the AEAD open, not a signature.
	@Test("a flipped authenticatedData byte on a privateMessage's wire header fails unprotect")
	func tamperedAuthenticatedDataFailsPrivateUnprotect() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()

		let (message, _) = try t.bobView.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: .privateMessage,
			authenticatedData: Self.ad)
		guard case .privateMessage(var sealed) = message else {
			throw TestSetupError.expectedPrivateProposal
		}
		sealed.authenticatedData[0] ^= 1

		#expect {
			_ = try t.aliceView.unprotect(provider, message: sealed)
		} throws: { error in
			guard case MLS.CryptoError.aeadOpenFailed = error else {
				return false
			}
			return true
		}
	}
}
