import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeMath
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Backs `MessageKeySource` with the real secret tree from
/// `MLSKeySchedule` — a 2-member tree (`numLeaves: 2`), matching the
/// official vector's own fixed setup (test-vectors.md's "Message
/// Protection" section: sender is always LeafIndex 1). Generation is
/// always 0 here — every message in this vector is the ratchet's first,
/// so there's no history to advance through.
private struct TwoMemberSecretTree: MLS.RFC9420.MessageKeySource {
	let provider: any MLS.CipherSuiteProvider
	let encryptionSecret: Data

	func key(for leafIndex: MLS.LeafIndex, generation: UInt32, contentType: MLS.ContentType)
		throws -> (
			key: Data, nonce: Data
		)
	{
		let leafSecret = try MLS.KeySchedule.leafSecret(
			provider, encryptionSecret: encryptionSecret, leafIndex: leafIndex.value,
			numLeaves: try MLS.LeafCount(validating: 2))
		let ratchetSecret =
			contentType == .application
			? try MLS.KeySchedule.applicationRatchetSecret(
				provider, leafSecret: leafSecret)
			: try MLS.KeySchedule.handshakeRatchetSecret(
				provider, leafSecret: leafSecret)
		let step = try MLS.KeySchedule.ratchetStep(
			provider, secret: ratchetSecret, generation: generation)
		return (step.key, step.nonce)
	}
}

@Suite("message-protection.json (mlswg/mls-implementations, official)")
struct MessageProtectionTests {
	static let provider = SwiftCryptoProvider()

	static let records =
		(try! VectorFile.load("message-protection", as: [MessageProtectionVector].self))
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	static let senderIndex = MLS.LeafIndex(value: 1)

	private func groupContext(_ record: MessageProtectionVector, suite: MLS.CipherSuite)
		-> MLS.RFC9420.GroupContext
	{
		MLS.RFC9420.GroupContext(
			version: .mls10, cipherSuite: suite, groupID: record.groupID.bytes,
			epoch: record.epoch,
			treeHash: record.treeHash.bytes,
			confirmedTranscriptHash: record.confirmedTranscriptHash.bytes,
			extensions: [])
	}

	private func verificationKey(_ record: MessageProtectionVector) -> MLS.SignaturePublicKey {
		.init(record.signaturePub.bytes)
	}

	private func signingKey(_ record: MessageProtectionVector) -> MLS.SignatureSecretKey {
		.init(record.signaturePriv.bytes)
	}

	private func decodeMessage(_ data: Data) throws -> MLS.RFC9420.Message {
		var reader = MLS.Reader(data)
		let message = try MLS.RFC9420.Message(from: &reader)
		try reader.finish()
		return message
	}

	@Test(
		"proposal/commit/application: pub verifies and unwraps to the raw content, priv unprotects, both re-protect and round-trip",
		arguments: records
	)
	func matchesVector(_ record: MessageProtectionVector) throws {
		let suite = MLS.CipherSuite(id: record.cipherSuite)
		let provider = try #require(Self.provider.cipherSuiteProvider(for: suite))
		let context = groupContext(record, suite: suite)
		let keySource = TwoMemberSecretTree(
			provider: provider, encryptionSecret: record.encryptionSecret.bytes)

		try checkHandshake(
			.proposal(try MLS.RFC9420.Proposal(mlsEncoded: record.proposal.bytes)),
			pub: record.proposalPub, priv: record.proposalPriv, provider: provider,
			context: context,
			record: record, keySource: keySource)

		try checkHandshake(
			.commit(try MLS.RFC9420.Commit(mlsEncoded: record.commit.bytes)),
			pub: record.commitPub, priv: record.commitPriv, provider: provider,
			context: context,
			record: record, keySource: keySource)

		try checkApplication(
			record.application.bytes, priv: record.applicationPriv, provider: provider,
			context: context,
			record: record, keySource: keySource)
	}

	private func checkHandshake(
		_ content: MLS.RFC9420.Content, pub: HexData, priv: HexData,
		provider: any MLS.CipherSuiteProvider,
		context: MLS.RFC9420.GroupContext, record: MessageProtectionVector,
		keySource: TwoMemberSecretTree
	) throws {
		// pub verifies and unwraps to the raw content.
		guard case .publicMessage(let decodedPub) = try decodeMessage(pub.bytes) else {
			Issue.record("expected a PublicMessage")
			return
		}
		#expect(
			try MLS.RFC9420.verifyPublic(
				provider, message: decodedPub, groupContext: context,
				verificationKey: verificationKey(record),
				membershipKey: record.membershipKey.bytes))
		#expect(decodedPub.content.content == content)

		// Re-protecting the raw content produces a PublicMessage that
		// verifies with the same keys (not byte-identical: ECDSA
		// signatures are randomized for 3 of our 5 suites).
		let framedContent = MLS.RFC9420.FramedContent(
			groupID: record.groupID.bytes, epoch: record.epoch,
			sender: .member(Self.senderIndex),
			authenticatedData: Data(), content: content)
		let confirmationTag: MLS.ConfirmationTag? =
			if case .commit = content { decodedPub.auth.confirmationTag } else { nil }
		let reprotected = try MLS.RFC9420.protectPublic(
			provider, content: framedContent, groupContext: context,
			confirmationTag: confirmationTag,
			signingKey: signingKey(record), membershipKey: record.membershipKey.bytes)
		#expect(
			try MLS.RFC9420.verifyPublic(
				provider, message: reprotected, groupContext: context,
				verificationKey: verificationKey(record),
				membershipKey: record.membershipKey.bytes))

		// priv unprotects using the secret tree.
		guard case .privateMessage(let decodedPriv) = try decodeMessage(priv.bytes) else {
			Issue.record("expected a PrivateMessage")
			return
		}
		let unprotected = try MLS.RFC9420.unprotectPrivate(
			provider, keySource: keySource, message: decodedPriv, groupContext: context,
			verificationKey: { _ in verificationKey(record) },
			senderDataSecret: record.senderDataSecret.bytes)
		#expect(unprotected.content.content == content)

		// Re-protecting via the secret tree round-trips.
		let reprivate = try MLS.RFC9420.protectPrivate(
			provider, keySource: keySource, content: framedContent,
			groupContext: context, generation: 0,
			confirmationTag: confirmationTag, signingKey: signingKey(record),
			senderDataSecret: record.senderDataSecret.bytes,
			reuseGuard: MLS.Framing.ReuseGuard(Data([1, 2, 3, 4])), paddingLength: 0)
		let reopened = try MLS.RFC9420.unprotectPrivate(
			provider, keySource: keySource, message: reprivate, groupContext: context,
			verificationKey: { _ in verificationKey(record) },
			senderDataSecret: record.senderDataSecret.bytes)
		#expect(reopened.content.content == content)
	}

	private func checkApplication(
		_ application: Data, priv: HexData, provider: any MLS.CipherSuiteProvider,
		context: MLS.RFC9420.GroupContext, record: MessageProtectionVector,
		keySource: TwoMemberSecretTree
	) throws {
		let framedContent = MLS.RFC9420.FramedContent(
			groupID: record.groupID.bytes, epoch: record.epoch,
			sender: .member(Self.senderIndex),
			authenticatedData: Data(), content: .application(application))

		// Protecting application content as a PublicMessage MUST fail.
		#expect(throws: MLS.FramingError.applicationContentMustNotBePublic) {
			_ = try MLS.RFC9420.protectPublic(
				provider, content: framedContent, groupContext: context,
				confirmationTag: nil,
				signingKey: signingKey(record),
				membershipKey: record.membershipKey.bytes)
		}

		guard case .privateMessage(let decodedPriv) = try decodeMessage(priv.bytes) else {
			Issue.record("expected a PrivateMessage")
			return
		}
		let unprotected = try MLS.RFC9420.unprotectPrivate(
			provider, keySource: keySource, message: decodedPriv, groupContext: context,
			verificationKey: { _ in verificationKey(record) },
			senderDataSecret: record.senderDataSecret.bytes)
		#expect(unprotected.content.content == .application(application))

		let reprivate = try MLS.RFC9420.protectPrivate(
			provider, keySource: keySource, content: framedContent,
			groupContext: context, generation: 0,
			confirmationTag: nil, signingKey: signingKey(record),
			senderDataSecret: record.senderDataSecret.bytes,
			reuseGuard: MLS.Framing.ReuseGuard(Data([5, 6, 7, 8])), paddingLength: 0)
		let reopened = try MLS.RFC9420.unprotectPrivate(
			provider, keySource: keySource, message: reprivate, groupContext: context,
			verificationKey: { _ in verificationKey(record) },
			senderDataSecret: record.senderDataSecret.bytes)
		#expect(reopened.content.content == .application(application))
	}
}
