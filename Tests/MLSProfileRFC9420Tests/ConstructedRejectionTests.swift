import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath
import Testing

@testable import MLSProfileRFC9420

/// The rejections that needed a committer's signing key — unreachable
/// while the vectors supplied only joiner secrets, recorded as
/// signing-oracle-bound in `spec/conformance.md` since 5b. Phase 6b's
/// `create` provides the oracle: every commit here is *validly signed and
/// membership-tagged* by a real member, malformed only in the one way
/// under test. All of them throw before the confirmation-tag check, so a
/// garbage tag is fine (and the one test that needs a *valid-everything*
/// commit with a wrong tag rebuilds its membership tag by hand).
@Suite("Constructed commit rejections (the signing oracle arrives)")
struct ConstructedRejectionTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	struct Pair {
		var alice: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
	}

	/// Alice + Bob, converged at epoch 1, with Alice's signing key in hand.
	static func pair() throws -> Pair {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		return Pair(alice: alice, groupA: groupA, groupB: groupB)
	}

	/// A commit really signed and membership-tagged by Alice, with a
	/// garbage confirmation tag — enough to reach every pre-tag check.
	static func craftedCommit(
		_ pair: Pair, proposals: [MLS.RFC9420.ProposalOrRef],
		path: MLS.RFC9420.UpdatePath?
	) throws -> MLS.RFC9420.PublicMessage {
		let content = MLS.RFC9420.FramedContent(
			groupID: pair.groupA.context.groupID, epoch: pair.groupA.context.epoch,
			sender: .member(pair.groupA.myLeafIndex), authenticatedData: Data(),
			content: .commit(.init(proposals: proposals, path: path)))
		return try MLS.RFC9420.protectPublic(
			Self.provider, content: content, groupContext: pair.groupA.context,
			confirmationTag: MLS.ConfirmationTag(Data(repeating: 0xAB, count: 32)),
			signingKey: pair.alice.signingKey,
			membershipKey: pair.groupA.epoch.membershipKey)
	}

	static func expectRejected(
		_ pair: Pair, _ message: MLS.RFC9420.PublicMessage,
		throws error: MLS.RFC9420.GroupError
	) {
		var groupB = pair.groupB
		#expect(throws: error) {
			try groupB.process(
				provider, commit: message, proposals: [:], psk: { _ in nil })
		}
	}

	@Test("S18: an empty commit without a path is rejected")
	func pathRequired() throws {
		let pair = try Self.pair()
		Self.expectRejected(
			pair, try Self.craftedCommit(pair, proposals: [], path: nil),
			throws: .pathRequired)
	}

	@Test("a ReInit-bearing commit is rejected, not silently applied")
	func unsupportedReInit() throws {
		let pair = try Self.pair()
		let reInit = MLS.RFC9420.Proposal.reInit(
			.init(
				groupID: Data("next".utf8), version: .mls10,
				cipherSuite: .curve25519Aes128, extensions: []))
		Self.expectRejected(
			pair,
			try Self.craftedCommit(pair, proposals: [.proposal(reInit)], path: nil),
			throws: .unsupportedReInit)
	}

	@Test("a Remove naming a blank leaf is rejected")
	func removeOfNonMember() throws {
		let pair = try Self.pair()
		let blank = MLS.LeafIndex(value: pair.groupA.tree.leafCount.value + 1)
		Self.expectRejected(
			pair,
			try Self.craftedCommit(
				pair, proposals: [.proposal(.remove(blank))], path: nil),
			throws: .removeOfNonMember(leaf: blank))
	}

	@Test("S20: an UpdatePath leaf that isn't commit-sourced is rejected")
	func updatePathLeafNotCommitSource() throws {
		let pair = try Self.pair()
		// Alice's ORIGINAL KeyPackage leaf -- genuinely
		// key_package-sourced with a valid signature. (Her *current* tree
		// leaf is no use here: her own add-commit replaced it with a
		// commit-sourced one, which sails past this check -- the first
		// draft of this test learned that the hard way.)
		let leaf = pair.alice.keyPackage.leafNode
		Self.expectRejected(
			pair,
			try Self.craftedCommit(
				pair, proposals: [],
				path: .init(leafNode: leaf, nodes: [])),
			throws: .updatePathLeafNotCommitSource)
	}

	@Test("S20: an UpdatePath leaf reusing the committer's encryption key is rejected")
	func updatePathReusesEncryptionKey() throws {
		let pair = try Self.pair()
		let record = try #require(pair.groupA.tree.leaf(at: pair.groupA.myLeafIndex))
		let current = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
		// A really-signed commit-sourced leaf that keeps the old key.
		var leaf = current
		leaf.source = .commit(parentHash: Data(repeating: 1, count: 32))
		leaf.signature = try MLS.signWithLabel(
			Self.provider, privateKey: pair.alice.signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(
					groupID: pair.groupA.context.groupID,
					leafIndex: pair.groupA.myLeafIndex)))
		Self.expectRejected(
			pair,
			try Self.craftedCommit(
				pair, proposals: [], path: .init(leafNode: leaf, nodes: [])),
			throws: .updatePathReusesEncryptionKey)
	}

	/// The first of the two standing holes: a fully valid commit whose
	/// confirmation tag alone is wrong. The naive mutation dies at the
	/// membership tag instead, so the membership tag is recomputed over
	/// the tampered auth data — which is exactly what a malicious *member*
	/// can do, making this the right adversary model for the check.
	@Test("S12/S25: a wrong confirmation tag on an otherwise-valid commit is rejected")
	func confirmationTagMismatch() throws {
		let pair = try Self.pair()
		var groupA = pair.groupA
		let out = try groupA.committing(
			Self.provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(Self.provider))
		var message = out.commit
		message.auth.confirmationTag = MLS.ConfirmationTag(
			Data(repeating: 0xCD, count: 32))

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: try message.content.mlsEncoded(),
			encodedGroupContext: try pair.groupA.context.mlsEncoded())
		var authWriter = MLS.Writer()
		try message.auth.encodeRequiringSignature(
			contentType: .commit, to: &authWriter)
		message.membershipTag = try MLS.Framing.membershipTag(
			Self.provider, membershipKey: pair.groupA.epoch.membershipKey,
			signedContent: signedContent, encodedAuthData: Data(authWriter.bytes))

		Self.expectRejected(pair, message, throws: .confirmationTagMismatch)
	}

	/// The second standing hole: a resumption PSK with reinit usage.
	@Test("a reinit-usage resumption PSK in a commit is rejected")
	func unsupportedResumptionUsage() throws {
		let pair = try Self.pair()
		let psk = MLS.RFC9420.Proposal.preSharedKey(
			.resumption(
				.init(
					usage: .reinit, groupID: pair.groupA.context.groupID,
					epoch: 0),
				nonce: Data(repeating: 5, count: Self.provider.hashSize)))
		Self.expectRejected(
			pair,
			try Self.craftedCommit(pair, proposals: [.proposal(psk)], path: nil),
			throws: .unsupportedResumptionUsage)
	}
}
