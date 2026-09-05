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
				provider, commit: message, proposals: .init(), psk: { _ in nil })
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

	/// §12.2: a regular commit is invalid if it contains an ExternalInit. The
	/// commit is validly signed and membership-tagged by a real member (Alice);
	/// only the ExternalInit is malformed. `validateProposalList` runs before the
	/// path-required and confirmation-tag checks, so this reaches the §12.2 gate
	/// — a malicious committer would otherwise compute a matching tag, since the
	/// receiver derives the epoch from the ordinary `init_secret`.
	@Test("§12.2: an ExternalInit in a regular commit is rejected, not accepted")
	func externalInitInRegularCommit() throws {
		let pair = try Self.pair()
		let externalInit = MLS.RFC9420.Proposal.externalInit(
			.init(kemOutput: Data(repeating: 0x01, count: 32)))
		Self.expectRejected(
			pair,
			try Self.craftedCommit(
				pair, proposals: [.proposal(externalInit)], path: nil),
			throws: .externalInitInRegularCommit)
	}

	/// The construct side refuses the same list with the same error — §12.2
	/// binds "a group member creating a Commit" as well as one processing it.
	@Test("§12.2: constructing a regular commit with an ExternalInit is refused")
	func externalInitConstructRefused() throws {
		let pair = try Self.pair()
		let externalInit = MLS.RFC9420.Proposal.externalInit(
			.init(kemOutput: Data(repeating: 0x01, count: 32)))
		#expect(throws: MLS.RFC9420.GroupError.externalInitInRegularCommit) {
			_ = try pair.groupA.committing(
				Self.provider, proposals: [.proposal(externalInit)],
				signingKey: pair.alice.signingKey,
				randomness: .generate(Self.provider))
		}
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

	@Test("§12.4.2: an UpdatePath leaf reusing the committer's current key is rejected")
	func updatePathReusesCommitterKey() throws {
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
			throws: .updatePathReusesCommitterKey)
	}

	/// The whole-tree freshness sweep, now separately testable: a
	/// commit-sourced leaf reusing *Bob's* key — in the tree, but not the
	/// committer's own — reaches past the committer-key bullet and trips
	/// the sweep. Before the error split, this and the case above were one
	/// case, and deleting the committer-key check was mutation-invisible.
	@Test("S20: an UpdatePath leaf reusing another member's key trips the freshness sweep")
	func updatePathReusesEncryptionKey() throws {
		let pair = try Self.pair()
		let bobIndex = try #require(
			pair.groupA.tree.nonBlankLeaves().map(\.0).first {
				$0 != pair.groupA.myLeafIndex
			})
		let bobRecord = try #require(pair.groupA.tree.leaf(at: bobIndex))
		let record = try #require(pair.groupA.tree.leaf(at: pair.groupA.myLeafIndex))
		var leaf = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
		leaf.encryptionKey = bobRecord.encryptionKey
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

	/// §12.4.2's first sentence — "Validate the LeafNode as specified in
	/// Section 7.3" — was unimplemented for the UpdatePath leaf until the
	/// stage-5 review found `.commitUpdatePath` dead: the committer's new
	/// identity binding entered the tree without the policy checks every
	/// other leaf gets. The group here carries a required_capabilities
	/// its members satisfy; the crafted path leaf does not.
	@Test("an UpdatePath leaf that fails section 7.3 policy is rejected")
	func updatePathLeafFailsPolicy() throws {
		let provider = Self.provider
		let required = MLS.RFC9420.ExtensionType(rawValue: 99)
		let alice = try SelfInteropTests.member("alice", capabilityExtensions: [required])
		let bob = try SelfInteropTests.member("bob", capabilityExtensions: [required])

		var writer = MLS.Writer()
		try writer.encode(MLS.RFC9420.RequiredCapabilities(extensionTypes: [required]))
		let requirement = MLS.RFC9420.Extension(
			type: .init(.requiredCapabilities), data: Data(writer.bytes))

		var groupA = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(32),
			leafNode: alice.keyPackage.leafNode,
			leafSecretKey: alice.leafSecretKey,
			extensions: [requirement],
			epochSecret: provider.randomBytes(provider.hashSize))
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// A commit-sourced leaf, really signed by Alice, with a fresh key
		// -- valid in every way except its capabilities omit the required
		// extension type.
		let (_, freshKey) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: freshKey,
			signatureKey: alice.keyPackage.leafNode.signatureKey,
			credential: alice.keyPackage.leafNode.credential,
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .commit(parentHash: Data(repeating: 1, count: 32)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: alice.signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(
					groupID: groupA.context.groupID,
					leafIndex: groupA.myLeafIndex)))
		let content = MLS.RFC9420.FramedContent(
			groupID: groupA.context.groupID, epoch: groupA.context.epoch,
			sender: .member(groupA.myLeafIndex), authenticatedData: Data(),
			content: .commit(
				.init(
					proposals: [],
					path: .init(leafNode: leaf, nodes: []))))
		let message = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: groupA.context,
			confirmationTag: MLS.ConfirmationTag(Data(repeating: 0xAB, count: 32)),
			signingKey: alice.signingKey,
			membershipKey: groupA.epoch.membershipKey)
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			try groupB.process(
				provider, commit: message, proposals: .init(), psk: { _ in nil })
		}
	}

	/// The first of the two standing holes: a fully valid commit whose
	/// confirmation tag alone is wrong. The naive mutation dies at the
	/// membership tag instead, so the membership tag is recomputed over
	/// the tampered auth data — which is exactly what a malicious *member*
	/// can do, making this the right adversary model for the check.
	@Test("S12/S25: a wrong confirmation tag on an otherwise-valid commit is rejected")
	func confirmationTagMismatch() throws {
		let pair = try Self.pair()
		let out = try pair.groupA.committing(
			Self.provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(Self.provider), framing: .publicMessage)
		guard case .publicMessage(var message) = out.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}
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
