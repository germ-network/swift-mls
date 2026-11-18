import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §16.7: tree encryption keys "MUST be distinct from one another".
/// §12.4.2's checks compare an UpdatePath only against the tree before it is
/// merged; this implementation also checks the commit's final tree, path or not,
/// and the send side runs the same checks, so every commit this library builds
/// is one it accepts.
@Suite("Commits never leave two tree nodes with one encryption key (RFC 9420 §16.7)")
struct CommitKeyUniquenessTests {
	static let provider = SelfInteropTests.provider

	/// Alice and Bob at epoch 1; Alice has already committed once with `used`.
	private static func afterCommit(
		using used: MLS.RFC9420.Group.CommitRandomness
	) throws -> (alice: SelfInteropTests.Member, group: MLS.RFC9420.Group) {
		let pair = try ProposalValidationTests.pair()
		var group = pair.groupA
		try group.commit(
			provider, proposals: [], signingKey: pair.alice.signingKey, randomness: used
		)
		return (pair.alice, group)
	}

	@Test(
		"committing twice with one CommitRandomness is refused on the second commit"
	)
	func committingRefusesReusedRandomness() throws {
		let used = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		let (alice, group) = try Self.afterCommit(using: used)
		#expect(throws: MLS.RFC9420.GroupError.updatePathReusesCommitterKey) {
			_ = try group.committing(
				Self.provider, proposals: [], signingKey: alice.signingKey,
				randomness: used, lifetimeCheck: .unchecked)
		}
	}

	@Test("a refused key reuse never requests a leaf signature")
	func refusedKeyReuseRequestsNoLeafSignature() throws {
		let used = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		let (alice, group) = try Self.afterCommit(using: used)
		let recorder = SignerSeamTests.RoleRecorder(
			provider: Self.provider, key: alice.signingKey)
		#expect(throws: MLS.RFC9420.GroupError.updatePathReusesCommitterKey) {
			_ = try group.committing(
				Self.provider, proposals: [], sign: recorder.sign, randomness: used,
				lifetimeCheck: .unchecked)
		}
		#expect(recorder.roles.isEmpty)
	}

	@Test("committing with a reused path secret and a fresh leaf key is refused")
	func committingRefusesReusedPathSecretWithFreshLeafKey() throws {
		let used = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		let (alice, group) = try Self.afterCommit(using: used)
		var reused = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		reused.firstPathSecret = used.firstPathSecret
		#expect(throws: MLS.RFC9420.GroupError.updatePathReusesEncryptionKey) {
			_ = try group.committing(
				Self.provider, proposals: [], signingKey: alice.signingKey,
				randomness: reused, lifetimeCheck: .unchecked)
		}
	}

	/// A member whose KeyPackage leaf carries `encryptionKey`, correctly signed.
	private static func member(
		_ name: String, encryptionKey: MLS.HpkePublicKey
	) throws -> SelfInteropTests.Member {
		let base = try SelfInteropTests.member(name)
		var leaf = base.keyPackage.leafNode
		leaf.encryptionKey = encryptionKey
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: base.signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = base.keyPackage
		keyPackage.leafNode = leaf
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: base.signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return .init(
			identity: base.identity, signingKey: base.signingKey,
			signatureKey: base.signatureKey, leafSecretKey: base.leafSecretKey,
			initSecretKey: base.initSecretKey, keyPackage: keyPackage)
	}

	@Test("committing with a path whose leaf key equals one of its node keys throws")
	func committingRefusesPathWhoseLeafKeyEqualsANodeKey() throws {
		let pair = try ProposalValidationTests.pair()
		var randomness = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		randomness.leafEncryptionPublicKey = try MLS.TreeKEM.nodeKeyPair(
			Self.provider, pathSecret: randomness.firstPathSecret
		).1
		#expect(throws: MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: 1)) {
			_ = try pair.groupA.committing(
				Self.provider, proposals: [], signingKey: pair.alice.signingKey,
				randomness: randomness, lifetimeCheck: .unchecked)
		}
	}

	@Test("receiving a commit whose path repeats a node key is rejected")
	func receivingRejectsPathWithDuplicateNodeKeys() throws {
		let provider = Self.provider
		let trio = try ProposalValidationTests.trio()
		let senderIndex = trio.groupA.myLeafIndex
		let nodeKey = try provider.hpkeGenerateKeyPair().1
		let (_, leafKey) = try provider.hpkeGenerateKeyPair()

		// Alice's direct path in a four-leaf tree is nodes 1 and 3, both with
		// non-empty copath resolutions. Give both the same key, with a
		// parent-hash chain that is consistent for that tree.
		var tree = trio.groupA.tree
		try tree.blankDirectPath(of: senderIndex)
		for node in [UInt32(1), 3] {
			try tree.setParent(
				node,
				to: .init(
					encryptionKey: nodeKey, parentHash: Data(),
					unmergedLeaves: []))
		}
		let parentHash = try tree.parentHashForLeaf(senderIndex, provider)

		var leaf = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(trio.groupA.tree.leaf(at: senderIndex)).encoded)
		leaf.encryptionKey = leafKey
		leaf.source = .commit(parentHash: parentHash)
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: trio.alice.signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(
					groupID: trio.groupA.context.groupID, leafIndex: senderIndex
				)))
		let ciphertext = MLS.HpkeCiphertext(
			kemOutput: Data(repeating: 1, count: 32),
			ciphertext: Data(repeating: 2, count: 32))
		let path = MLS.RFC9420.UpdatePath(
			leafNode: leaf,
			nodes: [
				.init(encryptionKey: nodeKey, encryptedPathSecret: [ciphertext]),
				.init(encryptionKey: nodeKey, encryptedPathSecret: [ciphertext]),
			])

		let message = try ConstructedRejectionTests.craftedCommit(
			.init(alice: trio.alice, groupA: trio.groupA, groupB: trio.groupB),
			proposals: [], path: path)
		var receiver = trio.groupB
		#expect(throws: MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: 3)) {
			try receiver.process(
				provider, commit: message, proposals: .init(), psk: { _ in nil })
		}
	}

	private static func pairAndParentKeyAdd() throws -> (
		pair: ProposalValidationTests.Pair, add: MLS.RFC9420.KeyPackage
	) {
		let pair = try ProposalValidationTests.pair()
		let parentKey = try #require(pair.groupA.tree.parent(at: 1)).encryptionKey
		let carol = try member("carol", encryptionKey: parentKey)
		return (pair, carol.keyPackage)
	}

	@Test(
		"receiving a pathless commit that Adds a leaf whose key equals a parent key is rejected"
	)
	func pathlessCommitRejectsAddWhoseLeafKeyEqualsAParentKey() throws {
		let (pair, add) = try Self.pairAndParentKeyAdd()
		let message = try ConstructedRejectionTests.craftedCommit(
			.init(alice: pair.alice, groupA: pair.groupA, groupB: pair.groupB),
			proposals: [.proposal(.add(add))], path: nil)
		var receiver = pair.groupB
		#expect(throws: MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: 4)) {
			try receiver.process(
				Self.provider, commit: message, proposals: .init(),
				psk: { _ in nil })
		}
	}

	@Test("committing an Add whose leaf key equals a parent key throws")
	func committingRefusesAddWhoseLeafKeyEqualsAParentKey() throws {
		let (pair, add) = try Self.pairAndParentKeyAdd()
		for includePath in [true, false] {
			#expect(throws: MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: 4)) {
				_ = try pair.groupA.committing(
					Self.provider, proposals: [.proposal(.add(add))],
					signingKey: pair.alice.signingKey,
					randomness: .generate(Self.provider),
					lifetimeCheck: .unchecked,
					includePath: includePath)
			}
		}
	}
}
