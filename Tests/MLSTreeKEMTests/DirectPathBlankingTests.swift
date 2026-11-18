import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import SecretBytes
import Testing

@testable import MLSTreeKEM

/// RFC 9420 §7.5: the recipient must "Blank all nodes on the direct path of the
/// sender's leaf" (the sender does the same) before setting the filtered direct
/// path, so a stale key on a filtered node never survives a commit.
@Suite("UpdatePath blanks the sender's whole direct path (RFC 9420 §7.5)")
struct DirectPathBlankingTests {
	static let provider = SwiftCryptoProvider()

	private static func leaf(_ tag: UInt8, _ provider: any MLS.CipherSuiteProvider) throws
		-> MLS.TreeKEM.LeafRecord
	{
		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		return .init(encryptionKey: publicKey, parentHash: nil, encoded: Data([tag]))
	}

	private static func staleParent(_ provider: any MLS.CipherSuiteProvider) throws
		-> MLS.TreeKEM.ParentNode
	{
		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		return .init(encryptionKey: publicKey, parentHash: Data(), unmergedLeaves: [])
	}

	/// Four leaves. Leaf 1 is blank, so the sender's (leaf 0) direct-path node 1
	/// has an empty copath resolution and is filtered, yet it holds a stale key.
	/// Node 3 (root) is unfiltered.
	private static func treeWithStaleFilteredNode(
		_ provider: any MLS.CipherSuiteProvider, filteredNodeBlank: Bool = false
	) throws -> (tree: MLS.TreeKEM.RatchetTree, stale: MLS.TreeKEM.ParentNode) {
		let stale = try staleParent(provider)
		let nodes: [MLS.TreeKEM.TreeNode?] = [
			.leaf(try leaf(0, provider)),
			filteredNodeBlank ? nil : .parent(stale),
			nil,
			nil,
			.leaf(try leaf(2, provider)),
			nil,
			.leaf(try leaf(3, provider)),
		]
		return (try MLS.TreeKEM.RatchetTree(nodes: nodes), stale)
	}

	private static let sender = MLS.LeafIndex(value: 0)

	private static func commit(
		_ tree: inout MLS.TreeKEM.RatchetTree, _ provider: any MLS.CipherSuiteProvider
	) throws -> (leaf: MLS.TreeKEM.LeafRecord, pathNodes: [MLS.TreeKEM.PathNode]) {
		let seed = try SecretBytes(bytes: Data(repeating: 0xAB, count: provider.hashSize))
		let stage = try tree.beginCommitPath(
			sender: sender, firstPathSecret: seed, provider)
		let (_, key) = try provider.hpkeGenerateKeyPair()
		let newLeaf = MLS.TreeKEM.LeafRecord(
			encryptionKey: key, parentHash: stage.leafParentHash, encoded: Data([0xFE]))
		try tree.setLeaf(sender, to: newLeaf)
		let context = try tree.treeHash(provider)
		let (pathNodes, _) = try tree.finishCommitPath(
			stage, groupContext: context, excluding: [], provider)
		return (newLeaf, pathNodes)
	}

	@Test("merging an UpdatePath blanks a non-blank filtered node on the sender's direct path")
	func applyUpdatePathBlanksFilteredDirectPathNodes() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		let (original, _) = try Self.treeWithStaleFilteredNode(provider)
		var committer = original
		let (leaf, pathNodes) = try Self.commit(&committer, provider)

		var receiver = original
		try receiver.applyUpdatePath(
			sender: Self.sender, leaf: leaf, pathNodes: pathNodes, provider)

		#expect(receiver.isBlank(at: 1))
		#expect(receiver.parent(at: 3) != nil)
	}

	@Test("building an UpdatePath blanks a non-blank filtered node on the sender's direct path")
	func beginCommitPathBlanksFilteredDirectPathNodes() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		var tree = try Self.treeWithStaleFilteredNode(provider).tree
		_ = try tree.beginCommitPath(
			sender: Self.sender,
			firstPathSecret: try SecretBytes(
				bytes: Data(repeating: 0xAB, count: provider.hashSize)),
			provider)

		#expect(tree.isBlank(at: 1))
		#expect(tree.parent(at: 3) != nil)
	}

	@Test(
		"the tree hash after the commit differs from the hash with the stale filtered node kept"
	)
	func blankingChangesTreeHashWhenFilteredNodeWasNonBlank() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		let (original, stale) = try Self.treeWithStaleFilteredNode(provider)
		var tree = original
		_ = try Self.commit(&tree, provider)
		let blanked = try tree.treeHash(provider)

		try tree.setParent(1, to: stale)
		#expect(try tree.treeHash(provider) != blanked)
	}

	@Test(
		"committer and receiver reach the same tree hash when a filtered node was non-blank"
	)
	func committerAndReceiverConvergeWhenFilteredNodeWasNonBlank() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		let (original, _) = try Self.treeWithStaleFilteredNode(provider)
		var committer = original
		let (leaf, pathNodes) = try Self.commit(&committer, provider)
		var receiver = original
		try receiver.applyUpdatePath(
			sender: Self.sender, leaf: leaf, pathNodes: pathNodes, provider)

		#expect(try receiver.treeHash(provider) == committer.treeHash(provider))
	}

	@Test("the tree hash is unchanged when every filtered node was already blank")
	func blankingLeavesTreeHashUnchangedWhenFilteredNodesAreBlank() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		let (original, _) = try Self.treeWithStaleFilteredNode(
			provider, filteredNodeBlank: true)
		var committer = original
		let (leaf, pathNodes) = try Self.commit(&committer, provider)
		var receiver = original
		try receiver.applyUpdatePath(
			sender: Self.sender, leaf: leaf, pathNodes: pathNodes, provider)

		var expected = original
		try expected.setLeaf(Self.sender, to: leaf)
		try expected.setParent(
			3,
			to: .init(
				encryptionKey: pathNodes[0].encryptionKey, parentHash: Data(),
				unmergedLeaves: []))
		#expect(try receiver.treeHash(provider) == expected.treeHash(provider))
		#expect(receiver == committer)
	}
}
