import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// The round trip the plan calls out as the strongest proof encap and
/// decap actually agree: build a fresh commit path (`beginCommitPath` +
/// `finishCommitPath`) over a synthetic tree, then have every other leaf
/// decap it and confirm they all recover the identical `commit_secret`.
/// `treekem.json`'s own vectors only exercise decap against an
/// externally-generated path; this is the half that vector can't cover.
@Suite("Encap/decap round trip (synthetic tree, no wire format)")
struct UpdatePathTests {
	static let provider = SwiftCryptoProvider()

	@Test("every other leaf recovers the same commit_secret a fresh commit path produces")
	func encapDecapRoundTrip() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		// A fresh 4-leaf tree, all parents blank -- nobody shares a key yet.
		var leafKeys:
			[MLS.LeafIndex: (secret: MLS.HpkeSecretKey, public: MLS.HpkePublicKey)] =
				[:]
		var nodes: [MLS.TreeKEM.TreeNode?] = []
		for i in 0..<4 {
			let (secretKey, publicKey) = try provider.hpkeGenerateKeyPair()
			leafKeys[.init(value: UInt32(i))] = (secretKey, publicKey)
			nodes.append(
				.leaf(
					.init(
						encryptionKey: publicKey, parentHash: nil,
						encoded: Data([UInt8(i)]))))
			if i < 3 { nodes.append(nil) }
		}
		var tree = try MLS.TreeKEM.RatchetTree(nodes: nodes)

		let sender = MLS.LeafIndex(value: 0)
		let firstPathSecret = Data(repeating: 0xAB, count: provider.hashSize)
		let stage = try tree.beginCommitPath(
			sender: sender, firstPathSecret: firstPathSecret, provider)

		// Encap step 3 (profile's job in reality): install the committer's
		// new leaf, carrying the parent_hash beginCommitPath computed.
		// Skipped here: signing a real LeafNode -- only the tree-level
		// round trip is this test's concern.
		let (senderSecretKey, senderPublicKey) = try provider.hpkeGenerateKeyPair()
		leafKeys[sender] = (senderSecretKey, senderPublicKey)
		try tree.setLeaf(
			sender,
			to: .init(
				encryptionKey: senderPublicKey, parentHash: stage.leafParentHash,
				encoded: Data([0xFF])))

		// Encap step 4 (profile's job): the GroupContext used as HPKE
		// info. This test only needs consistent bytes on both sides, not
		// a real GroupContext structure.
		let groupContext = try tree.treeHash(provider)

		let (pathNodes, commitSecret) = try tree.finishCommitPath(
			stage, groupContext: groupContext, excluding: [], provider)

		try tree.validatePathStructure(
			sender: sender,
			nodeCiphertextCounts: pathNodes.map(\.encryptedPathSecrets.count),
			excluding: [])

		for leaf in [1, 2, 3] {
			let receiver = MLS.LeafIndex(value: UInt32(leaf))
			let heldKeys = [2 * receiver.value: leafKeys[receiver]!.secret]
			let decapped = try tree.decapCommitPath(
				heldSecretKeys: heldKeys, sender: sender, pathNodes: pathNodes,
				groupContext: groupContext, provider)
			#expect(
				decapped.commitSecret == commitSecret,
				"leaf \(leaf) decapsulating sender 0's fresh path")
		}
	}

	/// Stage-5 review finding: `commit_secret` for a commit whose filtered
	/// direct path has *zero* unfiltered entries (a single-leaf tree, here)
	/// was one derivation past `firstPathSecret` -- wrong, since the chain
	/// never actually advances past the seed when nothing consumes it.
	/// mls-rs's `PathSecretGenerator`'s first `next_secret()` call, whatever
	/// triggers it, returns the seed unadvanced; `commit_secret` here is
	/// exactly that first (and only) call.
	@Test(
		"commit_secret for a single-leaf tree's commit is firstPathSecret itself, not a derivation of it"
	)
	func emptyPathCommitSecretIsUnadvanced() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		var tree = MLS.TreeKEM.RatchetTree(
			singleLeaf: .init(
				encryptionKey: publicKey, parentHash: nil, encoded: Data([0])))

		let sender = MLS.LeafIndex(value: 0)
		let firstPathSecret = Data(repeating: 0x11, count: provider.hashSize)
		let stage = try tree.beginCommitPath(
			sender: sender, firstPathSecret: firstPathSecret, provider)

		let (_, senderPublicKey) = try provider.hpkeGenerateKeyPair()
		try tree.setLeaf(
			sender,
			to: .init(
				encryptionKey: senderPublicKey, parentHash: stage.leafParentHash,
				encoded: Data([0xFF])))

		let (_, commitSecret) = try tree.finishCommitPath(
			stage, groupContext: Data(), excluding: [], provider)

		#expect(commitSecret == firstPathSecret)
	}

	/// Stage-5 review finding: nothing in this component previously merged
	/// a wire `UpdatePath` into a *receiver's* tree at all -- only the
	/// committer's own tree ever got the new leaf/keys/parent-hashes
	/// installed (`beginCommitPath` mutates in place), and `decapCommitPath`
	/// only ever computed `commit_secret`, never touched tree structure.
	/// Every other member needs the same public mutations the committer
	/// applied to their own copy in order to converge on the same tree
	/// (and therefore the same `tree_hash` for `GroupContext`). This proves
	/// `applyUpdatePath` produces exactly that: an independent tree that
	/// started identical pre-commit ends up structurally equal to the
	/// committer's own tree after merging the same wire path.
	@Test(
		"applyUpdatePath merges a committer's path into an independent receiver tree, converging on the same structure"
	)
	func applyUpdatePathConverges() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		var nodes: [MLS.TreeKEM.TreeNode?] = []
		for i in 0..<4 {
			let (_, publicKey) = try provider.hpkeGenerateKeyPair()
			nodes.append(
				.leaf(
					.init(
						encryptionKey: publicKey, parentHash: nil,
						encoded: Data([UInt8(i)]))))
			if i < 3 { nodes.append(nil) }
		}
		var committerTree = try MLS.TreeKEM.RatchetTree(nodes: nodes)
		var receiverTree = committerTree

		let sender = MLS.LeafIndex(value: 0)
		let firstPathSecret = Data(repeating: 0xCD, count: provider.hashSize)
		let stage = try committerTree.beginCommitPath(
			sender: sender, firstPathSecret: firstPathSecret, provider)

		let (_, senderPublicKey) = try provider.hpkeGenerateKeyPair()
		let newLeaf = MLS.TreeKEM.LeafRecord(
			encryptionKey: senderPublicKey, parentHash: stage.leafParentHash,
			encoded: Data([0xFE]))
		try committerTree.setLeaf(sender, to: newLeaf)

		let groupContext = try committerTree.treeHash(provider)
		let (pathNodes, _) = try committerTree.finishCommitPath(
			stage, groupContext: groupContext, excluding: [], provider)

		try receiverTree.applyUpdatePath(
			sender: sender, leaf: newLeaf, pathNodes: pathNodes, provider)

		#expect(receiverTree == committerTree)
	}
}
