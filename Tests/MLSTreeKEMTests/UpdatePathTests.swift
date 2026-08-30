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
		tree.setLeaf(
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
				decapped == commitSecret,
				"leaf \(leaf) decapsulating sender 0's fresh path")
		}
	}
}
