import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// Stage-5 review findings #1 and #2, both exercised against one shared
/// tree shape: a commit that adds a new member (excluded from path-secret
/// encryption, RFC 9420's own rule -- a brand-new leaf has no key anything
/// could have been encrypted under yet) alongside an existing member whose
/// copath resolution sits *next to* the new leaf, so the ciphertext count
/// and position genuinely differ with/without the exclusion. The same
/// commit also has a filtered root-level entry (an entirely untouched
/// subtree), which is what `installPathSecrets`' filtered-skip fix needs.
///
/// 8-leaf tree, node indices 0-14:
/// ```
///                     7
///           3                   11
///      1         5         9         13
///   0     2   4     6   8     10  12    14
/// ```
/// Leaf 0 (node 0): sender. Leaf 1 (node 2): blank, unused. Leaf 2
/// (node 4): blank until this commit's Add -- the new joiner. Leaf 3
/// (node 6): an existing member, present from the start. Leaves 4-7
/// (nodes 8/10/12/14, under node 11): blank throughout -- node 11's
/// resolution is empty, so the root-level direct-path entry (sibling 11)
/// is filtered.
@Suite("Add-exclusion: decap excluding, installPathSecrets filtered-skip")
struct AddExclusionTests {
	static let provider = SwiftCryptoProvider()

	struct Scenario {
		var committerTree: MLS.TreeKEM.RatchetTree
		var pathNodes: [MLS.TreeKEM.PathNode]
		var commitSecret: Data
		var groupContext: Data
		var sender: MLS.LeafIndex
		var joiner: MLS.LeafIndex
		var leaf3SecretKey: MLS.HpkeSecretKey
		/// `GroupSecrets.path_secret`, as a Welcome-joiner would receive
		/// it -- the path secret at the LCA (node 3). Node 3 is this
		/// scenario's *only* unfiltered direct-path entry and the first
		/// one `beginCommitPath`'s chain ever reaches, so it equals
		/// `firstPathSecret` itself, unadvanced -- `CommitPathStage` is
		/// deliberately opaque (a matched pair with `finishCommitPath`),
		/// so this is derived by that reasoning rather than read out of it.
		var lcaPathSecret: Data
	}

	static func buildScenario() throws -> Scenario {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let (_, senderInitialPublicKey) = try provider.hpkeGenerateKeyPair()
		let (leaf3SecretKey, leaf3PublicKey) = try provider.hpkeGenerateKeyPair()

		var nodes: [MLS.TreeKEM.TreeNode?] = Array(repeating: nil, count: 15)
		nodes[0] = .leaf(
			.init(
				encryptionKey: senderInitialPublicKey, parentHash: nil,
				encoded: Data([0])))
		nodes[6] = .leaf(
			.init(encryptionKey: leaf3PublicKey, parentHash: nil, encoded: Data([3])))
		var tree = try MLS.TreeKEM.RatchetTree(nodes: nodes)

		let sender = MLS.LeafIndex(value: 0)

		// Apply the Add proposal: insert the joiner at leaf 2 specifically
		// (leaf 1 is blank and would otherwise win `insertLeaf`'s
		// leftmost-blank search), then mark it unmerged along its own
		// direct path -- a no-op here since every ancestor above it is
		// still blank, but it's what a real Add-application does.
		let (_, joinerPublicKey) = try provider.hpkeGenerateKeyPair()
		let joiner = tree.insertLeaf(
			.init(encryptionKey: joinerPublicKey, parentHash: nil, encoded: Data([2])),
			hint: .init(value: 2))
		try #require(joiner == .init(value: 2))
		for step in try MLS.TreeMath.directPath(
			from: 2 * joiner.value, leafCount: tree.leafCount)
		{
			try tree.addUnmergedLeaf(joiner, to: step.path)
		}

		let firstPathSecret = Data(repeating: 0x42, count: provider.hashSize)
		let stage = try tree.beginCommitPath(
			sender: sender, firstPathSecret: firstPathSecret, provider)

		let (_, senderPublicKey) = try provider.hpkeGenerateKeyPair()
		tree.setLeaf(
			sender,
			to: .init(
				encryptionKey: senderPublicKey, parentHash: stage.leafParentHash,
				encoded: Data([0xFF])))

		let groupContext = try tree.treeHash(provider)
		let (pathNodes, commitSecret) = try tree.finishCommitPath(
			stage, groupContext: groupContext, excluding: [joiner], provider)

		return Scenario(
			committerTree: tree, pathNodes: pathNodes, commitSecret: commitSecret,
			groupContext: groupContext, sender: sender, joiner: joiner,
			leaf3SecretKey: leaf3SecretKey, lcaPathSecret: firstPathSecret)
	}

	/// Sanity check on the scenario itself, not the fixes: exactly one
	/// unfiltered direct-path entry (node 3 -- node 7/root is filtered,
	/// its whole subtree is blank), and exactly one ciphertext at it (leaf
	/// 3's -- the joiner at node 4 is excluded from encryption entirely).
	@Test("scenario has one unfiltered path entry with one (not two) ciphertexts")
	func scenarioShape() throws {
		let scenario = try Self.buildScenario()
		#expect(scenario.pathNodes.count == 1)
		#expect(scenario.pathNodes[0].encryptedPathSecrets.count == 1)
	}

	@Test(
		"decapCommitPath with the correct excluding set recovers the committer's commit_secret"
	)
	func decapWithCorrectExcludingSucceeds() throws {
		let scenario = try Self.buildScenario()
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let secret = try scenario.committerTree.decapCommitPath(
			heldSecretKeys: [6: scenario.leaf3SecretKey], sender: scenario.sender,
			pathNodes: scenario.pathNodes, groupContext: scenario.groupContext,
			excluding: [scenario.joiner], provider)

		#expect(secret == scenario.commitSecret)
	}

	/// The excluding fix, demonstrated without touching the source: the
	/// wire ciphertext count (1, leaf 3 only) only lines up with what
	/// `validatePathStructure`/the position lookup expect when `excluding`
	/// names the joiner. Passing the wrong set (here, empty) is exactly
	/// the pre-fix call shape (`decapCommitPath` used to hardcode `[]`
	/// internally in both places) and must fail structurally rather than
	/// silently landing on a wrong secret.
	@Test("decapCommitPath with the wrong excluding set fails structurally, not silently")
	func decapWithWrongExcludingFails() throws {
		let scenario = try Self.buildScenario()
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		#expect(throws: MLS.TreeKEM.TreeError.self) {
			_ = try scenario.committerTree.decapCommitPath(
				heldSecretKeys: [6: scenario.leaf3SecretKey],
				sender: scenario.sender,
				pathNodes: scenario.pathNodes, groupContext: scenario.groupContext,
				excluding: [], provider)
		}
	}

	/// The filtered-skip fix: the joiner's LCA with the sender is node 3;
	/// walking from there to the root crosses exactly one filtered entry
	/// (node 7/root, sibling 11's subtree is entirely blank). Before the
	/// fix, `installPathSecrets` required a non-blank parent (and a
	/// chain-derived key match) at *every* entry including that filtered
	/// one -- node 7 is blank, so it always threw `publicKeyMismatch` on
	/// a perfectly valid Welcome. After the fix, the filtered entry is
	/// skipped outright: one installed key (node 3), not two, and no
	/// attempt to touch node 7 at all.
	@Test("installPathSecrets skips the filtered root entry instead of failing on it")
	func installPathSecretsSkipsFilteredEntry() throws {
		let scenario = try Self.buildScenario()
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let installed = try scenario.committerTree.installPathSecrets(
			forLeaf: scenario.joiner, from: scenario.sender,
			pathSecret: scenario.lcaPathSecret,
			provider)

		#expect(installed.map(\.node) == [3])
		let derivedPublicKey = try MLS.TreeKEM.nodeKeyPair(
			provider, pathSecret: scenario.lcaPathSecret
		)
		.publicKey
		#expect(scenario.committerTree.parent(at: 3)?.encryptionKey == derivedPublicKey)
	}
}
