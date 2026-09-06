import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// A Welcome joiner installing path secrets walks the signer's direct path
/// from the LCA to the root and, at each unfiltered node, checks a key derived
/// from the path-secret chain against the tree's stored key (RFC 9420
/// §12.4.3.1: "The private key MUST be the private key that corresponds to the
/// public key in the node"). On the walked nodes it reads only that stored
/// `encryptionKey` — never their `unmergedLeaves`.
///
/// OpenMLS's equivalent (`treesync/mod.rs` `derive_path_secrets`) adds a step
/// swift-mls omits: it skips a non-blank walked node when the joiner is one of
/// that node's unmerged leaves. That skip is **subsumed** here, because the
/// commit that produced the Welcome already merged the committer's UpdatePath
/// along that very path — RFC 9420 §7.5 blanks the whole direct path (step 1),
/// then for each node of the *filtered* direct path sets the fresh key and
/// "Set[s] the list of unmerged leaves to the empty list" (step 2). So on the
/// LCA→root walk every node is either blank (skipped via `filteredDirectPath`)
/// or re-keyed with an empty unmerged list: no walked node can list the joiner,
/// and OpenMLS's extra skip can never fire on a valid Welcome.
///
/// Note the subsumption is an *identity*, not a toggle: `installPathSecrets`
/// never reads the walked nodes' `unmergedLeaves` (the only unmerged lists it
/// reads at all are the signer's copath siblings', via
/// `filteredDirectPath`→`resolution`, and only to test emptiness — which
/// unmerged contents cannot flip). So adding or removing a per-node
/// unmerged-leaf skip cannot change its result on any valid input; that
/// invariance is the whole claim. This test therefore does not "exercise the
/// skip"; it exercises the state OpenMLS's skip is written for (a joiner
/// unmerged at an unfiltered node) and confirms the commit clears it and the
/// install still lands the RFC-correct keys across it.
@Suite("installPathSecrets across a formerly-unmerged node")
struct UnmergedLeafInstallTests {
	static let provider = SwiftCryptoProvider()

	/// 8-leaf tree, node indices 0–14:
	/// ```
	///                     7
	///           3                   11
	///      1         5         9         13
	///   0     2   4     6   8     10  12    14
	/// ```
	/// Committer A = leaf 0 (node 0); joiner = leaf 1 (node 2); existing member
	/// B = leaf 3 (node 6). Leaves 4–7 (under node 11) stay blank, so node 11's
	/// resolution is empty and the root entry (sibling 11) is filtered.
	///
	/// Node 3 is pre-populated non-blank with a throwaway key, standing in for
	/// a prior epoch that keyed it — so the Add's unmerged-marking at node 3 is
	/// real, not the no-op it is when every ancestor is blank (as
	/// `AddExclusionTests` notes of its own joiner). The committer's direct
	/// path here has *two* unfiltered entries (nodes 1 and 3), so the install
	/// walk advances the path-secret chain once — coverage `AddExclusionTests`'
	/// single-entry walk does not have.
	@Test("a joiner unmerged at an unfiltered node installs correctly once the commit clears it")
	func unmergedLeafClearedThenInstalledAcrossChain() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let (_, aKey) = try provider.hpkeGenerateKeyPair()
		let (_, bKey) = try provider.hpkeGenerateKeyPair()
		let (_, staleNode3Key) = try provider.hpkeGenerateKeyPair()

		var nodes: [MLS.TreeKEM.TreeNode?] = Array(repeating: nil, count: 15)
		nodes[0] = .leaf(.init(encryptionKey: aKey, parentHash: nil, encoded: Data([0])))
		nodes[6] = .leaf(.init(encryptionKey: bKey, parentHash: nil, encoded: Data([3])))
		nodes[3] = .parent(
			.init(encryptionKey: staleNode3Key, parentHash: Data(), unmergedLeaves: []))
		var tree = try MLS.TreeKEM.RatchetTree(nodes: nodes)

		let committer = MLS.LeafIndex(value: 0)

		// Apply the Add: insert the joiner at leaf 1, then mark it unmerged on
		// every non-blank ancestor of its direct path — RFC 9420 §12.1.1 ("For
		// each non-blank intermediate node along the path from the leaf L to
		// the root, add L's leaf index to the unmerged_leaves list"). Node 3 is
		// non-blank so it genuinely lists the joiner; nodes 1 and 7 are blank,
		// so `addUnmergedLeaf` is a no-op there.
		let (_, joinerKey) = try provider.hpkeGenerateKeyPair()
		let joiner = try tree.insertLeaf(
			.init(encryptionKey: joinerKey, parentHash: nil, encoded: Data([1])),
			hint: .init(value: 1))
		try #require(joiner == .init(value: 1))
		for step in MLS.TreeMath.directPath(
			from: 2 * joiner.value, leafCount: tree.leafCount)
		{
			try tree.addUnmergedLeaf(joiner, to: step.path)
		}

		// (a) The scenario is non-vacuous: node 3 — an unfiltered entry on the
		// committer's direct path and on the joiner's LCA→root walk — lists the
		// joiner as unmerged. This is exactly the state OpenMLS's skip is for.
		#expect(tree.parent(at: 3)?.unmergedLeaves == [joiner])

		// The commit: derive and install fresh keys along the committer's
		// filtered direct path, clearing each such node's unmerged list — RFC
		// 9420 §7.5 merge step 2. The install below reads only tree state, so
		// the leaf-signing / `finishCommitPath` ceremony `AddExclusionTests`
		// performs is deliberately elided.
		let firstPathSecret = Data(repeating: 0x42, count: provider.hashSize)
		_ = try tree.beginCommitPath(
			sender: committer, firstPathSecret: firstPathSecret, provider)

		// (b) The clearing. Node 3 is re-keyed with an empty unmerged list, and
		// node 1 (the LCA, blank before the commit) is now keyed. Remove
		// `beginCommitPath`'s clearing and only this assertion fails.
		#expect(tree.parent(at: 3)?.unmergedLeaves == [])
		#expect(tree.parent(at: 1) != nil)

		// (c) The install. LCA(leaf 0, leaf 1) = node 1, the first unfiltered
		// entry on the committer's direct path, so its path secret is
		// `firstPathSecret` unadvanced — that is the value GroupSecrets carries
		// to the joiner (RFC 9420 §12.4.3.1). The walk installs node 1 then
		// node 3; node 7 (root) is filtered and skipped.
		let installed = try tree.installPathSecrets(
			forLeaf: joiner, from: committer, pathSecret: firstPathSecret, provider)

		#expect(installed.map(\.node) == [1, 3])

		// Each installed node's stored key must equal the key derived from the
		// path-secret chain: node 1 ← `firstPathSecret`, node 3 ← one "path"
		// step past it (RFC 9420 §7.4). The node-3 match is the load-bearing
		// one — it crosses the formerly-unmerged node and depends on the chain
		// advancing, which a single-entry walk never exercises.
		let node1Key = try MLS.TreeKEM.nodeKeyPair(
			provider, pathSecret: firstPathSecret
		).publicKey
		let node3Secret = try MLS.TreeKEM.nextPathSecret(provider, from: firstPathSecret)
		let node3Key = try MLS.TreeKEM.nodeKeyPair(
			provider, pathSecret: node3Secret
		).publicKey
		#expect(tree.parent(at: 1)?.encryptionKey == node1Key)
		#expect(tree.parent(at: 3)?.encryptionKey == node3Key)
	}
}
