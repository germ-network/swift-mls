import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// The receiver's half of processing a commit's `UpdatePath`: merges the
	/// sender's fresh leaf and every unfiltered direct-path node's new
	/// public key into the local tree, then recomputes and verifies the
	/// resulting parent-hash chain against what the sender's own new leaf
	/// claims (`leaf.parentHash`). Every node on the sender's direct path
	/// is blanked first (RFC 9420 §7.5), so a filtered node ends up blank
	/// rather than keeping a stale key. `parentHashForLeaf` is the same
	/// computation that *builds* a chain on the committer's side and
	/// *verifies* one here; RFC 9420 §7.9 defines it once.
	///
	/// Every unfiltered node's `unmergedLeaves` is cleared here too — RFC
	/// 9420's commit-construction rule the committer already applied to
	/// their own tree before signing; every other member must replicate the
	/// identical mutation to converge on the same tree hash.
	///
	/// Distinct from `decapCommitPath`: that computes `commit_secret` by
	/// decrypting one entry and deriving forward, and never mutates the
	/// tree. This merges the *public* structure every member must converge
	/// on, independent of whether (or how) this receiver could decrypt
	/// anything. Callers run both — order doesn't matter, neither reads
	/// what the other wrote.
	public mutating func applyUpdatePath(
		sender: MLS.LeafIndex, leaf: MLS.TreeKEM.LeafRecord,
		pathNodes: [MLS.TreeKEM.PathNode], _ provider: any MLS.CipherSuiteProvider
	) throws {
		let path = MLS.TreeMath.directPath(from: 2 * sender.value, leafCount: leafCount)
		let filtered = try filteredDirectPath(from: sender)
		let expectedCount = filtered.filter { !$0 }.count
		guard pathNodes.count == expectedCount else {
			throw MLS.TreeKEM.TreeError.wrongPathNodeCount(
				expected: expectedCount, actual: pathNodes.count)
		}

		try setLeaf(sender, to: leaf)
		try blankDirectPath(of: sender)

		var pathIndex = 0
		for (step, isFiltered) in zip(path, filtered) where !isFiltered {
			try setParent(
				step.path,
				to: .init(
					encryptionKey: pathNodes[pathIndex].encryptionKey,
					parentHash: Data(),
					unmergedLeaves: []))
			pathIndex += 1
		}

		let computedLeafParentHash = try parentHashForLeaf(sender, provider)
		guard leaf.parentHash == computedLeafParentHash else {
			throw MLS.TreeKEM.TreeError.parentHashMismatch
		}
	}
}
