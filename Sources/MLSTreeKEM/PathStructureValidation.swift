import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// The explicit path-structure validation `Commit.path`'s wire types
	/// (`UpdatePath`/`UpdatePathNode`) were split out to require — the tree
	/// phase's own headline: `MLSFraming`'s opaque wrapper couldn't check this,
	/// because it has no tree to check against.
	///
	/// `sender`'s `UpdatePath.nodes` must supply exactly one entry per
	/// *unfiltered* direct-path position (S9), and each entry's ciphertext
	/// count must equal its copath resolution's size, minus any leaves
	/// excluded because they were added in this same commit (S10).
	///
	/// mls-rs is *not* this strict in either direction that matters: a
	/// *short* `nodes` array is a bare out-of-bounds index at the point
	/// it's used, and ciphertext count is never checked eagerly at all.
	/// (It does reject an over-*long* path up front, so S9 is only half
	/// unchecked there.) Both checks here run eagerly, before anything
	/// consumes the path — exactly what this validation exists for.
	public func validatePathStructure(
		sender: MLS.LeafIndex, nodeCiphertextCounts: [Int], excluding: Set<MLS.LeafIndex>
	) throws {
		let filtered = try filteredDirectPath(from: sender)
		let path = MLS.TreeMath.directPath(from: 2 * sender.value, leafCount: leafCount)
		let expectedCount = filtered.filter { !$0 }.count

		guard nodeCiphertextCounts.count == expectedCount else {
			throw MLS.TreeKEM.TreeError.wrongPathNodeCount(
				expected: expectedCount, actual: nodeCiphertextCounts.count)
		}

		var pathIndex = 0
		for (step, isFiltered) in zip(path, filtered) where !isFiltered {
			let excludedNodeIndices = Set(excluding.map { 2 * $0.value })
			let expectedCiphertexts = resolution(of: step.sibling)
				.filter { !excludedNodeIndices.contains($0) }
				.count
			guard nodeCiphertextCounts[pathIndex] == expectedCiphertexts else {
				throw MLS.TreeKEM.TreeError.wrongCiphertextCount(
					pathIndex: pathIndex, expected: expectedCiphertexts,
					actual: nodeCiphertextCounts[pathIndex])
			}
			pathIndex += 1
		}
	}
}
