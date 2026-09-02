import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// Synthetic leaf payloads throughout — no `LeafNode`, no profile linked at
/// all, which is the actual proof that `MLSTreeKEM` doesn't secretly depend
/// on `MLSProfileRFC9420`. The official tree vectors, which do need a real
/// `LeafNode` decoder, run in `MLSProfileRFC9420Tests` instead.
private func syntheticLeaf(_ tag: UInt8) -> MLS.TreeKEM.LeafRecord {
	MLS.TreeKEM.LeafRecord(
		encryptionKey: .init(Data([tag])), parentHash: nil, encoded: Data([tag, tag]))
}

private func syntheticParent(_ tag: UInt8, unmerged: [UInt32] = []) -> MLS.TreeKEM.ParentNode {
	MLS.TreeKEM.ParentNode(
		encryptionKey: .init(Data([tag])), parentHash: Data(),
		unmergedLeaves: unmerged.map { MLS.LeafIndex(value: $0) })
}

@Suite("RatchetTree structure and mutation")
struct RatchetTreeTests {
	@Test("a fresh single-leaf tree has one leaf, no parents, and the right leaf count")
	func singleLeaf() {
		let tree = MLS.TreeKEM.RatchetTree(singleLeaf: syntheticLeaf(1))
		#expect(tree.leafCount.value == 1)
		#expect(tree.leaf(at: .init(value: 0)) == syntheticLeaf(1))
	}

	@Test("out-of-physical-bounds indices read as blank, not a crash or a decode error")
	func outOfBoundsReadsAsBlank() {
		let tree = MLS.TreeKEM.RatchetTree(singleLeaf: syntheticLeaf(1))
		#expect(tree.leaf(at: .init(value: 5)) == nil)
		#expect(tree.parent(at: 99) == nil)
		#expect(tree.isBlank(at: 99))
	}

	@Test("setLeaf/setParent round-trip, and blanking with nil clears the slot")
	func setAndClear() throws {
		var tree = try MLS.TreeKEM.RatchetTree(nodes: [
			.leaf(syntheticLeaf(1)), nil, .leaf(syntheticLeaf(2)),
		])
		try tree.setParent(1, to: syntheticParent(9))
		#expect(tree.parent(at: 1) == syntheticParent(9))
		try tree.setParent(1, to: nil)
		#expect(tree.parent(at: 1) == nil)
	}

	@Test("serializedNodeCount stops at the last non-blank node, keeping interior blanks")
	func serializedNodeCountStopsAtLastNonBlank() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(1)), nil, nil, nil, .leaf(syntheticLeaf(2)),
				nil, nil,
			])
		// The array is held full-width (nodeCount 7), but only the run up to
		// the last non-blank node (index 4) is content — the trailing pair
		// (5-6) is what encode drops. Interior blanks (1-3) are not trailing.
		#expect(tree.serializedNodeCount == 5)
		#expect(tree.leaf(at: .init(value: 0)) == syntheticLeaf(1))
		#expect(tree.leaf(at: .init(value: 2)) == syntheticLeaf(2))
		#expect(tree.isBlank(at: 1))
		#expect(tree.isBlank(at: 3))
		// Leaf index 2 (node 4) is occupied, so the right half is not empty
		// and §7.7 truncation leaves leafCount at 4.
		tree.truncate()
		#expect(tree.leafCount.value == 4)
	}

	@Test("insertLeaf fills the leftmost blank leaf before ever growing the tree")
	func insertFillsBlankFirst() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [.leaf(syntheticLeaf(1)), .parent(syntheticParent(9)), nil])
		let index = try tree.insertLeaf(syntheticLeaf(3))
		#expect(index == MLS.LeafIndex(value: 1))
		#expect(tree.leaf(at: .init(value: 1)) == syntheticLeaf(3))
		#expect(tree.leafCount.value == 2)
	}

	@Test("insertLeaf grows the tree (doubling the padded leaf count) once every leaf is full")
	func insertGrowsWhenFull() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(1)), .parent(syntheticParent(9)),
				.leaf(syntheticLeaf(2)),
			])
		#expect(tree.leafCount.value == 2)
		let index = try tree.insertLeaf(syntheticLeaf(3))
		#expect(index == MLS.LeafIndex(value: 2))
		#expect(tree.leafCount.value == 4)
		#expect(tree.leaf(at: .init(value: 2)) == syntheticLeaf(3))
		#expect(tree.leaf(at: .init(value: 3)) == nil)
	}

	@Test(
		"blankLeafAndDirectPath clears the leaf and every ancestor, leaving the sibling alone"
	)
	func blankClearsDirectPathOnly() throws {
		// 4-leaf tree: leaves at 0,2,4,6; parents at 1,3,5.
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(0)), .parent(syntheticParent(1)),
				.leaf(syntheticLeaf(2)), .parent(syntheticParent(3)),
				.leaf(syntheticLeaf(4)), .parent(syntheticParent(5)),
				.leaf(syntheticLeaf(6)),
			])
		try tree.blankLeafAndDirectPath(.init(value: 0))
		#expect(tree.leaf(at: .init(value: 0)) == nil)
		#expect(tree.parent(at: 1) == nil)  // direct-path ancestor
		#expect(tree.parent(at: 3) == nil)  // root
		// The sibling subtree (leaf 1, node index 2) is untouched.
		#expect(tree.leaf(at: .init(value: 1)) == syntheticLeaf(2))
		#expect(tree.parent(at: 5) == syntheticParent(5))
	}

	@Test("addUnmergedLeaf keeps the list sorted ascending, regardless of insertion order")
	func unmergedLeavesStaySorted() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(0)), .parent(syntheticParent(1)),
				.leaf(syntheticLeaf(2)),
			])
		try tree.addUnmergedLeaf(.init(value: 5), to: 1)
		try tree.addUnmergedLeaf(.init(value: 1), to: 1)
		try tree.addUnmergedLeaf(.init(value: 3), to: 1)
		#expect(tree.parent(at: 1)?.unmergedLeaves.map(\.value) == [1, 3, 5])
	}

	@Test("addUnmergedLeaf rejects a duplicate rather than silently ignoring it")
	func unmergedLeavesRejectsDuplicate() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(0)), .parent(syntheticParent(1, unmerged: [2])),
				.leaf(syntheticLeaf(2)),
			])
		#expect(throws: MLS.TreeKEM.TreeError.duplicateUnmergedLeaf) {
			try tree.addUnmergedLeaf(.init(value: 2), to: 1)
		}
	}

	@Test("validateUnmergedLeaves accepts a tree with no unmerged leaves at all")
	func validateUnmergedLeavesAcceptsEmpty() throws {
		let tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(0)), .parent(syntheticParent(1)),
				.leaf(syntheticLeaf(2)),
			]
		)
		#expect(throws: Never.self) { try tree.validateUnmergedLeaves() }
	}

	@Test("validateNoDuplicateEncryptionKeys rejects two nodes sharing one HPKE key")
	func rejectsDuplicateEncryptionKey() throws {
		// Two distinct leaves, same tag -- `syntheticLeaf` derives the
		// encryption key from the tag, so this is the same key at two
		// different nodes (index 0 and index 2).
		let tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(9)), .parent(syntheticParent(1)),
				.leaf(syntheticLeaf(9)),
			])
		#expect(throws: MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: 2)) {
			try tree.validateNoDuplicateEncryptionKeys()
		}
	}
}

@Suite("Resolution and filtered direct path")
struct ResolutionTests {
	/// 4-leaf tree, node indices 0-6:
	///
	/// ```
	///           3
	///       1       5
	///     0   2   4   6
	/// ```
	///
	/// Leaves 0 and 3 (node indices 0, 6) are non-blank; leaf 1 (node
	/// index 2) is blank; leaf 2 (node index 4) is blank but its parent
	/// (index 5) carries it as an unmerged leaf. Parent 1 (covering
	/// leaves 0-1) is non-blank. Root (index 3) is blank.
	static func buildTree() throws -> MLS.TreeKEM.RatchetTree {
		try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(0)), .parent(syntheticParent(1)),
				nil, nil,
				nil, .parent(syntheticParent(5, unmerged: [2])),
				.leaf(syntheticLeaf(6)),
			])
	}

	@Test("a non-blank node's resolution is itself, then its unmerged leaves in order")
	func nonBlankNodeResolvesToItself() throws {
		let tree = try Self.buildTree()
		#expect(tree.resolution(of: 1) == [1])
		#expect(tree.resolution(of: 5) == [5, 4])  // itself, then unmerged leaf 2 -> node 4
	}

	@Test("a blank leaf resolves to nothing")
	func blankLeafResolvesEmpty() throws {
		let tree = try Self.buildTree()
		#expect(tree.resolution(of: 2) == [])
	}

	@Test("a blank parent's resolution is its children's resolutions, left then right")
	func blankParentRecursesLeftToRight() throws {
		let tree = try Self.buildTree()
		// Root (3) is blank -> recurse into left subtree (1, non-blank ->
		// [1]) then right subtree (5, non-blank with unmerged leaf 2 -> [5, 4]).
		#expect(tree.resolution(of: 3) == [1, 5, 4])
	}

	@Test("filteredDirectPath marks an entry true exactly where the copath resolution is empty")
	func filteredDirectPathMatchesEmptyCopathResolutions() throws {
		let tree = try Self.buildTree()
		// Direct path from leaf 0 (node 0): -> (path: 1, sibling: 2), (path: 3, sibling: 5).
		// Copath node 2 (blank leaf) resolves empty -> filtered = true.
		// Copath node 5 (non-blank) resolves non-empty -> filtered = false.
		#expect(try tree.filteredDirectPath(from: .init(value: 0)) == [true, false])
	}
}

/// The structural growth bound: `setNode` refuses any index beyond the
/// current padded tree except `insertLeaf`'s single doubling step. Before
/// this, the exact call below padded the backing array toward 2^25 entries
/// one nil at a time and then aborted the process on `leafCount`'s `try!`
/// — reproduced, not argued. `.timeLimit` because the pre-fix failure mode
/// at smaller indices is minutes of allocation, not a thrown error.
@Suite("RatchetTree growth bounds")
struct RatchetTreeGrowthTests {
	private func leaf(_ byte: UInt8) -> MLS.TreeKEM.LeafRecord {
		.init(
			encryptionKey: MLS.HpkePublicKey(Data([byte])), parentHash: nil,
			encoded: Data([byte]))
	}

	@Test(
		"an index beyond the padded tree throws instead of allocating toward an abort",
		.timeLimit(.minutes(1)),
		arguments: [UInt32(1) << 20, UInt32(1) << 23])
	func outOfBoundsThrows(_ index: UInt32) throws {
		var tree = MLS.TreeKEM.RatchetTree(singleLeaf: leaf(1))
		#expect(
			throws: MLS.TreeKEM.TreeError.nodeIndexOutOfBounds(
				index: 2 * index, nodeCount: 1)
		) {
			try tree.setLeaf(MLS.LeafIndex(value: index), to: nil)
		}
		// And the tree is untouched -- it is still a single-leaf tree.
		#expect(tree.leafCount.value == 1)
	}

	@Test("the doubling step still works: a full tree grows by exactly one leaf pair")
	func doublingStepStillGrows() throws {
		var tree = MLS.TreeKEM.RatchetTree(singleLeaf: leaf(1))
		let index = try tree.insertLeaf(leaf(2))
		#expect(index.value == 1)
		#expect(tree.leafCount.value == 2)
		// The reallocation to the larger nodeCount must preserve every
		// existing node at its own index (array index == node index).
		#expect(tree.leaf(at: .init(value: 0)) == leaf(1))
		#expect(tree.leaf(at: .init(value: 1)) == leaf(2))
	}

	@Test("truncate shrinks leafCount once a Remove empties the rightmost subtree (§7.7)")
	func truncateShrinksAfterRightRemove() throws {
		// A full 4-leaf tree (leaves at node indices 0, 2, 4, 6).
		var tree = try MLS.TreeKEM.RatchetTree(nodes: [
			.leaf(leaf(1)), nil, .leaf(leaf(2)), nil,
			.leaf(leaf(3)), nil, .leaf(leaf(4)),
		])
		#expect(tree.leafCount.value == 4)
		// Remove both right-half leaves — this empties the entire right
		// subtree and the root.
		try tree.blankLeafAndDirectPath(.init(value: 3))
		try tree.blankLeafAndDirectPath(.init(value: 2))
		tree.truncate()
		// §7.7: the tree drops to the smallest power of two that still holds
		// its non-blank leaves — here, two.
		#expect(tree.leafCount.value == 2)
		#expect(tree.leaf(at: .init(value: 0)) == leaf(1))
		#expect(tree.leaf(at: .init(value: 1)) == leaf(2))
		// A leaf in the right half must not truncate: keep leaf 2, remove
		// only leaf 3 — leaf 1 (right of the 2-leaf split) holds it open.
		var kept = try MLS.TreeKEM.RatchetTree(nodes: [
			.leaf(leaf(1)), nil, .leaf(leaf(2)), nil,
			.leaf(leaf(3)), nil, .leaf(leaf(4)),
		])
		try kept.blankLeafAndDirectPath(.init(value: 3))
		kept.truncate()
		// Leaf index 2 (node 4) still occupies the right half, holding the
		// tree open at four leaves.
		#expect(kept.leafCount.value == 4)
	}

	@Test("a wire slot trimmed away on decode is still settable in the padded tree")
	func trimmedFillStillWorks() throws {
		// Wire array of length 2 -> leafCount 2, padded to full width
		// (nodeCount 3). Node 2 exists even though the trimmed wire array
		// didn't carry it, so setLeaf(1) lands within the tree.
		var tree = try MLS.TreeKEM.RatchetTree(nodes: [.leaf(leaf(1)), nil])
		#expect(tree.leafCount.value == 2)
		#expect(tree.serializedNodeCount == 1)  // only node 0 is non-blank
		try tree.setLeaf(MLS.LeafIndex(value: 1), to: leaf(2))
		#expect(tree.leafCount.value == 2)
		#expect(tree.serializedNodeCount == 3)  // node 2 now non-blank
	}
}
