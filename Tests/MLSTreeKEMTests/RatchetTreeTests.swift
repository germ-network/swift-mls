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
		#expect(tree.leafCount == 1)
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
		tree.setParent(1, to: syntheticParent(9))
		#expect(tree.parent(at: 1) == syntheticParent(9))
		tree.setParent(1, to: nil)
		#expect(tree.parent(at: 1) == nil)
	}

	@Test("trim removes only the trailing run of blanks, never an interior one")
	func trimOnlyTrailing() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(1)), nil, nil, nil, .leaf(syntheticLeaf(2)),
				nil, nil,
			])
		tree.trim()
		// Interior blanks (indices 1-3) must survive; only the trailing
		// pair (indices 5-6) is removed.
		#expect(tree.leaf(at: .init(value: 0)) == syntheticLeaf(1))
		#expect(tree.leaf(at: .init(value: 2)) == syntheticLeaf(2))
		#expect(tree.isBlank(at: 1))
		#expect(tree.isBlank(at: 3))
		// Leaf index 2 (node 4) is present, so this is still a 4-leaf-
		// capacity tree — trim only drops the physically-redundant
		// trailing blank (leaf index 3), it doesn't shrink leafCount.
		#expect(tree.leafCount == 4)
	}

	@Test("insertLeaf fills the leftmost blank leaf before ever growing the tree")
	func insertFillsBlankFirst() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [.leaf(syntheticLeaf(1)), .parent(syntheticParent(9)), nil])
		let index = tree.insertLeaf(syntheticLeaf(3))
		#expect(index == MLS.LeafIndex(value: 1))
		#expect(tree.leaf(at: .init(value: 1)) == syntheticLeaf(3))
		#expect(tree.leafCount == 2)
	}

	@Test("insertLeaf grows the tree (doubling the padded leaf count) once every leaf is full")
	func insertGrowsWhenFull() throws {
		var tree = try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(1)), .parent(syntheticParent(9)),
				.leaf(syntheticLeaf(2)),
			])
		#expect(tree.leafCount == 2)
		let index = tree.insertLeaf(syntheticLeaf(3))
		#expect(index == MLS.LeafIndex(value: 2))
		#expect(tree.leafCount == 4)
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
