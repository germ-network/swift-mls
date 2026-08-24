import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSTreeMath

@Suite("tree-math.json (mlswg/mls-implementations)")
struct TreeMathTests {
	static let records = try! VectorFile.load("tree-math", as: [TreeMathVector].self)

	@Test("n_nodes, root, and every node's left/right/parent/sibling", arguments: records)
	func matchesVector(_ record: TreeMathVector) {
		#expect(MLS.TreeMath.nodeCount(leafCount: record.nLeaves) == record.nNodes)
		#expect(MLS.TreeMath.root(leafCount: record.nLeaves) == record.root)

		for node in 0..<record.nNodes {
			let isLeaf = MLS.TreeMath.isLeaf(node)
			#expect(isLeaf == (record.left[Int(node)] == nil))

			if !isLeaf {
				#expect(MLS.TreeMath.left(node) == record.left[Int(node)])
				#expect(MLS.TreeMath.right(node) == record.right[Int(node)])
			}
			#expect(
				MLS.TreeMath.parent(node, leafCount: record.nLeaves)
					== record.parent[Int(node)])
			#expect(
				MLS.TreeMath.sibling(node, leafCount: record.nLeaves)
					== record.sibling[Int(node)])
		}
	}

	@Test(
		"directPath, reversed, walks root to a leaf via the same nodes tree-math.json's parent chain gives"
	)
	func directPathMatchesParentChain() throws {
		for record in Self.records where record.nLeaves > 1 {
			for leaf in stride(from: UInt32(0), to: 2 * record.nLeaves, by: 2) {
				let path = try MLS.TreeMath.directPath(
					from: leaf, leafCount: record.nLeaves)
				// Walking the vector's own `parent` array from `leaf` up must
				// produce exactly the `.path` sequence `directPath` returns.
				var expected: [UInt32] = []
				var current = leaf
				while let p = record.parent[Int(current)] {
					expected.append(p)
					current = p
				}
				#expect(path.map(\.path) == expected)
			}
		}
	}

	/// An unguarded non-power-of-two `leafCount` sends `directPath`'s
	/// parent-chain loop climbing without ever reaching that count's root.
	@Test(
		"directPath rejects a non-power-of-two leafCount instead of hanging",
		arguments: [
			3, 5, 6, 7, 9,
		])
	func directPathRejectsInvalidLeafCount(_ leafCount: UInt32) {
		#expect(throws: MLS.TreeMathError.invalidLeafCount(leafCount)) {
			_ = try MLS.TreeMath.directPath(from: 0, leafCount: leafCount)
		}
	}

	@Test(
		"paddedLeafCount recovers n from a valid 2n-1 node array length, for every tree-math.json size"
	)
	func paddedLeafCountMatchesVector() throws {
		for record in Self.records {
			#expect(
				try MLS.TreeMath.paddedLeafCount(nodeArrayCount: Int(record.nNodes))
					== record.nLeaves)
		}
	}

	/// Trimming means a trailing-blanks-removed array is shorter than the
	/// full `2n - 1` and still valid — there is no "malformed length" to
	/// reject at this layer, only an oversized result.
	@Test(
		"paddedLeafCount recovers n from an array shorter than 2n-1, as if trailing blanks were trimmed",
		arguments: [(0, 1), (1, 1), (2, 2), (3, 2), (4, 4), (5, 4), (6, 4), (9, 8)]
	)
	func paddedLeafCountHandlesTrimmedArrays(_ pair: (nodeArrayCount: Int, expected: UInt32))
		throws
	{
		#expect(
			try MLS.TreeMath.paddedLeafCount(nodeArrayCount: pair.nodeArrayCount)
				== pair.expected)
	}

	/// `nodeArrayCount` is a plain `Int`, not an actual array — the ceiling
	/// check is O(1) arithmetic, so this is cheap to exercise directly
	/// rather than skip as "would need an implausible array."
	@Test("paddedLeafCount rejects a result at or beyond LeafIndex.ceiling")
	func paddedLeafCountRejectsCeilingOverflow() {
		#expect(throws: MLS.TreeMathError.invalidLeafCount(MLS.LeafIndex.ceiling)) {
			_ = try MLS.TreeMath.paddedLeafCount(
				nodeArrayCount: Int(MLS.LeafIndex.ceiling) * 2 - 1)
		}
	}
}
