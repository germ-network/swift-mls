import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSTreeMath

@Suite("tree-math.json (mlswg/mls-implementations)")
struct TreeMathTests {
	static let records = try! VectorFile.load("tree-math", as: [TreeMathVector].self)

	@Test("n_nodes, root, and every node's left/right/parent/sibling", arguments: records)
	func matchesVector(_ record: TreeMathVector) throws {
		let nLeaves = try MLS.LeafCount(validating: record.nLeaves)
		#expect(MLS.TreeMath.nodeCount(leafCount: nLeaves) == record.nNodes)
		#expect(MLS.TreeMath.root(leafCount: nLeaves) == record.root)

		for node in 0..<record.nNodes {
			let isLeaf = MLS.TreeMath.isLeaf(node)
			#expect(isLeaf == (record.left[Int(node)] == nil))

			if !isLeaf {
				#expect(MLS.TreeMath.left(node) == record.left[Int(node)])
				#expect(MLS.TreeMath.right(node) == record.right[Int(node)])
			}
			#expect(
				MLS.TreeMath.parent(node, leafCount: nLeaves)
					== record.parent[Int(node)])
			#expect(
				MLS.TreeMath.sibling(node, leafCount: nLeaves)
					== record.sibling[Int(node)])
		}
	}

	@Test(
		"directPath, reversed, walks root to a leaf via the same nodes tree-math.json's parent chain gives"
	)
	func directPathMatchesParentChain() throws {
		for record in Self.records where record.nLeaves > 1 {
			let nLeaves = try MLS.LeafCount(validating: record.nLeaves)
			for leaf in stride(from: UInt32(0), to: 2 * record.nLeaves, by: 2) {
				let path = MLS.TreeMath.directPath(from: leaf, leafCount: nLeaves)
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

	/// A non-power-of-two leaf count would send `directPath`'s parent-chain
	/// loop climbing without ever reaching that count's root — a hang, not a
	/// wrong answer.
	///
	/// This used to test `directPath` directly, because the guard lived
	/// there (and, before that, as a `precondition` in `root`). It now tests
	/// the *type*: `directPath` cannot be handed an invalid count at all, so
	/// there is no longer a call to make. The `.timeLimit` stays — if
	/// someone ever reintroduces a raw-`UInt32` entry point, the failure
	/// mode goes back to wedging the run rather than failing it.
	@Test(
		"LeafCount rejects a non-power-of-two or zero, so directPath cannot hang",
		.timeLimit(.minutes(1)),
		arguments: [
			0, 3, 5, 6, 7, 9,
		])
	func leafCountRejectsNonPowerOfTwo(_ leafCount: UInt32) {
		#expect(throws: MLS.TreeMathError.invalidLeafCount(leafCount)) {
			_ = try MLS.LeafCount(validating: leafCount)
		}
	}

	/// Zero is rejected with the non-powers-of-two above: `LeafCount` stores
	/// a height, so the smallest tree it can name is a single leaf. There is
	/// no empty tree in MLS, and nothing in the codebase constructs one.
	@Test("LeafCount accepts every power of two", arguments: [1, 2, 4, 8, 1024])
	func leafCountAcceptsValidSizes(_ leafCount: UInt32) throws {
		#expect(try MLS.LeafCount(validating: leafCount).value == leafCount)
	}

	@Test(
		"paddedLeafCount recovers n from a valid 2n-1 node array length, for every tree-math.json size"
	)
	func paddedLeafCountMatchesVector() throws {
		for record in Self.records {
			#expect(
				try MLS.TreeMath.paddedLeafCount(nodeArrayCount: Int(record.nNodes))
					.value
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
			try MLS.TreeMath.paddedLeafCount(nodeArrayCount: pair.nodeArrayCount).value
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
