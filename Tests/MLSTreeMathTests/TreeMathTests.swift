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

	/// The ceiling half of `init(validating:)`, which the power-of-two cases
	/// above never reach. Directly pinned because this is exactly the
	/// boundary where an unbounded tree detonates: `RatchetTree.leafCount`
	/// computes its value with `try!`, so a count that reaches 2^24 aborts
	/// the process rather than throwing (see `RatchetTree.leafCount`'s
	/// own comment).
	@Test("LeafCount accepts the largest legal tree and rejects the next power of two")
	func leafCountCeilingBoundary() throws {
		let largest = MLS.LeafIndex.ceiling / 2
		#expect(try MLS.LeafCount(validating: largest).value == largest)
		#expect(throws: MLS.TreeMathError.invalidLeafCount(MLS.LeafIndex.ceiling)) {
			_ = try MLS.LeafCount(validating: MLS.LeafIndex.ceiling)
		}
	}

	/// Swift's `<<` is a smart shift: over-shifting yields 0 rather than
	/// trapping. `init(validating:)` rejects 0 like any other
	/// non-power-of-two value, so an unsaturated overflow would still
	/// throw — but as `invalidLeafCount(0)`, blaming a value the caller
	/// never passed instead of the huge one it did. Saturating to `.max`
	/// keeps the rejection honest: `.max` also exceeds
	/// `LeafIndex.ceiling`, so it throws for the caller's actual input.
	/// Pinned directly because no caller can currently reach it:
	/// `init(nodeArrayCount:)`'s largest possible argument is exactly 2³¹.
	@Test(
		"nextPowerOfTwo saturates instead of wrapping to zero",
		arguments: [
			(UInt32(0x8000_0001), UInt32.max), (UInt32.max, UInt32.max),
			// The exact boundary, and the largest value any caller can
			// actually produce: still exact, not saturated.
			(UInt32(1) << 31, UInt32(1) << 31),
			(UInt32.max / 2 + 1, UInt32(1) << 31),
		])
	func nextPowerOfTwoSaturates(_ pair: (input: UInt32, expected: UInt32)) {
		#expect(MLS.LeafCount.nextPowerOfTwo(pair.input) == pair.expected)
	}

	/// The consequence that actually matters: whatever `nextPowerOfTwo`
	/// returns at the top of its range, a huge node-array length throws
	/// rather than silently resolving to some other `LeafCount`.
	@Test("an overflowing node-array length throws, not silently resolves")
	func hugeNodeArrayNeverBecomesEmpty() {
		for count in [Int(UInt32.max), Int(UInt32.max) - 1, 1 << 31] {
			#expect(throws: MLS.TreeMathError.self) {
				_ = try MLS.LeafCount(nodeArrayCount: count)
			}
		}
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
