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
	func directPathMatchesParentChain() {
		for record in Self.records where record.nLeaves > 1 {
			for leaf in stride(from: UInt32(0), to: 2 * record.nLeaves, by: 2) {
				let path = MLS.TreeMath.directPath(
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
}
