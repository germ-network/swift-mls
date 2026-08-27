import MLSCodec

/// RFC 9420 Appendix C's array-based encoding of a complete binary tree
/// (§4.1 points here; §4.1 itself states MLS places no requirements on a
/// tree's internal representation): `n` leaves live at even indices
/// `0, 2, 4, ...`, internal nodes at odd indices, packed into `2n - 1`
/// array slots so no pointers or explicit parent/child links are needed —
/// a node's position alone determines its neighbors.
///
/// This is pure index arithmetic with no relationship to *what* a tree
/// holds. RFC 9420 uses it twice — the secret tree (`MLSKeySchedule`) and
/// the ratchet tree (`MLSTreeKEM`, phase 4) — and it is the same arithmetic
/// both times, so it lives here rather than being owned by, or duplicated
/// between, either.
extension MLS {
	public enum TreeMath: Sendable {
		/// `2n - 1` — the array size for a tree of `leafCount` leaves.
		/// `0` leaves is `0` nodes: there is no node zero-of-nothing.
		public static func nodeCount(leafCount: MLS.LeafCount) -> UInt32 {
			leafCount.value == 0 ? 0 : 2 * leafCount.value - 1
		}

		/// The middle index of the `2n - 1`-slot array, *not* its last
		/// index — `n - 1`, not `nodeCount - 1`. For a power-of-two leaf
		/// count the two coincide only at `n = 1`; every other size makes
		/// the difference concrete (16 leaves → 31 slots, root at index 15,
		/// not 30 — node 30 is a leaf, the tree's rightmost).
		///
		/// Only equals the RFC's general root index when `n` is a power of
		/// two — which `MLS.LeafCount` now guarantees by construction
		/// (RFC 9420 §4.1: "Every tree used in this protocol is a perfect
		/// binary tree"). This function previously carried a `precondition`
		/// trap, and `directPath` a separate `guard`, for the same
		/// invariant; the type replaces both.
		public static func root(leafCount: MLS.LeafCount) -> UInt32 {
			leafCount.value == 0 ? 0 : leafCount.value - 1
		}

		public static func isLeaf(_ node: UInt32) -> Bool { node & 1 == 0 }

		public static func isInTree(_ node: UInt32, root: UInt32) -> Bool {
			node <= 2 * root
		}

		/// A node's level is how many trailing 1-bits its index has — 0
		/// for every leaf (an even number has none), 1 for the lowest rung
		/// of internal nodes, and so on up to the root.
		static func level(_ node: UInt32) -> UInt32 { UInt32(node.trailingOneBitCount) }

		/// Undefined on a leaf — callers must check `isLeaf` first, exactly
		/// as RFC 9420's own `left`/`right` are undefined there.
		public static func left(_ node: UInt32) -> UInt32 {
			node ^ (0x01 << (level(node) - 1))
		}

		public static func right(_ node: UInt32) -> UInt32 {
			node ^ (0x03 << (level(node) - 1))
		}

		/// `nil` at the root, which has no parent.
		public static func parent(_ node: UInt32, leafCount: MLS.LeafCount) -> UInt32? {
			parentAndSibling(node, leafCount: leafCount)?.parent
		}

		public static func sibling(_ node: UInt32, leafCount: MLS.LeafCount) -> UInt32? {
			parentAndSibling(node, leafCount: leafCount)?.sibling
		}

		static func parentAndSibling(_ node: UInt32, leafCount: MLS.LeafCount) -> (
			parent: UInt32, sibling: UInt32
		)? {
			let root = root(leafCount: leafCount)
			guard node != root else { return nil }

			let lvl = level(node)
			let p = (node & ~(1 << (lvl + 1))) | (1 << lvl)
			let s = node < p ? right(p) : left(p)
			return (p, s)
		}

		/// The path from `node` up to the root, as `(path, sibling)` pairs
		/// ordered leaf-to-root — `path[0]` is `node`'s immediate parent,
		/// the last entry is the root itself (`parentAndSibling` returns
		/// `nil` only once `current == root`, and that final value is
		/// appended before the loop exits). Reverse it to walk root-down,
		/// which is what deriving a secret-tree leaf's secret from the
		/// shared root secret needs (`MLSKeySchedule`).
		///
		/// No longer throws: `MLS.LeafCount` cannot hold a value that would
		/// make the loop below non-terminating, so there is nothing left to
		/// reject. The hang this used to guard — an invalid count sends the
		/// climb past a root index that is on no node's ancestor chain — is
		/// now unrepresentable rather than checked.
		public static func directPath(from node: UInt32, leafCount: MLS.LeafCount) -> [(
			path: UInt32, sibling: UInt32
		)] {
			guard isInTree(node, root: root(leafCount: leafCount)) else { return [] }
			var result: [(UInt32, UInt32)] = []
			var current = node
			while let ps = parentAndSibling(current, leafCount: leafCount) {
				result.append((ps.parent, ps.sibling))
				current = ps.parent
			}
			return result
		}

		/// Superseded by `MLS.LeafCount.init(nodeArrayCount:)`, which
		/// returns the validated type rather than a raw `UInt32` a caller
		/// could then pass anywhere. Kept as a thin forwarder because it is
		/// the name the tree-decode path already reads well with.
		public static func paddedLeafCount(nodeArrayCount: Int) throws -> MLS.LeafCount {
			try MLS.LeafCount(nodeArrayCount: nodeArrayCount)
		}
	}
}

extension FixedWidthInteger {
	fileprivate var trailingOneBitCount: Int { (self ^ (self &+ 1)).nonzeroBitCount - 1 }
}
