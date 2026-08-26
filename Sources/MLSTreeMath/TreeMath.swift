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
		public static func nodeCount(leafCount: UInt32) -> UInt32 {
			leafCount == 0 ? 0 : 2 * leafCount - 1
		}

		/// The middle index of the `2n - 1`-slot array, *not* its last
		/// index — `n - 1`, not `nodeCount - 1`. For a power-of-two leaf
		/// count the two coincide only at `n = 1`; every other size makes
		/// the difference concrete (16 leaves → 31 slots, root at index 15,
		/// not 30 — node 30 is a leaf, the tree's rightmost).
		///
		/// Only equals the RFC's general root index when `n` is a power of
		/// two — true of every tree this protocol constructs (RFC 9420
		/// §4.1: "Every tree used in this protocol is a perfect binary
		/// tree"); `directPath` is what guards against an invalid count.
		public static func root(leafCount: UInt32) -> UInt32 {
			leafCount == 0 ? 0 : leafCount - 1
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
		public static func parent(_ node: UInt32, leafCount: UInt32) -> UInt32? {
			parentAndSibling(node, leafCount: leafCount)?.parent
		}

		public static func sibling(_ node: UInt32, leafCount: UInt32) -> UInt32? {
			parentAndSibling(node, leafCount: leafCount)?.sibling
		}

		static func parentAndSibling(_ node: UInt32, leafCount: UInt32) -> (
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
		/// `leafCount` must be 0 or a power of two (RFC 9420 §4.1) — an
		/// invalid count sends the loop below climbing without ever
		/// reaching that count's root: a hang, not a wrong answer.
		public static func directPath(from node: UInt32, leafCount: UInt32) throws -> [(
			path: UInt32, sibling: UInt32
		)] {
			guard leafCount == 0 || leafCount.nonzeroBitCount == 1 else {
				throw MLS.TreeMathError.invalidLeafCount(leafCount)
			}
			guard isInTree(node, root: root(leafCount: leafCount)) else { return [] }
			var result: [(UInt32, UInt32)] = []
			var current = node
			while let ps = parentAndSibling(current, leafCount: leafCount) {
				result.append((ps.parent, ps.sibling))
				current = ps.parent
			}
			return result
		}
	}

	public enum TreeMathError: Error, Sendable, Equatable {
		/// A tree's leaf count must be 0 or a power of two — see
		/// `TreeMath.directPath`.
		case invalidLeafCount(UInt32)
	}
}

extension FixedWidthInteger {
	fileprivate var trailingOneBitCount: Int { (self ^ (self &+ 1)).nonzeroBitCount - 1 }
}
