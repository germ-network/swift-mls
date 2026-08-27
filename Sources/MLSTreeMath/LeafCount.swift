import MLSCodec

extension MLS {
	/// A tree size that is valid by construction: zero, or a power of two.
	///
	/// RFC 9420 §4.1: *"Every tree used in this protocol is a perfect binary
	/// tree"* — but nothing made that structurally true here, so the
	/// invariant was patched reactively in two places that had converged on
	/// it by luck rather than by design (a `precondition` trap in `root`,
	/// added when the only caller passed trusted counts; a `guard` throwing
	/// from `directPath`, added when phase 4 made the count
	/// attacker-controlled). Both were right for the caller in front of
	/// them, and neither could protect the other entry points.
	///
	/// The failure they were guarding is worth naming precisely, because it
	/// is not a wrong answer: `parentAndSibling` climbs until it reaches the
	/// index `root(leafCount:)` computes, and for a non-power-of-two count
	/// that index is never on any node's ancestor chain. `directPath` then
	/// loops forever. A hang, on attacker-supplied input.
	///
	/// Validating once at the boundary makes the whole input class
	/// unrepresentable, which is what OpenMLS's `TreeSize` does (it rounds
	/// any node count up to the nearest perfect size at construction) and
	/// what this codebase's own `LeafIndex` already does for indices.
	public struct LeafCount: Hashable, Sendable, Comparable {
		public let value: UInt32

		/// Rejects anything that isn't zero or a power of two.
		public init(validating value: UInt32) throws {
			guard value == 0 || value.nonzeroBitCount == 1 else {
				throw MLS.TreeMathError.invalidLeafCount(value)
			}
			guard value < MLS.LeafIndex.ceiling else {
				throw MLS.TreeMathError.invalidLeafCount(value)
			}
			self.value = value
		}

		/// The padded leaf count implied by a wire node array's length —
		/// `(nodeArrayCount / 2 + 1)` rounded up to the next power of two.
		///
		/// The wire array is *not* always exactly `2n - 1` long: RFC 9420
		/// trims trailing blank slots before serializing (load-bearing for
		/// `tree-operations.json`'s byte-exact `tree_after` check), so a
		/// shorter array — anywhere from empty up to `2n - 1` — is valid and
		/// still resolves to the same padded leaf count `n`. This matches
		/// mls-rs's `NodeVec::total_leaf_count`
		/// (`(len / 2 + 1).next_power_of_two()`) exactly; there is no
		/// "malformed length" to reject here, only an oversized result.
		///
		/// Rounding up is what makes this total: every array length maps to
		/// a valid `LeafCount`, so this initializer cannot produce the
		/// invalid state `init(validating:)` exists to reject.
		public init(nodeArrayCount: Int) throws {
			guard nodeArrayCount >= 0, let count = UInt32(exactly: nodeArrayCount)
			else {
				throw MLS.TreeMathError.invalidLeafCount(
					UInt32(clamping: nodeArrayCount))
			}
			try self.init(validating: Self.nextPowerOfTwo(count / 2 + 1))
		}

		/// The empty tree. The one valid non-power-of-two value, and the
		/// reason `init(validating:)` special-cases zero rather than
		/// rejecting it.
		public static let zero = LeafCount(unchecked: 0)

		/// Skips validation. Only for values this type's own arithmetic
		/// produced — never for a decoded or caller-supplied count.
		init(unchecked value: UInt32) { self.value = value }

		public static func < (lhs: Self, rhs: Self) -> Bool { lhs.value < rhs.value }

		static func nextPowerOfTwo(_ x: UInt32) -> UInt32 {
			x <= 1 ? 1 : UInt32(1) << (UInt32.bitWidth - (x - 1).leadingZeroBitCount)
		}
	}
}
