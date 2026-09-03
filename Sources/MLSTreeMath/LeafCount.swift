import MLSCodec

extension MLS {
	/// A perfect-binary-tree size, stored as its height: `value` leaves is
	/// `1 << height`.
	///
	/// RFC 9420 §4.1: *"Every tree used in this protocol is a perfect binary
	/// tree."* Storing the height is what makes that structural rather than
	/// checked — `value` is computed as `1 << height`, so a non-power-of-two
	/// leaf count has no representation at all, not merely a rejected one.
	/// That closes a hang, not a style point: for a non-power-of-two count,
	/// the index `root(leafCount:)` returns sits on no node's ancestor chain,
	/// so `directPath`'s climb never reaches it and loops forever on
	/// attacker-supplied input. OpenMLS gives the same guarantee a different
	/// way: its `TreeSize` rounds a node count up to a perfect size at
	/// construction.
	///
	/// There is no empty tree: `height` is a `UInt8`, so the smallest size is
	/// `1 << 0`, a single leaf. Nothing constructs a zero-leaf tree —
	/// `init(nodeArrayCount:)` floors at one leaf and `RatchetTree` never
	/// holds fewer — so the state the old `value == 0` special cases guarded
	/// was a phantom, and modelling it is what invited the reactive
	/// special-casing this type exists to remove.
	public struct LeafCount: Hashable, Sendable {
		/// The tree height. `value == 1 << height`, so every representable
		/// `LeafCount` is a power of two by construction.
		public let height: UInt8

		/// The number of leaves, `2^height`.
		public var value: UInt32 { UInt32(1) << height }

		/// Derives the height of a power-of-two leaf count, rejecting any
		/// input that is not one — zero included, since an MLS tree is never
		/// empty — or that reaches `LeafIndex.ceiling`. The ceiling check is
		/// not decoration: `RatchetTree.leafCount` computes its value with
		/// `try!`, made safe by `setNode`'s bounds guard and
		/// `insertLeaf`'s `treeFull` check.
		public init(validating value: UInt32) throws {
			guard value.nonzeroBitCount == 1, value < MLS.LeafIndex.ceiling else {
				throw MLS.TreeMathError.invalidLeafCount(value)
			}
			self.height = UInt8(value.trailingZeroBitCount)
		}

		/// The padded leaf count implied by a wire node array's length —
		/// `(nodeArrayCount / 2 + 1)` rounded up to the next power of two.
		///
		/// The wire array is *not* always exactly `2n - 1` long: RFC 9420
		/// trims trailing blank slots before serializing (load-bearing for
		/// `tree-operations.json`'s byte-exact `tree_after` check), so a
		/// shorter array — anywhere from empty up to `2n - 1` — is valid
		/// and still resolves to the same padded leaf count `n`. This matches
		/// mls-rs's `NodeVec::total_leaf_count`
		/// (`(len / 2 + 1).next_power_of_two()`) exactly; there is no
		/// "malformed length" to reject here, only an oversized result.
		///
		/// Rounding up is what makes this total: every array length maps to a
		/// valid `LeafCount` (an empty array to a single leaf), so this
		/// initializer cannot produce a value `init(validating:)` rejects
		/// except by overflowing the ceiling.
		public init(nodeArrayCount: Int) throws {
			guard nodeArrayCount >= 0, let count = UInt32(exactly: nodeArrayCount)
			else {
				throw MLS.TreeMathError.invalidLeafCount(
					UInt32(clamping: nodeArrayCount))
			}
			try self.init(validating: Self.nextPowerOfTwo(count / 2 + 1))
		}

		/// Rounds `x` up to the next power of two, saturating at
		/// `UInt32.max` rather than wrapping to zero.
		///
		/// The saturation is load-bearing, not defensive tidiness. Swift's
		/// `<<` is a *smart* shift: over-shifting yields 0, it does not
		/// trap, so the unguarded form returns **0** for every input above
		/// 2³¹. Under the height model that is not the hazard it once was:
		/// `init(validating:)` rejects 0 the same as any other
		/// non-power-of-two value, so an unguarded overflow would still
		/// throw — but it would throw `invalidLeafCount(0)`, blaming a
		/// value the caller never passed. Saturating to `.max` keeps the
		/// rejection on the caller's actual input instead: `.max` also
		/// exceeds `LeafIndex.ceiling`, so `init(validating:)` throws for
		/// that reason, consistently.
		///
		/// Unreachable from `init(nodeArrayCount:)` today, whose largest
		/// possible argument is exactly 2³¹ (`UInt32.max / 2 + 1`), which
		/// this returns unchanged and `init(validating:)` then rejects for
		/// exceeding `LeafIndex.ceiling`. Saturating keeps that true for a
		/// second caller that does not exist yet — the same
		/// two-checks-drift failure this whole type was written to end,
		/// one level down.
		static func nextPowerOfTwo(_ x: UInt32) -> UInt32 {
			guard x > 1 else { return 1 }
			guard x <= 1 << 31 else { return .max }
			return UInt32(1) << (UInt32.bitWidth - (x - 1).leadingZeroBitCount)
		}
	}
}
