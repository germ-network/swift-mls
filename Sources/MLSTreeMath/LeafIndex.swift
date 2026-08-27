import MLSCodec

/// A leaf's position in the ratchet tree — one index space shared by the
/// ratchet tree, the secret tree, `Sender.member`, `RemoveProposal`, and
/// `GroupInfo.signer`. Lives here rather than in a wire-format target
/// because it is pure tree-position arithmetic, exactly like the rest of
/// `MLSTreeMath`: both `MLSFraming` and the ratchet tree (phase 4) need it,
/// and it has no dependency on either.
extension MLS {
	public struct LeafIndex: Hashable, Sendable, Comparable {
		public var value: UInt32

		/// RFC 9420 states no leaf-count cap; the wire-level bound is
		/// indirect and by bytes, not nodes — `ratchet_tree<V>`'s vector
		/// header caps the whole tree encoding at 2^30 bytes (§2.1.2).
		/// `2^24` is this implementation's own conservative decode-time
		/// bound. Decode-time check — construction from a trusted local
		/// count (e.g. `LeafIndex(value: currentLeafCount)`) is unchecked.
		///
		/// The peers pick bounds too, and they disagree *with each other*,
		/// which is the useful data point: mls-rs lands on exactly this
		/// value (`MAX_LEAF_INDEX = (1 << 24) - 1`, `tree_kem/node.rs:21`,
		/// enforced in its `LeafIndex` decode at `:47` — the same bound at
		/// the same placement), while OpenMLS derives a much larger one
		/// from the byte cap above (`MAX_TREE_SIZE = (1 << 30) - 1` →
		/// `MAX_LEAF = (MAX_TREE_SIZE - 1) / 2`, roughly 2^29,
		/// `binary_tree/array_representation/treemath.rs:6-14`). So this is
		/// a spec-permitted implementation choice with no consensus value,
		/// not a number invented here alone.
		public static let ceiling: UInt32 = 1 << 24

		public init(value: UInt32) { self.value = value }

		public static func < (lhs: Self, rhs: Self) -> Bool { lhs.value < rhs.value }
	}
}

extension MLS {
	public enum TreeMathError: Error, Sendable, Equatable {
		case leafIndexTooLarge(UInt32)
		/// A tree's leaf count must be a power of two, and below
		/// `LeafIndex.ceiling` — see `MLS.LeafCount`, which is where that
		/// is now enforced. (`TreeMath.directPath` used to throw this and
		/// no longer can: it takes a `LeafCount`, so it has no invalid
		/// input left to reject.)
		case invalidLeafCount(UInt32)
	}
}

extension MLS.LeafIndex: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt32(value) }

	public init(from reader: inout MLS.Reader) throws {
		let value = try reader.readUInt32()
		guard value < Self.ceiling else { throw MLS.TreeMathError.leafIndexTooLarge(value) }
		self.value = value
	}
}
