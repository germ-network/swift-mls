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
		/// bound, not a value the RFC or peers agree on. Decode-time
		/// check — construction from a trusted local count (e.g.
		/// `LeafIndex(value: currentLeafCount)`) is unchecked.
		public static let ceiling: UInt32 = 1 << 24

		public init(value: UInt32) { self.value = value }

		public static func < (lhs: Self, rhs: Self) -> Bool { lhs.value < rhs.value }
	}
}

extension MLS {
	public enum TreeMathError: Error, Sendable, Equatable {
		case leafIndexTooLarge(UInt32)
		/// A tree's leaf count must be 0 or a power of two — see
		/// `TreeMath.directPath`.
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
