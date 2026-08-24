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

		/// RFC 9420 caps a tree at 2^28 leaves; a leaf's node index (2x)
		/// must still fit the tree's varint-encoded node count, so
		/// implementations conventionally reject anything at or above
		/// 2^24. Decode-time check — construction from a trusted local
		/// count (e.g. `LeafIndex(value: currentLeafCount)`) is unchecked.
		public static let ceiling: UInt32 = 1 << 24

		public init(value: UInt32) { self.value = value }

		public static func < (lhs: Self, rhs: Self) -> Bool { lhs.value < rhs.value }
	}
}

extension MLS {
	public enum TreeMathError: Error, Sendable, Equatable {
		case leafIndexTooLarge(UInt32)
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
