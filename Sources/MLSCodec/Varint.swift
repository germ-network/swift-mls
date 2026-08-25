extension MLS {
	/// The variable-size length header of RFC 9420 §2.1.2 — the QUIC varint of
	/// RFC 9000 §16 restricted to its first three forms.
	public enum Varint {
		/// The largest encodable length: the 4-byte form carries 30 value bits.
		public static let maxValue: UInt32 = (1 << 30) - 1

		/// Bytes the minimum-length encoding of `value` occupies.
		public static func encodedLength(of value: UInt32) throws -> Int {
			switch value {
			case ..<0x40: 1
			case ..<0x4000: 2
			case ...maxValue: 4
			default: throw CodecError.lengthTooLarge(UInt64(value))
			}
		}
	}
}
