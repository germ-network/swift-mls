extension MLS {
	public enum CodecError: Error, Equatable, Sendable {
		/// Fewer bytes remained than the read required.
		case truncated(needed: Int, available: Int)
		/// A length header exceeded the 2^30 - 1 ceiling of RFC 9420 §2.1.2.
		case lengthTooLarge(UInt64)
		/// A length header used more bytes than the value requires. RFC 9420
		/// §2.1.2 requires minimum-length encoding and requires decoders to reject.
		case nonMinimalLength(value: UInt32, encodedBytes: Int)
		/// The two-bit prefix `11` — the 8-byte QUIC form, which MLS excludes.
		case reservedVarintPrefix
		/// A vector element decoded without consuming any bytes. Real
		/// short-count mismatches surface as `truncated` instead — this
		/// guards specifically against a decoder that could loop forever
		/// on malformed input.
		case vectorNotFullyConsumed(remaining: Int)
		/// Bytes remained after a top-level decode.
		case trailingBytes(Int)
		/// An `optional<T>` presence byte was neither 0 nor 1.
		case invalidOptionalPresence(UInt8)
		/// An ``MLSClosedEnum`` decoded a raw value with no case. Only
		/// reachable for values whose field genuinely cannot tolerate an
		/// unknown one; see ``MLSClosedEnum`` for when that holds and
		/// when the raw value must be carried through instead.
		case unknownEnumValue(UInt64)
	}
}
