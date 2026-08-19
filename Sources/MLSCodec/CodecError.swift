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
        /// A vector's contents did not divide evenly into elements.
        case vectorNotFullyConsumed(remaining: Int)
        /// Bytes remained after a top-level decode.
        case trailingBytes(Int)
        /// An `optional<T>` presence byte was neither 0 nor 1.
        case invalidOptionalPresence(UInt8)
    }
}
