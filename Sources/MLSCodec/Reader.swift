import Foundation

extension MLS {
    /// Consumes an RFC 9420 presentation-language encoding.
    public struct Reader: Sendable {
        private var remaining: ArraySlice<UInt8>

        public init(_ bytes: some Collection<UInt8>) {
            remaining = ArraySlice(Array(bytes))
        }

        private init(slice: ArraySlice<UInt8>) {
            remaining = slice
        }

        public var bytesRemaining: Int { remaining.count }
        public var isEmpty: Bool { remaining.isEmpty }

        /// Asserts the input is fully consumed. Call after a top-level decode.
        public func finish() throws {
            guard remaining.isEmpty else {
                throw CodecError.trailingBytes(remaining.count)
            }
        }

        public mutating func readBytes(_ count: Int) throws -> ArraySlice<UInt8> {
            guard remaining.count >= count else {
                throw CodecError.truncated(needed: count, available: remaining.count)
            }
            defer { remaining = remaining.dropFirst(count) }
            return remaining.prefix(count)
        }

        public mutating func readUInt8() throws -> UInt8 {
            guard let first = remaining.first else {
                throw CodecError.truncated(needed: 1, available: 0)
            }
            remaining = remaining.dropFirst()
            return first
        }

        public mutating func readUInt16() throws -> UInt16 {
            try readBytes(2).reduce(0) { $0 << 8 | UInt16($1) }
        }

        public mutating func readUInt32() throws -> UInt32 {
            try readBytes(4).reduce(0) { $0 << 8 | UInt32($1) }
        }

        public mutating func readUInt64() throws -> UInt64 {
            try readBytes(8).reduce(0) { $0 << 8 | UInt64($1) }
        }

        public mutating func readVarint() throws -> UInt32 {
            let first = try readUInt8()
            let width: Int
            switch first >> 6 {
            case 0: width = 1
            case 1: width = 2
            case 2: width = 4
            default: throw CodecError.reservedVarintPrefix
            }
            var value = UInt32(first & 0x3F)
            if width > 1 {
                for byte in try readBytes(width - 1) { value = value << 8 | UInt32(byte) }
            }
            // RFC 9420 §2.1.2 requires minimum-length encoding, and requires
            // decoders to reject anything longer. Without this a value has
            // several encodings, and anything hashing or signing the bytes
            // stops agreeing with a peer that re-encoded it.
            guard try Varint.encodedLength(of: value) == width else {
                throw CodecError.nonMinimalLength(value: value, encodedBytes: width)
            }
            return value
        }

        /// `opaque x<V>`
        public mutating func readOpaque() throws -> ArraySlice<UInt8> {
            let count = try readVarint()
            return try readBytes(Int(count))
        }

        public mutating func decode<T: MLSDecodable>(_ type: T.Type = T.self) throws -> T {
            try T(from: &self)
        }

        /// `T x<V>` — decodes until the length-delimited region is exhausted.
        public mutating func decodeVector<T: MLSDecodable>(_ type: T.Type = T.self) throws -> [T] {
            var contents = Reader(slice: try readOpaque())
            var values: [T] = []
            while !contents.isEmpty {
                let before = contents.bytesRemaining
                values.append(try T(from: &contents))
                // A element that consumes nothing would spin forever on
                // malformed input; treat it as a framing error instead.
                guard contents.bytesRemaining < before else {
                    throw CodecError.vectorNotFullyConsumed(remaining: contents.bytesRemaining)
                }
            }
            return values
        }

        /// `optional<T>`
        public mutating func decodeOptional<T: MLSDecodable>(_ type: T.Type = T.self) throws -> T? {
            switch try readUInt8() {
            case 0: return nil
            case 1: return try T(from: &self)
            case let other: throw CodecError.invalidOptionalPresence(other)
            }
        }
    }
}
