import Foundation

extension MLS {
    /// Accumulates an RFC 9420 presentation-language encoding.
    public struct Writer: Sendable {
        public private(set) var bytes: [UInt8] = []

        public init(reservingCapacity capacity: Int = 0) {
            bytes.reserveCapacity(capacity)
        }

        public var data: Data { Data(bytes) }
        public var count: Int { bytes.count }

        public mutating func writeBytes(_ raw: some Sequence<UInt8>) {
            bytes.append(contentsOf: raw)
        }

        public mutating func writeUInt8(_ value: UInt8) {
            bytes.append(value)
        }

        public mutating func writeUInt16(_ value: UInt16) {
            bytes.append(UInt8(truncatingIfNeeded: value >> 8))
            bytes.append(UInt8(truncatingIfNeeded: value))
        }

        public mutating func writeUInt32(_ value: UInt32) {
            for shift in stride(from: 24, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> UInt32(shift)))
            }
        }

        public mutating func writeUInt64(_ value: UInt64) {
            for shift in stride(from: 56, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            }
        }

        public mutating func writeVarint(_ value: UInt32) throws {
            switch try Varint.encodedLength(of: value) {
            case 1:
                bytes.append(UInt8(truncatingIfNeeded: value))
            case 2:
                bytes.append(UInt8(truncatingIfNeeded: value >> 8) | 0x40)
                bytes.append(UInt8(truncatingIfNeeded: value))
            default:
                bytes.append(UInt8(truncatingIfNeeded: value >> 24) | 0x80)
                bytes.append(UInt8(truncatingIfNeeded: value >> 16))
                bytes.append(UInt8(truncatingIfNeeded: value >> 8))
                bytes.append(UInt8(truncatingIfNeeded: value))
            }
        }

        /// `opaque x<V>` — a varint byte count followed by the bytes.
        public mutating func writeOpaque(_ raw: some Collection<UInt8>) throws {
            guard let length = UInt32(exactly: raw.count) else {
                throw CodecError.lengthTooLarge(UInt64(raw.count))
            }
            try writeVarint(length)
            bytes.append(contentsOf: raw)
        }

        public mutating func encode(_ value: some MLSEncodable) throws {
            try value.encode(to: &self)
        }

        /// `T x<V>` — the length header counts *bytes*, not elements, so the
        /// contents are encoded first to learn their size.
        public mutating func encodeVector(_ values: [some MLSEncodable]) throws {
            var contents = Writer()
            for value in values { try value.encode(to: &contents) }
            try writeOpaque(contents.bytes)
        }

        /// `optional<T>` — a presence byte, then the value if present.
        public mutating func encodeOptional(_ value: (some MLSEncodable)?) throws {
            guard let value else { return writeUInt8(0) }
            writeUInt8(1)
            try value.encode(to: &self)
        }
    }
}
