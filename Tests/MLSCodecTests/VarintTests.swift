import Testing
@testable import MLSCodec

private func encodedVarint(_ value: UInt32) throws -> [UInt8] {
    var writer = MLS.Writer()
    try writer.writeVarint(value)
    return writer.bytes
}

private func decodedVarint(_ bytes: [UInt8]) throws -> UInt32 {
    var reader = MLS.Reader(bytes)
    let value = try reader.readVarint()
    try reader.finish()
    return value
}

@Suite("Varint length headers (RFC 9420 §2.1.2)")
struct VarintTests {
    @Test("widths change at the documented boundaries", arguments: [
        (UInt32(0), 1), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (MLS.Varint.maxValue, 4),
    ])
    func width(value: UInt32, expected: Int) throws {
        #expect(try MLS.Varint.encodedLength(of: value) == expected)
        #expect(try encodedVarint(value).count == expected)
    }

    @Test("round-trips across every width", arguments: [
        UInt32(0), 1, 63, 64, 255, 256, 16_383, 16_384, 65_535, 1 << 20, MLS.Varint.maxValue,
    ])
    func roundTrip(value: UInt32) throws {
        #expect(try decodedVarint(encodedVarint(value)) == value)
    }

    @Test("known encodings match the spec's examples")
    func knownEncodings() throws {
        #expect(try encodedVarint(0) == [0x00])
        #expect(try encodedVarint(63) == [0x3F])
        #expect(try encodedVarint(64) == [0x40, 0x40])
        #expect(try encodedVarint(16_383) == [0x7F, 0xFF])
        #expect(try encodedVarint(16_384) == [0x80, 0x00, 0x40, 0x00])
        #expect(try encodedVarint(MLS.Varint.maxValue) == [0xBF, 0xFF, 0xFF, 0xFF])
    }

    @Test("rejects values above the 30-bit ceiling")
    func ceiling() {
        #expect(throws: MLS.CodecError.lengthTooLarge(UInt64(1 << 30))) {
            try encodedVarint(1 << 30)
        }
    }

    @Test("rejects the reserved 8-byte prefix that MLS excludes")
    func reservedPrefix() {
        #expect(throws: MLS.CodecError.reservedVarintPrefix) {
            try decodedVarint([0xC0, 0, 0, 0, 0, 0, 0, 0])
        }
    }

    // A value with two valid encodings would let a peer re-encode a structure
    // into different bytes, breaking every signature and hash over it.
    @Test("rejects non-minimal encodings", arguments: [
        (bytes: [UInt8]([0x40, 0x00]), value: UInt32(0)),
        (bytes: [UInt8]([0x40, 0x3F]), value: UInt32(63)),
        (bytes: [UInt8]([0x80, 0x00, 0x00, 0x00]), value: UInt32(0)),
        (bytes: [UInt8]([0x80, 0x00, 0x3F, 0xFF]), value: UInt32(16_383)),
    ])
    func nonMinimal(bytes: [UInt8], value: UInt32) {
        #expect(throws: MLS.CodecError.nonMinimalLength(value: value, encodedBytes: bytes.count)) {
            try decodedVarint(bytes)
        }
    }

    @Test("rejects a truncated multi-byte header")
    func truncated() {
        #expect(throws: MLS.CodecError.truncated(needed: 3, available: 1)) {
            try decodedVarint([0x80, 0x00])
        }
    }

    @Test("rejects the reserved prefix even as a single byte with no continuation")
    func reservedPrefixAlone() {
        #expect(throws: MLS.CodecError.reservedVarintPrefix) {
            try decodedVarint([0xC0])
        }
    }

    @Test("rejects UInt32.max, not only the value one past the ceiling")
    func ceilingFarAboveMax() {
        #expect(throws: MLS.CodecError.lengthTooLarge(UInt64(UInt32.max))) {
            try encodedVarint(UInt32.max)
        }
    }
}
