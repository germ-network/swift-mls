import Foundation
import Testing
@testable import MLSCodec

/// A struct exercising every presentation-language construct at once.
private struct Sample: MLSCodable, Equatable {
    var tag: UInt16
    var payload: [UInt8]
    var counts: [UInt32]
    var note: UInt64?

    func encode(to writer: inout MLS.Writer) throws {
        writer.writeUInt16(tag)
        try writer.writeOpaque(payload)
        try writer.encodeVector(counts)
        try writer.encodeOptional(note)
    }

    init(from reader: inout MLS.Reader) throws {
        tag = try reader.readUInt16()
        payload = Array(try reader.readOpaque())
        counts = try reader.decodeVector()
        note = try reader.decodeOptional()
    }

    init(tag: UInt16, payload: [UInt8], counts: [UInt32], note: UInt64?) {
        (self.tag, self.payload, self.counts, self.note) = (tag, payload, counts, note)
    }
}

@Suite("Presentation-language codec")
struct CodecTests {
    @Test("integers are big-endian")
    func integerEndianness() throws {
        var writer = MLS.Writer()
        writer.writeUInt8(0x01)
        writer.writeUInt16(0x0203)
        writer.writeUInt32(0x0405_0607)
        writer.writeUInt64(0x0809_0A0B_0C0D_0E0F)
        #expect(writer.bytes == Array(UInt8(1)...15))

        var reader = MLS.Reader(writer.bytes)
        #expect(try reader.readUInt8() == 0x01)
        #expect(try reader.readUInt16() == 0x0203)
        #expect(try reader.readUInt32() == 0x0405_0607)
        #expect(try reader.readUInt64() == 0x0809_0A0B_0C0D_0E0F)
        try reader.finish()
    }

    @Test("opaque vectors round-trip, including empty and multi-byte lengths", arguments: [0, 1, 63, 64, 300])
    func opaqueRoundTrip(count: Int) throws {
        let payload = (0..<count).map { UInt8($0 % 256) }
        var writer = MLS.Writer()
        try writer.writeOpaque(payload)
        #expect(writer.count == count + (try MLS.Varint.encodedLength(of: UInt32(count))))

        var reader = MLS.Reader(writer.bytes)
        #expect(Array(try reader.readOpaque()) == payload)
        try reader.finish()
    }

    // The length header counts bytes, not elements — a vector of 3 UInt32s is
    // a header of 12, not of 3. Getting this backwards decodes garbage.
    @Test("vector length headers count bytes, not elements")
    func vectorLengthIsBytes() throws {
        var writer = MLS.Writer()
        try writer.encodeVector([UInt32(1), 2, 3])
        #expect(writer.bytes.first == 12)
        #expect(writer.count == 13)
    }

    @Test("vectors round-trip, including empty")
    func vectorRoundTrip() throws {
        for values in [[], [1], [1, 2, 3, 4, 5]] as [[UInt32]] {
            var writer = MLS.Writer()
            try writer.encodeVector(values)
            var reader = MLS.Reader(writer.bytes)
            #expect(try reader.decodeVector(UInt32.self) == values)
            try reader.finish()
        }
    }

    @Test("optionals round-trip and use a single presence byte")
    func optionalRoundTrip() throws {
        var absent = MLS.Writer()
        try absent.encodeOptional(UInt32?.none)
        #expect(absent.bytes == [0])

        var present = MLS.Writer()
        try present.encodeOptional(UInt32?(0xAABB_CCDD))
        #expect(present.bytes == [1, 0xAA, 0xBB, 0xCC, 0xDD])

        var reader = MLS.Reader(present.bytes)
        #expect(try reader.decodeOptional(UInt32.self) == 0xAABB_CCDD)
        try reader.finish()
    }

    @Test("rejects an optional presence byte that is neither 0 nor 1")
    func badPresenceByte() {
        var reader = MLS.Reader([UInt8(2), 0, 0, 0, 0])
        #expect(throws: MLS.CodecError.invalidOptionalPresence(2)) {
            try reader.decodeOptional(UInt32.self)
        }
    }

    @Test("composite structures round-trip byte-identically")
    func compositeRoundTrip() throws {
        let samples = [
            Sample(tag: 0, payload: [], counts: [], note: nil),
            Sample(tag: 0xFFFF, payload: Array(repeating: 0xAB, count: 200), counts: [1, 2, 3], note: 42),
        ]
        for sample in samples {
            let encoded = try sample.mlsEncoded()
            let decoded = try Sample(mlsEncoded: encoded)
            #expect(decoded == sample)
            // Re-encoding must be byte-identical: everything downstream signs
            // and hashes these bytes.
            #expect(try decoded.mlsEncoded() == encoded)
        }
    }

    @Test("top-level decode rejects trailing bytes")
    func trailingBytes() throws {
        let encoded = try Sample(tag: 1, payload: [9], counts: [7], note: nil).mlsEncoded()
        #expect(throws: MLS.CodecError.trailingBytes(2)) {
            try Sample(mlsEncoded: encoded + Data([0xDE, 0xAD]))
        }
    }

    @Test("reads past the end are truncation errors, not crashes")
    func truncation() {
        var reader = MLS.Reader([UInt8(0x01), 0x02])
        #expect(throws: MLS.CodecError.truncated(needed: 4, available: 2)) {
            try reader.readUInt32()
        }
    }

    @Test("a vector whose contents overrun its header is rejected")
    func vectorOverrun() {
        // header says 6 bytes; UInt32 elements consume 4, leaving 2 dangling
        var reader = MLS.Reader([UInt8(6), 0, 0, 0, 1, 0, 0])
        #expect(throws: MLS.CodecError.truncated(needed: 4, available: 2)) {
            try reader.decodeVector(UInt32.self)
        }
    }

    @Test("random structures survive an encode/decode/re-encode cycle")
    func randomRoundTrip() throws {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<500 {
            let sample = Sample(
                tag: .random(in: .min ... .max, using: &generator),
                payload: (0..<Int.random(in: 0...300, using: &generator))
                    .map { _ in UInt8.random(in: .min ... .max, using: &generator) },
                counts: (0..<Int.random(in: 0...20, using: &generator))
                    .map { _ in UInt32.random(in: .min ... .max, using: &generator) },
                note: Bool.random(using: &generator)
                    ? UInt64.random(in: .min ... .max, using: &generator) : nil
            )
            let encoded = try sample.mlsEncoded()
            #expect(try Sample(mlsEncoded: encoded) == sample)
            #expect(try Sample(mlsEncoded: encoded).mlsEncoded() == encoded)
        }
    }
}
