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

	@Test(
		"opaque vectors round-trip, including empty and multi-byte lengths",
		arguments: [0, 1, 63, 64, 300])
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
			Sample(
				tag: 0xFFFF, payload: Array(repeating: 0xAB, count: 200),
				counts: [1, 2, 3], note: 42),
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

	// Every read primitive needs this independently: each has its own
	// bounds check, so covering one does not cover the others.
	@Test("every read primitive rejects truncated input, not only readUInt32")
	func truncationAtEveryPrimitive() {
		#expect(throws: MLS.CodecError.truncated(needed: 1, available: 0)) {
			var reader = MLS.Reader([UInt8]())
			_ = try reader.readUInt8()
		}
		#expect(throws: MLS.CodecError.truncated(needed: 2, available: 1)) {
			var reader = MLS.Reader([UInt8(0)])
			_ = try reader.readUInt16()
		}
		#expect(throws: MLS.CodecError.truncated(needed: 8, available: 3)) {
			var reader = MLS.Reader([UInt8](repeating: 0, count: 3))
			_ = try reader.readUInt64()
		}
		#expect(throws: MLS.CodecError.truncated(needed: 5, available: 2)) {
			var reader = MLS.Reader([UInt8](repeating: 0, count: 2))
			_ = try reader.readBytes(5)
		}
	}

	// RFC 9420 §2.1.2: a decoder must not let a length header overrun
	// available storage. A header claiming the 2^30-1 ceiling over a
	// near-empty buffer must fail fast on the length check, not attempt
	// to allocate anything close to a gigabyte.
	@Test("an opaque length header far beyond the input fails immediately, not by allocating")
	func opaqueOversizedHeader() {
		var reader = MLS.Reader([UInt8(0xBF), 0xFF, 0xFF, 0xFF])  // declares 2^30 - 1 bytes
		#expect(
			throws: MLS.CodecError.truncated(
				needed: Int(MLS.Varint.maxValue), available: 0)
		) {
			_ = try reader.readOpaque()
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

	// A vector element that consumes zero bytes would otherwise loop
	// forever on malformed input — this is the guard's actual trigger,
	// distinct from `vectorOverrun` above (an ordinary short count).
	@Test("a vector element that consumes zero bytes is rejected, not looped on")
	func vectorZeroByteElement() {
		struct ZeroByteElement: MLSDecodable {
			init(from reader: inout MLS.Reader) throws {}
		}
		var reader = MLS.Reader([UInt8(3), 0, 0, 0])  // 3-byte region, nothing consumes it
		#expect(throws: MLS.CodecError.vectorNotFullyConsumed(remaining: 3)) {
			_ = try reader.decodeVector(ZeroByteElement.self)
		}
	}

	// A synthetic Collection whose `count` lies about how much storage it
	// holds, so this exercises the oversized-length path without actually
	// allocating a gigabyte-scale buffer in the test.
	private struct OversizedCollection: Collection {
		let count: Int
		var startIndex: Int { 0 }
		var endIndex: Int { count }
		func index(after i: Int) -> Int { i + 1 }
		subscript(position: Int) -> UInt8 { 0 }
	}

	@Test("writeOpaque rejects a collection larger than the varint ceiling can express")
	func writeOpaqueOversized() {
		var writer = MLS.Writer()
		let tooLarge = Int(MLS.Varint.maxValue) + 1
		#expect(throws: MLS.CodecError.lengthTooLarge(UInt64(tooLarge))) {
			try writer.writeOpaque(OversizedCollection(count: tooLarge))
		}
	}

	private struct NestedSample: MLSCodable, Equatable {
		var id: UInt8
		var values: [UInt16]

		func encode(to writer: inout MLS.Writer) throws {
			writer.writeUInt8(id)
			try writer.encodeVector(values)
		}

		init(from reader: inout MLS.Reader) throws {
			id = try reader.readUInt8()
			values = try reader.decodeVector()
		}

		init(id: UInt8, values: [UInt16]) {
			(self.id, self.values) = (id, values)
		}
	}

	// The byte-count-not-element-count semantics compound across nesting
	// levels — a vector of structs that themselves contain vectors is
	// exactly where a one-level-deep test like `vectorLengthIsBytes` would
	// miss a bug in the outer length calculation.
	@Test("a vector of structs containing their own vectors round-trips")
	func nestedVectorRoundTrip() throws {
		let samples = [
			NestedSample(id: 1, values: []),
			NestedSample(id: 2, values: [10, 20, 30]),
			NestedSample(id: 3, values: [0xFFFF]),
		]
		var writer = MLS.Writer()
		try writer.encodeVector(samples)
		var reader = MLS.Reader(writer.bytes)
		#expect(try reader.decodeVector(NestedSample.self) == samples)
		try reader.finish()
	}

	@Test("random structures survive an encode/decode/re-encode cycle")
	func randomRoundTrip() throws {
		var generator = SeededGenerator(seed: 0xC0DE_C0DE_1234_5678)
		for _ in 0..<500 {
			let sample = Sample(
				tag: .random(in: .min ... .max, using: &generator),
				payload: (0..<Int.random(in: 0...300, using: &generator))
					.map { _ in
						UInt8.random(in: .min ... .max, using: &generator)
					},
				counts: (0..<Int.random(in: 0...20, using: &generator))
					.map { _ in
						UInt32.random(in: .min ... .max, using: &generator)
					},
				note: Bool.random(using: &generator)
					? UInt64.random(in: .min ... .max, using: &generator) : nil
			)
			let encoded = try sample.mlsEncoded()
			#expect(try Sample(mlsEncoded: encoded) == sample)
			#expect(try Sample(mlsEncoded: encoded).mlsEncoded() == encoded)
		}
	}

	// The property that actually protects signatures and hashes: for
	// arbitrary bytes, decoding either throws or the decoded value
	// re-encodes to exactly the bytes given. A decoder that "fixes up"
	// malformed input, or that accepts two different byte strings as the
	// same value, breaks every signature computed over this codec's output.
	@Test("mutated bytes either fail to decode or round-trip exactly")
	func decodeOrRoundTrip() throws {
		var generator = SeededGenerator(seed: 0xFEED_FACE_9999_0001)
		let seeds = [
			Sample(tag: 0, payload: [], counts: [], note: nil),
			Sample(
				tag: 0x1234, payload: Array(repeating: 0xAB, count: 40),
				counts: [1, 2, 3], note: 9),
		]
		var violations = 0
		for seed in seeds {
			var bytes = Array(try seed.mlsEncoded())
			for _ in 0..<3_000 {
				let index = Int.random(in: 0..<bytes.count, using: &generator)
				bytes[index] = UInt8.random(in: .min ... .max, using: &generator)

				if let decoded = try? Sample(mlsEncoded: bytes) {
					if (try? Array(decoded.mlsEncoded())) != bytes {
						violations += 1
					}
				}
			}
		}
		#expect(violations == 0)
	}
}
