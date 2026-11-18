import Foundation
import Testing

@testable import MLSCodec

nonisolated(unsafe) private var decodedElements = 0

private struct CountedElement: MLSDecodable {
	init(from reader: inout MLS.Reader) throws {
		_ = try reader.readUInt8()
		decodedElements += 1
	}
}

private func encodedBytes(count: Int) throws -> [UInt8] {
	var writer = MLS.Writer()
	try writer.encodeVector([UInt8](repeating: 7, count: count))
	return writer.bytes
}

/// A bounded vector decode stops at the first element past its limit and
/// materialises at most `maxCount` elements.
private struct ZeroWidthElement: MLSDecodable {
	init(from reader: inout MLS.Reader) throws {}
}

@Suite("Bounded vector decode", .serialized)
struct VectorLimitTests {
	@Test("a vector of exactly maxCount elements decodes")
	func vectorAtLimitDecodes() throws {
		var reader = MLS.Reader(try encodedBytes(count: 5))
		let values: [UInt8] = try reader.decodeVector(maxCount: 5)
		try reader.finish()
		#expect(values.count == 5)
	}

	@Test("a vector longer than maxCount throws vectorElementLimitExceeded")
	func vectorOverLimitThrows() throws {
		var reader = MLS.Reader(try encodedBytes(count: 6))
		#expect(throws: MLS.CodecError.vectorElementLimitExceeded(limit: 5)) {
			let _: [UInt8] = try reader.decodeVector(maxCount: 5)
		}
	}

	@Test("decoding stops before element maxCount + 1 is decoded")
	func decodingStopsAtLimit() throws {
		decodedElements = 0
		var reader = MLS.Reader(try encodedBytes(count: 50))
		#expect(throws: MLS.CodecError.vectorElementLimitExceeded(limit: 3)) {
			let _: [CountedElement] = try reader.decodeVector(maxCount: 3)
		}
		#expect(decodedElements == 3)
	}

	@Test("an element that consumes no bytes is a framing error, not a limit error")
	func zeroWidthElementIsRejected() throws {
		var reader = MLS.Reader(try encodedBytes(count: 4))
		#expect(throws: MLS.CodecError.vectorNotFullyConsumed(remaining: 4)) {
			let _: [ZeroWidthElement] = try reader.decodeVector(maxCount: 100)
		}
	}

	@Test("an empty vector decodes at any limit and one element exceeds a limit of zero")
	func limitOfZero() throws {
		var empty = MLS.Reader(try encodedBytes(count: 0))
		let none: [UInt8] = try empty.decodeVector(maxCount: 0)
		#expect(none.isEmpty)
		var one = MLS.Reader(try encodedBytes(count: 1))
		#expect(throws: MLS.CodecError.vectorElementLimitExceeded(limit: 0)) {
			let _: [UInt8] = try one.decodeVector(maxCount: 0)
		}
	}
}
