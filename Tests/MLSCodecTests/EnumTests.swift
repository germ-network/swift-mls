import Testing

@testable import MLSCodec

private enum ClosedKind: UInt8, MLSClosedEnum, Equatable {
	case reserved = 0
	case application = 1
	case handshake = 2
}

private enum KnownProposalLikeType: UInt16, RawRepresentable, Sendable, Equatable, Hashable {
	case add = 1
	case update = 2
	case remove = 3
}

private typealias ExtensibleProposalLikeType = MLS.ExtensibleEnum<KnownProposalLikeType>

@Suite("Enum codec policies (RFC 9420 §17.1)")
struct EnumTests {
	@Test("a closed enum round-trips its known values")
	func closedKnownRoundTrip() throws {
		for value: ClosedKind in [.reserved, .application, .handshake] {
			let encoded = try value.mlsEncoded()
			#expect(Array(encoded) == [value.rawValue])
			#expect(try ClosedKind(mlsEncoded: encoded) == value)
		}
	}

	// This is the whole point of the closed/extensible split: WireFormat,
	// ContentType et al. must reject anything RFC 9420 didn't define.
	@Test("a closed enum rejects an unknown raw value")
	func closedRejectsUnknown() {
		var reader = MLS.Reader([UInt8(99)])
		#expect(throws: MLS.CodecError.unknownEnumValue(99)) {
			try reader.decode(ClosedKind.self)
		}
	}

	@Test("an extensible enum round-trips known cases as .known")
	func extensibleKnownRoundTrip() throws {
		let value = ExtensibleProposalLikeType(.update)
		let encoded = try value.mlsEncoded()
		#expect(Array(encoded) == [0, 2])
		#expect(try ExtensibleProposalLikeType(mlsEncoded: encoded) == value)
	}

	// The failure mode this guards against: an unrelated future proposal
	// type must decode as data, not as a `CodecError` — rejecting it would
	// make GroupContextExtensions/required_capabilities unparsable for
	// every implementation that predates the new type.
	@Test("an extensible enum preserves an unknown raw value rather than rejecting it")
	func extensiblePreservesUnknown() throws {
		var reader = MLS.Reader([UInt8(0xFF), 0xFE])
		let decoded = try reader.decode(ExtensibleProposalLikeType.self)
		#expect(decoded == .unknown(0xFFFE))
		#expect(decoded.rawValue == 0xFFFE)
		#expect(try Array(decoded.mlsEncoded()) == [0xFF, 0xFE])
	}

	@Test("optional<T> composes through Optional's own MLSCodable conformance")
	func optionalConformance() throws {
		let values: [UInt32?] = [nil, 7]
		var writer = MLS.Writer()
		try writer.encodeVector(values)
		var reader = MLS.Reader(writer.bytes)
		#expect(try reader.decodeVector(UInt32?.self) == values)
	}
}
