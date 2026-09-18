import Foundation
import MLSCodec
import MLSProfileRFC9420
import MLSVectorSupport
import Testing

@testable import MLSCombiner

/// Framing vectors built from `key_package_ref.json` — real mls-rs-encoded
/// `MLSMessage` KeyPackages — framed by hand into Germ's deployed combiner-blob
/// layout (`[version byte][opaque t][opaque pq]`), mirroring the Rust
/// `encode_combiner_key_package`'s output shape.
@Suite("combiner blob framing (deployed v3, self-contained)")
struct CombinerBlobTests {
	static let records = (try! VectorFile.load("key_package_ref", as: [RefVector].self))

	private static func framed(_ t: Data, _ pq: Data, version: UInt8 = 3) -> Data {
		var writer = MLS.Writer()
		writer.writeUInt8(version)
		try! writer.writeOpaque(t)
		try! writer.writeOpaque(pq)
		return writer.data
	}

	private static func keyPackage(_ message: MLS.RFC9420.Message) -> MLS.RFC9420.KeyPackage? {
		if case .keyPackage(let kp) = message { return kp }
		return nil
	}

	@Test(
		"decodes a framed pair of real mls-rs key packages, halves intact",
		arguments: records)
	func decodesFramedPair(_ record: RefVector) throws {
		// The deployed framing carries each half as a full §6 MLSMessage (the Rust
		// parser's `MlsMessage::from_bytes` expectation), so wrap the vector's bare
		// KeyPackage the way the engine publishes it.
		var reader = MLS.Reader(record.input.bytes)
		let kp = try MLS.RFC9420.KeyPackage(from: &reader)
		try reader.finish()
		let kpBytes = try MLS.RFC9420.Message.keyPackage(kp).mlsEncoded()

		let blob = try #require(
			MLS.Combiner.CombinerBlob(bytes: Self.framed(kpBytes, kpBytes)))

		let t = try #require(Self.keyPackage(blob.tKeyPackage))
		let pq = try #require(Self.keyPackage(blob.pqKeyPackage))

		// Both halves re-encode to the original bare KeyPackage bytes (the
		// MLSMessage envelope around them is the framing's, not the vector's).
		#expect(try t.mlsEncoded() == record.input.bytes)
		#expect(try pq.mlsEncoded() == record.input.bytes)
		#expect(t.cipherSuite.id == record.cipherSuite)
	}

	@Test(
		"a bare MLSMessage is not a blob (the version byte is the discriminator)",
		arguments: records)
	func bareMessageIsNotABlob(_ record: RefVector) throws {
		#expect(MLS.Combiner.CombinerBlob(bytes: record.input.bytes) == nil)
	}

	@Test("rejects wrong version byte, truncation, and trailing bytes")
	func rejectsMalformed() throws {
		let kpBytes = try #require(Self.records.first).input.bytes
		let framed = Self.framed(kpBytes, kpBytes)

		#expect(
			MLS.Combiner.CombinerBlob(bytes: Self.framed(kpBytes, kpBytes, version: 2))
				== nil)

		#expect(MLS.Combiner.CombinerBlob(bytes: framed.dropLast()) == nil)
		#expect(MLS.Combiner.CombinerBlob(bytes: framed + Data([0])) == nil)
		#expect(MLS.Combiner.CombinerBlob(bytes: Data([framed.first!])) == nil)
	}
}
