import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

@Suite("key_package_ref.json, structural (mls-rs, self-contained)")
struct KeyPackageTests {
	static let provider = SwiftCryptoProvider()

	static let records = (try! VectorFile.load("key_package_ref", as: [RefVector].self))
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("decodes, re-encodes byte-identically, and its own ref matches", arguments: records)
	func structural(_ record: RefVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var reader = MLS.Reader(record.input.bytes)
		let keyPackage = try MLS.RFC9420.KeyPackage(from: &reader)
		try reader.finish()

		#expect(try keyPackage.mlsEncoded() == record.input.bytes)
		#expect(try keyPackage.reference(provider).data == record.output.bytes)
	}

	@Test("reference throws for a provider whose cipher suite doesn't match the package's")
	func referenceRejectsMismatchedProvider() throws {
		let record = try #require(Self.records.first)
		let mismatched = try #require(
			Self.provider.supportedCipherSuites.first { $0.id != record.cipherSuite })
		let provider = try #require(Self.provider.cipherSuiteProvider(for: mismatched))

		var reader = MLS.Reader(record.input.bytes)
		let keyPackage = try MLS.RFC9420.KeyPackage(from: &reader)

		#expect(throws: MLS.RFC9420.WireError.cipherSuiteMismatch) {
			try keyPackage.reference(provider)
		}
	}
}
