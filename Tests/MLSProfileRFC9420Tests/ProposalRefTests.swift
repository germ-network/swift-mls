import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

@Suite("proposal_ref.json, structural (mls-rs, self-contained)")
struct ProposalRefTests {
	static let provider = SwiftCryptoProvider()

	static let records = (try! VectorFile.load("proposal_ref", as: [RefVector].self))
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test(
		"decodes a real AuthenticatedContent, re-encodes byte-identically, and its ref matches",
		arguments: records)
	func structural(_ record: RefVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var reader = MLS.Reader(record.input.bytes)
		let authenticated = try MLS.RFC9420.AuthenticatedContent(from: &reader)
		try reader.finish()

		let reencoded = try authenticated.mlsEncoded()
		#expect(reencoded == record.input.bytes)

		let ref = try MLS.HashReference.compute(
			provider, label: "MLS 1.0 Proposal Reference", value: reencoded)
		#expect(ref.data == record.output.bytes)
	}
}
