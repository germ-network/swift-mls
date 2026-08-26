import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSFraming

@Suite("key_package_ref.json / proposal_ref.json (mls-rs, self-contained)")
struct HashReferenceTests {
	static let provider = SwiftCryptoProvider()

	static func records(_ name: String) -> [RefVector] {
		(try! VectorFile.load(name, as: [RefVector].self))
			.filter {
				provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite)
			}
	}

	// `input` is a bare serialized KeyPackage — opaque bytes are enough to
	// prove RefHash's label and construction before KeyPackage exists.
	// `MLS.RFC9420.KeyPackage`'s own tests (once written) additionally
	// decode `input` and confirm the ref of the decoded-then-re-encoded
	// bytes still matches — this file's real, dual-purpose job.
	@Test("MakeKeyPackageRef, opaque-bytes mode", arguments: records("key_package_ref"))
	func keyPackageRef(_ record: RefVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let ref = try MLS.HashReference.compute(
			provider, label: "MLS 1.0 KeyPackage Reference", value: record.input.bytes)
		#expect(ref.data == record.output.bytes)
	}

	@Test("MakeProposalRef, opaque-bytes mode", arguments: records("proposal_ref"))
	func proposalRef(_ record: RefVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let ref = try MLS.HashReference.compute(
			provider, label: "MLS 1.0 Proposal Reference", value: record.input.bytes)
		#expect(ref.data == record.output.bytes)
	}
}
