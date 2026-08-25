import Foundation
import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSCrypto

// mls-rs's own local fixture (not an official mlswg vector — see
// Vectors/README.md). It signs `context || content` under label
// "SignWithLabel", exercising SignWithLabel/VerifyWithLabel with a
// non-empty context, which crypto-basics.json's own sign_with_label record
// never does (its context is always empty).
@Suite("mls-rs-signatures.json (supplementary, not an official mlswg vector)")
struct SignatureVectorTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("mls-rs-signatures", as: [SignatureVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("the vector's signature verifies under our VerifyWithLabel", arguments: records)
	func verifiesVectorSignature(_ record: SignatureVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let verifies = try MLS.verifyWithLabel(
			provider,
			publicKey: .init(record.publicKey.bytes),
			label: "SignWithLabel",
			content: record.context.bytes + record.content.bytes,
			signature: record.signature.bytes
		)
		#expect(verifies)
	}

	// No re-signing test here: this fixture's `signer` field is not
	// consistently the raw private-key encoding swift-crypto expects
	// (mls-rs's own local generator used a 64-byte Ed25519 "expanded"
	// encoding and a 65-byte P-521 scalar for suites 1/3/5 respectively,
	// neither of which is RFC 9420's wire format). Re-signing coverage
	// with correctly-sized keys already exists via the official
	// crypto-basics.json suite (`CryptoBasicsTests.signWithLabel`); this
	// vector's own value is what it independently confirms — that its
	// signature verifies under our implementation — which the test above
	// already covers for all five supported suites.
}
