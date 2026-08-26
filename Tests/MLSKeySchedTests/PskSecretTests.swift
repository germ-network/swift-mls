import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSKeySchedule

@Suite("mls-rs-psk-secret.json (supplementary, not an official mlswg vector)")
struct PskSecretTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("mls-rs-psk-secret", as: [PskSecretVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("accumulates 1 to 10 external PSKs correctly", arguments: records)
	func matchesVector(_ record: PskSecretVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let secret = try MLS.KeySchedule.pskSecret(
			provider,
			psks: record.psks.map {
				(id: $0.id.bytes, nonce: $0.nonce.bytes, psk: $0.psk.bytes)
			}
		)
		#expect(secret == record.pskSecret.bytes)
	}
}
