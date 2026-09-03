import MLSCodec
import MLSCrypto
import MLSVectorSupport
import SecretBytes
import Testing

@testable import MLSKeySchedule

@Suite("psk_secret.json (mlswg/mls-implementations, official)")
struct PskSecretTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("psk_secret", as: [PskSecretVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("accumulates 0 to 10 external PSKs correctly", arguments: records)
	func matchesVector(_ record: PskSecretVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let secret = try MLS.KeySchedule.pskSecret(
			provider,
			psks: record.psks.map {
				// `PreSharedKeyID` (external case): psktype(1) ++
				// opaque psk_id<V> ++ opaque psk_nonce<V>. This vector
				// only exercises external PSKs; `MLS.KeySchedule.pskSecret`
				// itself no longer knows or cares which kind it was given
				// (see `Sources/MLSKeySchedule/Labels.swift`).
				var writer = MLS.Writer()
				writer.writeUInt8(1)
				try! writer.writeOpaque($0.id.bytes)
				try! writer.writeOpaque($0.nonce.bytes)
				return (
					encodedID: writer.data,
					psk: try SecretBytes(bytes: $0.psk.bytes)
				)
			}
		)
		#expect(secret == record.pskSecret.bytes)
	}
}
