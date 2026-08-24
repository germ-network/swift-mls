import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import MLSVectorSupport
import Testing

@testable import MLSFraming

@Suite("mls-rs-sender-data-key.json (supplementary, not an official mlswg vector)")
struct SenderDataKeyTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"mls-rs-sender-data-key", as: [SenderDataKeyVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test(
		"derives the expected key/nonce, and sealing with them matches the expected ciphertext",
		arguments: records)
	func matchesVector(_ record: SenderDataKeyVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		let (key, nonce) = try MLS.Framing.senderDataKeyNonce(
			provider, secret: record.secret.bytes,
			ciphertextSample: record.ciphertextBytes.bytes)
		#expect(key == record.expectedKey.bytes)
		#expect(nonce == record.expectedNonce.bytes)

		let senderData = MLS.Framing.SenderData(
			leafIndex: MLS.LeafIndex(value: record.senderData.sender),
			generation: record.senderData.generation,
			reuseGuard: MLS.Framing.ReuseGuard(record.senderData.reuseGuard.bytes))
		let aad = MLS.Framing.SenderDataAAD(
			groupID: record.senderDataAad.groupId.bytes,
			epoch: record.senderDataAad.epoch,
			contentType: .application)

		let sealed = try MLS.Framing.sealSenderData(
			provider, key: key, nonce: nonce, senderData: senderData, aad: aad)
		#expect(sealed == record.expectedCiphertext.bytes)
	}
}
