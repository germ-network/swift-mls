import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSKeySchedule

/// `SenderData`/`SenderDataAAD` (RFC 9420 §6.3.1) are framing-layer wire
/// types — `MLSKeySchedule` never needs to know their shape, only that a
/// ciphertext's leading bytes seed the key/nonce derivation. Encoding them
/// here, private to this test, gets full vector coverage (the derivation
/// *and* the AEAD seal built on it) without adding a wire type this
/// component has no other reason to own.
private struct SenderData: MLSEncodable {
	var sender: UInt32
	var generation: UInt32
	var reuseGuard: Data  // fixed 4 bytes, RFC 9420 §6.3.1 — no length prefix

	func encode(to writer: inout MLS.Writer) throws {
		writer.writeUInt32(sender)
		writer.writeUInt32(generation)
		writer.writeBytes(reuseGuard)
	}
}

private struct SenderDataAAD: MLSEncodable {
	var groupID: Data
	var epoch: UInt64
	var contentType: UInt8  // ContentType.application = 1

	func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(groupID)
		writer.writeUInt64(epoch)
		writer.writeUInt8(contentType)
	}
}

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

		let (key, nonce) = try MLS.KeySchedule.senderDataKeyNonce(
			provider, senderDataSecret: record.secret.bytes,
			ciphertext: record.ciphertextBytes.bytes
		)
		#expect(key == record.expectedKey.bytes)
		#expect(nonce == record.expectedNonce.bytes)

		let senderData = try SenderData(
			sender: record.senderData.sender, generation: record.senderData.generation,
			reuseGuard: record.senderData.reuseGuard.bytes
		).mlsEncoded()
		let aad = try SenderDataAAD(
			groupID: record.senderDataAad.groupId.bytes,
			epoch: record.senderDataAad.epoch, contentType: 1
		).mlsEncoded()

		let sealed = try provider.aeadSeal(
			key: key, nonce: nonce, aad: aad, plaintext: senderData)
		#expect(sealed == record.expectedCiphertext.bytes)
	}
}
