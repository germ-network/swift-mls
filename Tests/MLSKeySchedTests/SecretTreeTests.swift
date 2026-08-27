import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSKeySchedule

@Suite("secret-tree.json (mlswg/mls-implementations)")
struct SecretTreeTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("secret-tree", as: [SecretTreeVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	/// Ratchets are stateless here (`ratchetStep` takes a generation and a
	/// secret, not "the next one"), so reaching generation `N` means
	/// deriving-and-discarding every generation before it — exactly RFC
	/// 9420's own skip-ahead cost. A vector row's generation is arbitrary,
	/// not necessarily 0, exercising that this has no shortcut.
	private func ratchetToGeneration(
		_ provider: any MLS.CipherSuiteProvider, from baseSecret: Data, generation: UInt32
	) throws -> (key: Data, nonce: Data) {
		var secret = baseSecret
		for g in 0...generation {
			let step = try MLS.KeySchedule.ratchetStep(
				provider, secret: secret, generation: g)
			if g == generation { return (step.key, step.nonce) }
			secret = step.nextSecret
		}
		fatalError("unreachable: the range above always includes `generation`")
	}

	@Test(
		"every leaf's handshake/application ratchet reaches the vector's spot-checked generations",
		arguments: records)
	func matchesVector(_ record: SecretTreeVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		let numLeaves = try MLS.LeafCount(validating: UInt32(record.leaves.count))

		for (leafIndex, generations) in record.leaves.enumerated() {
			let leafSecret = try MLS.KeySchedule.leafSecret(
				provider, encryptionSecret: record.encryptionSecret.bytes,
				leafIndex: UInt32(leafIndex), numLeaves: numLeaves
			)
			let handshakeBase = try MLS.KeySchedule.handshakeRatchetSecret(
				provider, leafSecret: leafSecret)
			let applicationBase = try MLS.KeySchedule.applicationRatchetSecret(
				provider, leafSecret: leafSecret)

			for entry in generations {
				let (hKey, hNonce) = try ratchetToGeneration(
					provider, from: handshakeBase, generation: entry.generation)
				#expect(hKey == entry.handshakeKey.bytes)
				#expect(hNonce == entry.handshakeNonce.bytes)

				let (aKey, aNonce) = try ratchetToGeneration(
					provider, from: applicationBase,
					generation: entry.generation)
				#expect(aKey == entry.applicationKey.bytes)
				#expect(aNonce == entry.applicationNonce.bytes)
			}
		}

		let (key, nonce) = try MLS.Framing.senderDataKeyNonce(
			provider, secret: record.senderData.senderDataSecret.bytes,
			ciphertextSample: record.senderData.ciphertext.bytes
		)
		#expect(key == record.senderData.key.bytes)
		#expect(nonce == record.senderData.nonce.bytes)
	}

	@Test("an out-of-range leafIndex throws rather than returning the root secret")
	func leafSecretRejectsOutOfRangeIndex() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(
				for: .init(id: Self.records[0].cipherSuite)))
		#expect(throws: MLS.CryptoError.self) {
			try MLS.KeySchedule.leafSecret(
				provider,
				encryptionSecret: Data(repeating: 0, count: provider.hashSize),
				leafIndex: 4, numLeaves: try MLS.LeafCount(validating: 4))
		}
	}
}
