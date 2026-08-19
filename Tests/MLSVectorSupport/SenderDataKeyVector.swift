/// `mls-rs-sender-data-key.json` (supplementary, not an official mlswg
/// vector — see `Vectors/README.md`).
public struct SenderDataKeyVector: Decodable, Sendable {
	public struct SenderData: Decodable, Sendable {
		public let sender: UInt32
		public let generation: UInt32
		public let reuseGuard: HexData

		enum CodingKeys: String, CodingKey {
			case sender, generation
			case reuseGuard = "reuse_guard"
		}
	}

	public struct SenderDataAAD: Decodable, Sendable {
		public let epoch: UInt64
		public let groupId: HexData

		enum CodingKeys: String, CodingKey {
			case epoch
			case groupId = "group_id"
		}
	}

	public let cipherSuite: UInt16
	public let secret: HexData
	public let ciphertextBytes: HexData
	public let expectedKey: HexData
	public let expectedNonce: HexData
	public let senderData: SenderData
	public let senderDataAad: SenderDataAAD
	public let expectedCiphertext: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case secret
		case ciphertextBytes = "ciphertext_bytes"
		case expectedKey = "expected_key"
		case expectedNonce = "expected_nonce"
		case senderData = "sender_data"
		case senderDataAad = "sender_data_aad"
		case expectedCiphertext = "expected_ciphertext"
	}
}
