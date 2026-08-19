/// `secret-tree.json` (mlswg/mls-implementations). `leaves.count` is the
/// tree's leaf count; each leaf carries one or more spot checks at
/// (possibly non-sequential) generations, exercising the ratchet's
/// skip-ahead behavior, not just `next()`.
public struct SecretTreeVector: Decodable, Sendable {
	public struct SenderData: Decodable, Sendable {
		public let ciphertext: HexData
		public let key: HexData
		public let nonce: HexData
		public let senderDataSecret: HexData

		enum CodingKeys: String, CodingKey {
			case ciphertext, key, nonce
			case senderDataSecret = "sender_data_secret"
		}
	}

	public struct LeafGeneration: Decodable, Sendable {
		public let generation: UInt32
		public let applicationKey: HexData
		public let applicationNonce: HexData
		public let handshakeKey: HexData
		public let handshakeNonce: HexData

		enum CodingKeys: String, CodingKey {
			case generation
			case applicationKey = "application_key"
			case applicationNonce = "application_nonce"
			case handshakeKey = "handshake_key"
			case handshakeNonce = "handshake_nonce"
		}
	}

	public let cipherSuite: UInt16
	public let encryptionSecret: HexData
	public let senderData: SenderData
	public let leaves: [[LeafGeneration]]

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case encryptionSecret = "encryption_secret"
		case senderData = "sender_data"
		case leaves
	}
}
