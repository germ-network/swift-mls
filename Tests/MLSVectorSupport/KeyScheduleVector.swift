/// `key-schedule.json` (mlswg/mls-implementations) — a chain of epochs for
/// one group; each epoch's `commit_secret`/`psk_secret`/`group_context` are
/// inputs, everything else is the expected output of advancing the key
/// schedule from the previous epoch's `init_secret`.
public struct KeyScheduleVector: Decodable, Sendable {
	public struct Exporter: Decodable, Sendable {
		public let label: String
		public let context: HexData
		public let length: Int
		public let secret: HexData
	}

	public struct Epoch: Decodable, Sendable {
		public let commitSecret: HexData
		public let confirmationKey: HexData
		public let confirmedTranscriptHash: HexData
		public let encryptionSecret: HexData
		public let epochAuthenticator: HexData
		public let exporter: Exporter
		public let exporterSecret: HexData
		public let externalPub: HexData
		public let externalSecret: HexData
		public let groupContext: HexData
		public let initSecret: HexData
		public let joinerSecret: HexData
		public let membershipKey: HexData
		public let pskSecret: HexData
		public let resumptionPsk: HexData
		public let senderDataSecret: HexData
		public let treeHash: HexData
		public let welcomeSecret: HexData

		enum CodingKeys: String, CodingKey {
			case exporter
			case initSecret = "init_secret"
			case commitSecret = "commit_secret"
			case confirmationKey = "confirmation_key"
			case confirmedTranscriptHash = "confirmed_transcript_hash"
			case encryptionSecret = "encryption_secret"
			case epochAuthenticator = "epoch_authenticator"
			case exporterSecret = "exporter_secret"
			case externalPub = "external_pub"
			case externalSecret = "external_secret"
			case groupContext = "group_context"
			case joinerSecret = "joiner_secret"
			case membershipKey = "membership_key"
			case pskSecret = "psk_secret"
			case resumptionPsk = "resumption_psk"
			case senderDataSecret = "sender_data_secret"
			case treeHash = "tree_hash"
			case welcomeSecret = "welcome_secret"
		}
	}

	public let cipherSuite: UInt16
	public let groupId: HexData
	public let initialInitSecret: HexData
	public let epochs: [Epoch]

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case groupId = "group_id"
		case initialInitSecret = "initial_init_secret"
		case epochs
	}
}
