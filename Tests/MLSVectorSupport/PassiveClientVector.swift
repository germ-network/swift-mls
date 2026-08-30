/// Shared schema for `passive-client-welcome.json`, `passive-client-random.json`,
/// and `passive-client-handling-commit.json` — verified identical across all
/// 148 records (56 + 1 + 91) in this session.
public struct PassiveClientVector: Decodable, Sendable {
	public struct ExternalPsk: Decodable, Sendable {
		public let pskID: HexData
		public let psk: HexData

		enum CodingKeys: String, CodingKey {
			case pskID = "psk_id"
			case psk
		}
	}

	public struct Epoch: Decodable, Sendable {
		public let proposals: [HexData]
		public let commit: HexData
		public let epochAuthenticator: HexData

		enum CodingKeys: String, CodingKey {
			case proposals, commit
			case epochAuthenticator = "epoch_authenticator"
		}
	}

	public let cipherSuite: UInt16
	public let externalPsks: [ExternalPsk]
	public let keyPackage: HexData
	public let signaturePriv: HexData
	public let encryptionPriv: HexData
	public let initPriv: HexData
	public let welcome: HexData
	public let ratchetTree: HexData?
	public let initialEpochAuthenticator: HexData
	public let epochs: [Epoch]

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case externalPsks = "external_psks"
		case keyPackage = "key_package"
		case signaturePriv = "signature_priv"
		case encryptionPriv = "encryption_priv"
		case initPriv = "init_priv"
		case welcome
		case ratchetTree = "ratchet_tree"
		case initialEpochAuthenticator = "initial_epoch_authenticator"
		case epochs
	}
}
