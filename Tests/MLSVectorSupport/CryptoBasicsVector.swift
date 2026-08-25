/// `crypto-basics.json` (mlswg/mls-implementations) — one record per cipher
/// suite, each exercising the seven basic label-based crypto operations.
public struct CryptoBasicsVector: Decodable, Sendable {
	public struct DeriveSecret: Decodable, Sendable {
		public let label: String
		public let out: HexData
		public let secret: HexData
	}

	public struct DeriveTreeSecret: Decodable, Sendable {
		public let generation: UInt32
		public let label: String
		public let length: UInt16
		public let out: HexData
		public let secret: HexData
	}

	public struct EncryptWithLabel: Decodable, Sendable {
		public let ciphertext: HexData
		public let context: HexData
		public let kemOutput: HexData
		public let label: String
		public let plaintext: HexData
		public let priv: HexData
		public let pub: HexData

		enum CodingKeys: String, CodingKey {
			case ciphertext, context, label, plaintext, priv, pub
			case kemOutput = "kem_output"
		}
	}

	public struct ExpandWithLabel: Decodable, Sendable {
		public let context: HexData
		public let label: String
		public let length: UInt16
		public let out: HexData
		public let secret: HexData
	}

	public struct RefHash: Decodable, Sendable {
		public let label: String
		public let out: HexData
		public let value: HexData
	}

	public struct SignWithLabel: Decodable, Sendable {
		public let content: HexData
		public let label: String
		public let priv: HexData
		public let pub: HexData
		public let signature: HexData
	}

	public let cipherSuite: UInt16
	public let deriveSecret: DeriveSecret
	public let deriveTreeSecret: DeriveTreeSecret
	public let encryptWithLabel: EncryptWithLabel
	public let expandWithLabel: ExpandWithLabel
	public let refHash: RefHash
	public let signWithLabel: SignWithLabel

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case deriveSecret = "derive_secret"
		case deriveTreeSecret = "derive_tree_secret"
		case encryptWithLabel = "encrypt_with_label"
		case expandWithLabel = "expand_with_label"
		case refHash = "ref_hash"
		case signWithLabel = "sign_with_label"
	}
}

/// `mls-rs-signatures.json` — supplementary, not an official mlswg vector;
/// see `Vectors/README.md`.
public struct SignatureVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let content: HexData
	public let context: HexData
	public let signature: HexData
	public let signer: HexData
	public let publicKey: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case content, context, signature, signer
		case publicKey = "public"
	}
}
