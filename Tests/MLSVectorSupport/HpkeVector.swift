/// `hpke-base-mode.json`, trimmed from `cfrg/draft-irtf-cfrg-hpke`'s
/// `test-vectors.json` to `mode=0` (base) and the KEM/KDF pairs this repo
/// implements. See `Vectors/README.md`.
public struct HpkeVector: Decodable, Sendable {
	public struct Encryption: Decodable, Sendable {
		public let aad: HexData
		public let ciphertext: HexData
		public let nonce: HexData
		public let plaintext: HexData

		enum CodingKeys: String, CodingKey {
			case aad, nonce
			case ciphertext = "ct"
			case plaintext = "pt"
		}
	}

	public struct Export: Decodable, Sendable {
		public let exporterContext: HexData
		public let length: Int
		public let exportedValue: HexData

		enum CodingKeys: String, CodingKey {
			case exporterContext = "exporter_context"
			case length = "L"
			case exportedValue = "exported_value"
		}
	}

	public let mode: Int
	public let kemID: UInt16
	public let kdfID: UInt16
	public let aeadID: UInt16
	public let info: HexData
	public let ikmR: HexData
	public let ikmE: HexData
	public let skRm: HexData
	public let skEm: HexData
	public let pkRm: HexData
	public let pkEm: HexData
	public let enc: HexData
	public let sharedSecret: HexData
	public let keyScheduleContext: HexData
	public let secret: HexData
	public let key: HexData
	public let baseNonce: HexData
	public let exporterSecret: HexData
	public let encryptions: [Encryption]
	public let exports: [Export]

	enum CodingKeys: String, CodingKey {
		case mode, info, ikmR, ikmE, skRm, skEm, pkRm, pkEm, enc, secret, key
		case kemID = "kem_id"
		case kdfID = "kdf_id"
		case aeadID = "aead_id"
		case sharedSecret = "shared_secret"
		case keyScheduleContext = "key_schedule_context"
		case baseNonce = "base_nonce"
		case exporterSecret = "exporter_secret"
		case encryptions, exports
	}
}
