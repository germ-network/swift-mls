/// `psk_secret.json` (official mlswg/mls-implementations vector). Every PSK
/// it exercises is external: `psk_id` is the raw `ExternalPskId` bytes,
/// `psk_nonce` the `PskNonce` bytes. Some records carry zero PSKs — the
/// zero-PSK baseline case, `psk_secret` = an all-zero `Nh`-byte string.
public struct PskSecretVector: Decodable, Sendable {
	public struct Psk: Decodable, Sendable {
		public let id: HexData
		public let nonce: HexData
		public let psk: HexData

		enum CodingKeys: String, CodingKey {
			case id = "psk_id"
			case nonce = "psk_nonce"
			case psk
		}
	}

	public let cipherSuite: UInt16
	public let psks: [Psk]
	public let pskSecret: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case psks
		case pskSecret = "psk_secret"
	}
}
