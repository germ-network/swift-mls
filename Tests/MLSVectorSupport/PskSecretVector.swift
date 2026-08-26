/// `mls-rs-psk-secret.json` (supplementary, not an official mlswg vector —
/// see `Vectors/README.md`). Every PSK it exercises is external: `id` is
/// the raw `ExternalPskId` bytes, `nonce` the `PskNonce` bytes.
public struct PskSecretVector: Decodable, Sendable {
	public struct Psk: Decodable, Sendable {
		public let id: HexData
		public let nonce: HexData
		public let psk: HexData
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
