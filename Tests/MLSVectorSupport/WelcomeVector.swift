public struct WelcomeVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let initPriv: HexData
	public let signerPub: HexData
	public let keyPackage: HexData
	public let welcome: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case initPriv = "init_priv"
		case signerPub = "signer_pub"
		case keyPackage = "key_package"
		case welcome
	}
}
