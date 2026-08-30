public struct MessageProtectionVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let groupID: HexData
	public let epoch: UInt64
	public let treeHash: HexData
	public let confirmedTranscriptHash: HexData
	public let signaturePriv: HexData
	public let signaturePub: HexData
	public let encryptionSecret: HexData
	public let senderDataSecret: HexData
	public let membershipKey: HexData
	public let proposal: HexData
	public let proposalPub: HexData
	public let proposalPriv: HexData
	public let commit: HexData
	public let commitPub: HexData
	public let commitPriv: HexData
	public let application: HexData
	public let applicationPriv: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case groupID = "group_id"
		case epoch
		case treeHash = "tree_hash"
		case confirmedTranscriptHash = "confirmed_transcript_hash"
		case signaturePriv = "signature_priv"
		case signaturePub = "signature_pub"
		case encryptionSecret = "encryption_secret"
		case senderDataSecret = "sender_data_secret"
		case membershipKey = "membership_key"
		case proposal
		case proposalPub = "proposal_pub"
		case proposalPriv = "proposal_priv"
		case commit
		case commitPub = "commit_pub"
		case commitPriv = "commit_priv"
		case application
		case applicationPriv = "application_priv"
	}
}
