public struct TreeOperationsVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let proposal: HexData
	public let proposalSender: UInt32
	public let treeBefore: HexData
	public let treeAfter: HexData
	public let treeHashBefore: HexData
	public let treeHashAfter: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case proposal
		case proposalSender = "proposal_sender"
		case treeBefore = "tree_before"
		case treeAfter = "tree_after"
		case treeHashBefore = "tree_hash_before"
		case treeHashAfter = "tree_hash_after"
	}
}
