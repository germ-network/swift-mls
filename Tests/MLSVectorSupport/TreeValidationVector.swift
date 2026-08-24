public struct TreeValidationVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let tree: HexData
	public let groupID: HexData
	public let treeHashes: [HexData]
	public let resolutions: [[UInt32]]

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case tree
		case groupID = "group_id"
		case treeHashes = "tree_hashes"
		case resolutions
	}
}
