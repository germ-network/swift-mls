public struct TreeKemVector: Decodable, Sendable {
	public struct PathSecretEntry: Decodable, Sendable {
		public let node: UInt32
		public let pathSecret: HexData

		enum CodingKeys: String, CodingKey {
			case node
			case pathSecret = "path_secret"
		}
	}

	public struct LeafPrivate: Decodable, Sendable {
		public let encryptionPriv: HexData
		public let index: UInt32
		public let pathSecrets: [PathSecretEntry]
		public let signaturePriv: HexData

		enum CodingKeys: String, CodingKey {
			case encryptionPriv = "encryption_priv"
			case index
			case pathSecrets = "path_secrets"
			case signaturePriv = "signature_priv"
		}
	}

	public struct UpdatePathRecord: Decodable, Sendable {
		public let commitSecret: HexData
		/// One entry per leaf, in leaf-index order; `nil` at the sender's
		/// own position (and at any other leaf excluded from encryption).
		public let pathSecrets: [HexData?]
		public let sender: UInt32
		public let treeHashAfter: HexData
		public let updatePath: HexData

		enum CodingKeys: String, CodingKey {
			case commitSecret = "commit_secret"
			case pathSecrets = "path_secrets"
			case sender
			case treeHashAfter = "tree_hash_after"
			case updatePath = "update_path"
		}
	}

	public let cipherSuite: UInt16
	public let confirmedTranscriptHash: HexData
	public let epoch: UInt64
	public let groupID: HexData
	public let leavesPrivate: [LeafPrivate]
	public let ratchetTree: HexData
	public let updatePaths: [UpdatePathRecord]

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case confirmedTranscriptHash = "confirmed_transcript_hash"
		case epoch
		case groupID = "group_id"
		case leavesPrivate = "leaves_private"
		case ratchetTree = "ratchet_tree"
		case updatePaths = "update_paths"
	}
}
