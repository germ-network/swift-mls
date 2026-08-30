public struct MessagesVector: Decodable, Sendable {
	public let mlsWelcome: HexData
	public let mlsGroupInfo: HexData
	public let mlsKeyPackage: HexData
	public let ratchetTree: HexData
	public let groupSecrets: HexData
	public let addProposal: HexData
	public let updateProposal: HexData
	public let removeProposal: HexData
	public let preSharedKeyProposal: HexData
	public let reInitProposal: HexData
	public let externalInitProposal: HexData
	public let groupContextExtensionsProposal: HexData
	public let commit: HexData
	public let publicMessageApplication: HexData
	public let publicMessageProposal: HexData
	public let publicMessageCommit: HexData
	public let privateMessage: HexData

	enum CodingKeys: String, CodingKey {
		case mlsWelcome = "mls_welcome"
		case mlsGroupInfo = "mls_group_info"
		case mlsKeyPackage = "mls_key_package"
		case ratchetTree = "ratchet_tree"
		case groupSecrets = "group_secrets"
		case addProposal = "add_proposal"
		case updateProposal = "update_proposal"
		case removeProposal = "remove_proposal"
		case preSharedKeyProposal = "pre_shared_key_proposal"
		case reInitProposal = "re_init_proposal"
		case externalInitProposal = "external_init_proposal"
		case groupContextExtensionsProposal = "group_context_extensions_proposal"
		case commit
		case publicMessageApplication = "public_message_application"
		case publicMessageProposal = "public_message_proposal"
		case publicMessageCommit = "public_message_commit"
		case privateMessage = "private_message"
	}
}
