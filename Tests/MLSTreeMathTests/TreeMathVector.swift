public struct TreeMathVector: Decodable, Sendable {
	public let nLeaves: UInt32
	public let nNodes: UInt32
	public let root: UInt32
	public let left: [UInt32?]
	public let right: [UInt32?]
	public let parent: [UInt32?]
	public let sibling: [UInt32?]

	enum CodingKeys: String, CodingKey {
		case nLeaves = "n_leaves"
		case nNodes = "n_nodes"
		case root, left, right, parent, sibling
	}
}
