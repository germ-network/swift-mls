import MLSCodec
import MLSTreeKEM

extension MLS.RFC9420.UpdatePathNode {
	public var pathNode: MLS.TreeKEM.PathNode {
		.init(encryptionKey: encryptionKey, encryptedPathSecrets: encryptedPathSecret)
	}

	public init(_ pathNode: MLS.TreeKEM.PathNode) {
		self.init(
			encryptionKey: pathNode.encryptionKey,
			encryptedPathSecret: pathNode.encryptedPathSecrets)
	}
}
