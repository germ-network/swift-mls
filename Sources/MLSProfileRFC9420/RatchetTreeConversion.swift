import Foundation
import MLSCodec
import MLSTreeKEM
import MLSTreeMath

extension MLS.RFC9420.LeafNode {
	var record: MLS.TreeKEM.LeafRecord {
		get throws {
			let parentHash: Data?
			if case .commit(let hash) = source {
				parentHash = hash
			} else {
				parentHash = nil
			}
			return MLS.TreeKEM.LeafRecord(
				encryptionKey: encryptionKey, parentHash: parentHash,
				encoded: try mlsEncoded())
		}
	}
}

extension MLS.TreeKEM.RatchetTree {
	/// `optional<Node> ratchet_tree<V>` decodes into this profile's `Node`
	/// enum first (only it knows how to self-delimit a `LeafNode`, which
	/// carries no length prefix on the wire), then converts to a
	/// `RatchetTree` — `MLSTreeKEM` itself never sees a `Node` or a
	/// `LeafNode`. `MLSTreeKEM`'s own `RatchetTree.init(nodes:)` is the
	/// single place that validates the array length implies a legal
	/// padded leaf count; this initializer adds nothing on top of that.
	public init(_ nodes: [MLS.RFC9420.Node?]) throws {
		try self.init(
			nodes: try nodes.map { node in
				switch node {
				case nil: return nil
				case .leaf(let leafNode): return .leaf(try leafNode.record)
				case .parent(let parentNode): return .parent(parentNode)
				}
			})
	}

	/// The reverse of `init(_:)` — decodes each leaf's `LeafRecord.encoded`
	/// bytes back into a real `LeafNode`, over exactly the tree's current
	/// physical array (`physicalNodeCount`, not the padded `nodeCount`),
	/// so a tree left un-trimmed round-trips its actual blanks and a
	/// trimmed one round-trips its actual shorter length.
	public var nodes: [MLS.RFC9420.Node?] {
		get throws {
			try (0..<physicalNodeCount).map { i in
				if MLS.TreeMath.isLeaf(i) {
					guard let record = leaf(at: .init(value: i / 2)) else {
						return nil
					}
					return .leaf(
						try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
					)
				}
				guard let parentNode = parent(at: i) else { return nil }
				return .parent(parentNode)
			}
		}
	}
}
