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

extension MLS.RFC9420 {
	/// RFC 9420 §12.4.3.3: a serialized ratchet tree MUST NOT carry blank
	/// nodes after the last non-blank one. Checked on the **wire** array, not
	/// on a decoded `RatchetTree`: a trailing blank inflates the padded leaf
	/// count (`RatchetTree.init(nodes:)` rounds the array length up), so the
	/// padded, full-width tree can no longer tell whether the wire ended in a
	/// blank — the check has to run before construction. An empty array is
	/// rejected too. Kept explicit rather than folded into decode so a
	/// malformed tree is rejected, not silently normalized.
	public static func validateNoTrailingBlank(_ nodes: [MLS.RFC9420.Node?]) throws {
		guard let last = nodes.last else { throw MLS.TreeKEM.TreeError.emptyTree }
		guard last != nil else { throw MLS.TreeKEM.TreeError.trailingBlankLeaves }
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
	/// bytes back into a real `LeafNode`, over the tree's content up to the
	/// last non-blank node (`serializedNodeCount`). This is where the wire's
	/// trailing-blank trimming happens: the in-memory tree is full width, and
	/// emitting `0..<serializedNodeCount` drops the padding, so the bytes match
	/// what a well-formed peer sent (RFC 9420 §12.4.3.3, the byte-exact
	/// `tree_after` gate).
	public var nodes: [MLS.RFC9420.Node?] {
		get throws {
			try (0..<serializedNodeCount).map { i in
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
