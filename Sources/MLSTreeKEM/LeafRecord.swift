import Foundation
import MLSCodec
import MLSCrypto

extension MLS.TreeKEM {
	/// Everything the ratchet-tree algorithms read from a leaf, plus the
	/// leaf's exact wire encoding — which the tree hash covers verbatim
	/// (`optional<LeafNode>`, byte-for-byte).
	///
	/// This is a *projection* of the profile's `LeafNode`, not `LeafNode`
	/// itself: `MLSTreeKEM` must not depend on `MLSProfileRFC9420` — phase 5
	/// puts commit application in that profile target, which would call
	/// into `MLSTreeKEM`, and a dependency the other way would be a cycle.
	/// Reusability follows from the same fact: `MLS.Slim`'s leaf differs
	/// from RFC 9420's, and a `RatchetTree` built from this projection
	/// needs no changes to work with either.
	///
	/// `encryptionKey`/`parentHash` are redundant with `encoded` — both are
	/// also encoded inside it — which is a real de-sync hazard if anything
	/// could construct one by hand. Fields are `let`, reachable only
	/// through `init(_:)`, so a profile builds exactly one of these per
	/// leaf, always from its own already-signed `LeafNode`'s three
	/// matching fields.
	public struct LeafRecord: Sendable, Equatable {
		public let encryptionKey: MLS.HpkePublicKey
		/// nil iff the leaf's `leaf_node_source != commit` — a leaf that
		/// didn't just author a path has nothing to check its parent hash
		/// against yet.
		public let parentHash: Data?
		/// The profile's encoded `LeafNode`, byte-for-byte.
		public let encoded: Data

		public init(encryptionKey: MLS.HpkePublicKey, parentHash: Data?, encoded: Data) {
			self.encryptionKey = encryptionKey
			self.parentHash = parentHash
			self.encoded = encoded
		}
	}

	/// `struct { NodeType node_type; select(...){ case leaf: LeafRecord
	/// leaf_node; case parent: ParentNode parent_node; }; } TreeNode;` —
	/// this component's own name for RFC 9420's `Node`, holding a leaf
	/// projection instead of a `LeafNode` (see `LeafRecord`'s doc comment).
	public enum TreeNode: Sendable, Equatable {
		case leaf(LeafRecord)
		case parent(ParentNode)
	}
}
