import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSTreeMath

extension MLS.RFC9420 {
	/// `ParentNode` itself lives in `MLSTreeKEM` (see that file's doc
	/// comment) — the tree hash needs to re-encode a *filtered* copy of it,
	/// so the encoder has to live where that filtering happens. This
	/// typealias means nothing here ever has to say `MLS.TreeKEM.ParentNode`.
	public typealias ParentNode = MLS.TreeKEM.ParentNode

	/// `enum { reserved(0), leaf(1), parent(2), (255) } NodeType;`
	public enum NodeType: UInt8, MLSClosedEnum {
		case leaf = 1
		case parent = 2
	}

	/// `struct { NodeType node_type; select(...){ case leaf: LeafNode
	/// leaf_node; case parent: ParentNode parent_node; }; } Node;`
	///
	/// `ratchet_tree`'s wire form is `optional<Node> ratchet_tree<V>` — a
	/// vector of *optional* nodes (blank tree slots are absent, not a
	/// third `Node` case) — so this type only needs to represent "a node,"
	/// never "no node"; `[Node?]` at the call site covers the rest.
	///
	/// `MLSTreeKEM`'s `RatchetTree` stores a `LeafRecord` projection at each
	/// leaf slot, not a `LeafNode` directly (see that type's doc comment),
	/// so converting between `[Node?]` and a `RatchetTree` is this file's
	/// job, not `MLSTreeKEM`'s — see `RatchetTreeConversion.swift`. A
	/// `LeafNode` has no length prefix on the wire, so it can't be skipped
	/// without parsing it; only the profile, which knows `LeafNode`'s
	/// shape, can do that.
	public enum Node: Sendable, Equatable {
		case leaf(LeafNode)
		case parent(ParentNode)
	}
}

extension MLS.RFC9420.Node: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .leaf(let leafNode):
			try writer.encode(MLS.RFC9420.NodeType.leaf)
			try writer.encode(leafNode)
		case .parent(let parentNode):
			try writer.encode(MLS.RFC9420.NodeType.parent)
			try writer.encode(parentNode)
		}
	}
}

extension MLS.RFC9420.Node: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		switch try MLS.RFC9420.NodeType(from: &reader) {
		case .leaf: self = .leaf(try MLS.RFC9420.LeafNode(from: &reader))
		case .parent: self = .parent(try MLS.RFC9420.ParentNode(from: &reader))
		}
	}
}
