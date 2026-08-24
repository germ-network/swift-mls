import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.RFC9420 {
	/// `struct { HPKEPublicKey encryption_key; opaque parent_hash<V>;
	/// LeafIndex unmerged_leaves<V>; } ParentNode;`
	public struct ParentNode: Sendable, Equatable, MLSCodable {
		public var encryptionKey: MLS.HpkePublicKey
		public var parentHash: Data
		public var unmergedLeaves: [MLS.LeafIndex]

		public init(
			encryptionKey: MLS.HpkePublicKey, parentHash: Data,
			unmergedLeaves: [MLS.LeafIndex]
		) {
			self.encryptionKey = encryptionKey
			self.parentHash = parentHash
			self.unmergedLeaves = unmergedLeaves
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try encryptionKey.encode(to: &writer)
			try writer.writeOpaque(parentHash)
			try writer.encodeVector(unmergedLeaves)
		}

		public init(from reader: inout MLS.Reader) throws {
			encryptionKey = try MLS.HpkePublicKey(from: &reader)
			parentHash = Data(try reader.readOpaque())
			unmergedLeaves = try reader.decodeVector()
		}
	}

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
	/// never "no node"; `[Node?]` at the call site covers the rest. Types
	/// only, per this phase's scope: no tree-hash, parent-hash, or
	/// resolution algorithms — those are phase 4 (`MLSTreeKEM`)'s job, and
	/// nothing here presumes how they'll be built.
	public enum Node: Sendable, Equatable {
		case leaf(LeafNode)
		case parent(ParentNode)
	}
}

extension MLS.RFC9420.Node: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .leaf(let leafNode):
			try MLS.RFC9420.NodeType.leaf.encode(to: &writer)
			try leafNode.encode(to: &writer)
		case .parent(let parentNode):
			try MLS.RFC9420.NodeType.parent.encode(to: &writer)
			try parentNode.encode(to: &writer)
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
