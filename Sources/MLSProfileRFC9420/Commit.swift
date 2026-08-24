import Foundation
import MLSCodec
import MLSCrypto

extension MLS.RFC9420 {
	/// `struct { HPKEPublicKey encryption_key; HPKECiphertext
	/// encrypted_path_secret<V>; } UpdatePathNode;`
	public struct UpdatePathNode: Sendable, Equatable, MLSCodable {
		public var encryptionKey: MLS.HpkePublicKey
		public var encryptedPathSecret: [MLS.HpkeCiphertext]

		public init(
			encryptionKey: MLS.HpkePublicKey, encryptedPathSecret: [MLS.HpkeCiphertext]
		) {
			self.encryptionKey = encryptionKey
			self.encryptedPathSecret = encryptedPathSecret
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try encryptionKey.encode(to: &writer)
			try writer.encodeVector(encryptedPathSecret)
		}

		public init(from reader: inout MLS.Reader) throws {
			encryptionKey = try MLS.HpkePublicKey(from: &reader)
			encryptedPathSecret = try reader.decodeVector()
		}
	}

	/// `struct { LeafNode leaf_node; UpdatePathNode nodes<V>; } UpdatePath;`
	///
	/// Fully typed, unlike the `EncodedPathNodes`-opaque seam the original
	/// plan called for. That seam existed so `Commit`/framing could stay
	/// usable with zero `MLSTreeKEM` linked — but `Commit` lives in this
	/// profile target, not in `MLSFraming`, and `UpdatePathNode` itself has
	/// no dependency on any tree-specific type (no `LeafIndex` per node, no
	/// copath structure — just an `HpkePublicKey` and a ciphertext vector,
	/// both already available here via `MLSCrypto`). The concern the seam
	/// addressed doesn't apply to where this type actually ended up.
	/// `messages.json`'s `commit` records need full structural round-trip
	/// fidelity, which a typed `[UpdatePathNode]` gives for free. What
	/// phase 4 still needs, and what stays a phase-4 job regardless of this
	/// type's shape: validating `nodes.count` and each node's
	/// `encryptedPathSecret.count` against the committer's actual copath
	/// resolution, which requires tree state this type doesn't and
	/// shouldn't carry.
	public struct UpdatePath: Sendable, Equatable, MLSCodable {
		public var leafNode: LeafNode
		public var nodes: [UpdatePathNode]

		public init(leafNode: LeafNode, nodes: [UpdatePathNode]) {
			self.leafNode = leafNode
			self.nodes = nodes
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try leafNode.encode(to: &writer)
			try writer.encodeVector(nodes)
		}

		public init(from reader: inout MLS.Reader) throws {
			leafNode = try MLS.RFC9420.LeafNode(from: &reader)
			nodes = try reader.decodeVector()
		}
	}

	/// `struct { ProposalOrRef proposals<V>; optional<UpdatePath> path; } Commit;`
	public struct Commit: Sendable, Equatable, MLSCodable {
		public var proposals: [ProposalOrRef]
		public var path: UpdatePath?

		public init(proposals: [ProposalOrRef], path: UpdatePath?) {
			self.proposals = proposals
			self.path = path
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encodeVector(proposals)
			try writer.encodeOptional(path)
		}

		public init(from reader: inout MLS.Reader) throws {
			proposals = try reader.decodeVector()
			path = try reader.decodeOptional()
		}
	}
}
