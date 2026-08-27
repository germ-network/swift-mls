import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM {
	/// `struct { HPKEPublicKey encryption_key; opaque parent_hash<V>;
	/// uint32 unmerged_leaves<V>; } ParentNode;`
	///
	/// Lives here, not in the profile, because §7.9's parent-hash chain
	/// needs to re-encode a *filtered* copy of this type for
	/// `original_sibling_tree_hash` (§7.8's tree hash re-encodes it
	/// unfiltered): an ancestor's own unmerged leaves get blanked and
	/// removed from parents' `unmerged_leaves` lists. `MLSTreeKEM` needs
	/// its own encoder either way, and a second one in the profile would
	/// be a byte-exactness hazard against this one. `MLSProfileRFC9420`
	/// keeps a `public typealias ParentNode = MLS.TreeKEM.ParentNode` so
	/// callers there never notice.
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
}
