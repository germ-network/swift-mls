import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// RFC 9420 §7.8: `TreeHashInput` is a tagged union —
	/// `struct { LeafIndex leaf_index; optional<LeafNode> leaf_node; }`
	/// for a leaf (tag 1), `struct { optional<ParentNode> parent_node;
	/// opaque left_hash<V>; opaque right_hash<V>; }` for a parent (tag 2)
	/// — hashed bottom-up: a parent's hash covers its already-computed
	/// children's hashes, so this recurses down and hashes on the way back
	/// up rather than needing an explicit post-order queue.
	///
	/// `filteredUnmergedLeaves`, when non-nil, reconstructs what the hash
	/// would have been *before* these specific leaves existed in the tree
	/// at all: a filtered leaf hashes as blank (not just present-but-
	/// unlisted), and every parent's `unmerged_leaves` also drops them —
	/// the "original tree hash" §7.9's parent-hash chain needs (a leaf
	/// added after some ancestor's chain was last computed shouldn't
	/// affect what that ancestor's chain covers), as opposed to the plain
	/// tree hash `GroupContext.tree_hash` carries (`nil`, no filtering).
	/// Kept as one function with a parameter, not two, since they're the
	/// same algorithm and a second copy would be a byte-exactness hazard
	/// against this one.
	public func treeHash(
		at index: UInt32, filteredUnmergedLeaves: Set<MLS.LeafIndex>? = nil,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> Data {
		var writer = MLS.Writer()
		if MLS.TreeMath.isLeaf(index) {
			writer.writeUInt8(1)
			let leafIndex = MLS.LeafIndex(value: index / 2)
			try leafIndex.encode(to: &writer)
			let record =
				(filteredUnmergedLeaves?.contains(leafIndex) ?? false)
				? nil : leaf(at: leafIndex)
			writer.writeUInt8(record == nil ? 0 : 1)
			if let record { writer.writeBytes(record.encoded) }
		} else {
			writer.writeUInt8(2)
			var parentNode = parent(at: index)
			if let filteredUnmergedLeaves {
				parentNode?.unmergedLeaves.removeAll {
					filteredUnmergedLeaves.contains($0)
				}
			}
			try writer.encodeOptional(parentNode)
			let leftHash = try treeHash(
				at: MLS.TreeMath.left(index),
				filteredUnmergedLeaves: filteredUnmergedLeaves,
				provider)
			let rightHash = try treeHash(
				at: MLS.TreeMath.right(index),
				filteredUnmergedLeaves: filteredUnmergedLeaves,
				provider)
			try writer.writeOpaque(leftHash)
			try writer.writeOpaque(rightHash)
		}
		return try provider.hash(Data(writer.bytes))
	}

	/// The whole tree's hash — `GroupContext.tree_hash`'s value.
	public func treeHash(_ provider: any MLS.CipherSuiteProvider) throws -> Data {
		try treeHash(at: MLS.TreeMath.root(leafCount: leafCount), provider)
	}
}
