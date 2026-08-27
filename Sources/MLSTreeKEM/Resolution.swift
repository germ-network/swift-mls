import MLSCodec
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// RFC 9420 §4.1.1's resolution: a non-blank node contributes itself,
	/// then its unmerged leaves (in the order they're already stored,
	/// ascending); a blank *parent* recurses into both children; a blank
	/// *leaf* contributes nothing. Node indices only — this is the first
	/// algorithm needing actual tree content, unlike anything in
	/// `MLSTreeMath`.
	///
	/// Stack-based (push right then left, so popping visits left before
	/// right) to match mls-rs's `get_resolution_index` exactly, including
	/// its node ordering — resolution order isn't cosmetic, it's what a
	/// sender's copath-resolution encryption and a receiver's ciphertext-
	/// position lookup both have to agree on.
	public func resolution(of index: UInt32) -> [UInt32] {
		var stack = [index]
		var result: [UInt32] = []
		while let current = stack.popLast() {
			if let treeNode = node(at: current) {
				result.append(current)
				if case .parent(let parentNode) = treeNode {
					result.append(
						contentsOf: parentNode.unmergedLeaves.map {
							2 * $0.value
						})
				}
			} else if !MLS.TreeMath.isLeaf(current) {
				stack.append(MLS.TreeMath.right(current))
				stack.append(MLS.TreeMath.left(current))
			}
		}
		return result
	}

	/// RFC 9420 §4.1.2's filtered direct path: `true` at position `i` iff
	/// `directPath[i]`'s copath child has an empty resolution — that
	/// direct-path entry is omitted from the wire `UpdatePath` entirely
	/// (§7.6), since encrypting a path secret to zero recipients has
	/// nothing to encrypt to.
	public func filteredDirectPath(from leafIndex: MLS.LeafIndex) throws -> [Bool] {
		MLS.TreeMath.directPath(from: 2 * leafIndex.value, leafCount: leafCount)
			.map { resolution(of: $0.sibling).isEmpty }
	}
}
