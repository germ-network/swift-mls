import MLSCodec

extension MLS.TreeKEM {
	public enum TreeError: Error, Sendable, Equatable {
		/// A tree slot's node type doesn't match its array position's
		/// parity (a leaf at an odd index, or a parent at an even one).
		case wrongNodeKind(index: UInt32)
		/// `UpdatePath.nodes.count` didn't equal the sender's filtered
		/// direct-path length -- in either direction. RFC 9420 defines the
		/// filtered direct path deterministically from the tree the sender
		/// and receiver both already agree on, so this count is never
		/// ambiguous; a mismatch means a malformed or malicious `Commit`.
		case wrongPathNodeCount(expected: Int, actual: Int)
		/// One `UpdatePathNode`'s ciphertext count didn't equal its
		/// copath resolution's size (minus any leaves excluded because
		/// they were added in this same commit). Checked explicitly here
		/// because nothing upstream of tree processing can check it --
		/// this is exactly the validation `Commit.path`'s wire types were
		/// split out to require.
		case wrongCiphertextCount(pathIndex: Int, expected: Int, actual: Int)
		/// A derived HPKE public key didn't match the key it was checked
		/// against -- the wire `UpdatePathNode.encryptionKey` during
		/// decap, or the tree's own stored key while installing a
		/// `Welcome`'s path secrets. Either way: the sender and receiver
		/// disagree about the tree, or the path secret was tampered with.
		case publicKeyMismatch
		case parentHashMismatch
		/// A parent's `parent_hash` was checked against more than one
		/// non-blank leaf's chain -- every non-blank parent with a
		/// non-empty parent hash must be covered by exactly one leaf.
		case parentHashCoveredTwice
		case treeHashMismatch
		case unmergedLeavesNotSorted
		case unmergedLeafNotAtExpectedPosition
		case duplicateUnmergedLeaf
		/// An encryption key appears at more than one node in the tree --
		/// checked by `validateNoDuplicateEncryptionKeys`, whose doc
		/// comment carries the three sections this spans (§12.4.3.1 for
		/// parents, §7.3 for leaves, §16.7 for the general form).
		case duplicateEncryptionKey(node: UInt32)
		/// The tree's last node is blank -- RFC 9420 §12.4.3.3: "the sender
		/// MUST NOT include blank nodes after the last non-blank node. The
		/// receiver MUST check that the last node in ratchet_tree is
		/// non-blank." (Remove also truncates trailing all-blank subtrees,
		/// §12.1.3 -- but that alone doesn't rule out a trailing blank
		/// leaf, only an all-blank trailing subtree; this wire check is
		/// the actual invariant being enforced here.)
		case trailingBlankLeaves
		case emptyTree
		/// The receiver's own leaf isn't in this tree at all, or is blank.
		case notAMember
	}
}
