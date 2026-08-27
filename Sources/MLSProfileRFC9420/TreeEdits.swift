import MLSCodec
import MLSTreeKEM
import MLSTreeMath

extension MLS.RFC9420 {
	public enum TreeEditError: Error, Sendable, Equatable {
		/// `apply` only edits tree structure -- PSK/ReInit/ExternalInit/
		/// GroupContextExtensions proposals don't touch the tree at all,
		/// so passing one here is a caller error, not a malformed commit.
		case notATreeEditingProposal
	}
}

extension MLS.TreeKEM.RatchetTree {
	/// Applies one already-validated Add/Update/Remove proposal, sent by
	/// `sender`, to `self`. Mechanism lives here (in the profile) rather
	/// than in `MLSTreeKEM`, since it consumes `Proposal`/`LeafNode` —
	/// `MLSTreeKEM` only supplies the primitives this is built from
	/// (`insertLeaf`, `setLeaf`, `blankLeafAndDirectPath`,
	/// `addUnmergedLeaf`, `trim`).
	///
	/// Proposal validation (does the sender have permission, is the tree
	/// state consistent with the proposal) is *not* this function's job —
	/// per GER-2295's scope, that's phase 6 (commit construction/
	/// application). This applies a proposal already taken as valid,
	/// exactly what `tree-operations.json` exercises.
	public mutating func apply(_ proposal: MLS.RFC9420.Proposal, sender: MLS.LeafIndex) throws {
		switch proposal {
		case .add(let keyPackage):
			let newIndex = insertLeaf(try keyPackage.leafNode.record)
			for step in MLS.TreeMath.directPath(
				from: 2 * newIndex.value, leafCount: leafCount)
			{
				try addUnmergedLeaf(newIndex, to: step.path)
			}
		case .update(let leafNode):
			// The leaf gets the *new* LeafNode, not a blank -- only the
			// ancestor chain (whose keys nobody can vouch for against the
			// member's new encryption key) goes blank.
			setLeaf(sender, to: try leafNode.record)
			blankDirectPath(of: sender)
		case .remove(let removed):
			blankLeafAndDirectPath(removed)
		case .preSharedKey, .reInit, .externalInit, .groupContextExtensions:
			throw MLS.RFC9420.TreeEditError.notATreeEditingProposal
		}
		trim()
	}
}
