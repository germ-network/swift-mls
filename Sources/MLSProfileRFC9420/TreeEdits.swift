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
	/// `addUnmergedLeaf`, `truncate`).
	///
	/// Proposal validation (does the sender have permission, is the tree
	/// state consistent with the proposal) is *not* this function's job —
	/// that's `validateProposalList` (commit construction/
	/// application). This applies a proposal already taken as valid,
	/// exactly what `tree-operations.json` exercises.
	/// Returns the leaf index an Add landed on (nil for every other
	/// proposal) — positional truth from `insertLeaf` itself, so callers
	/// never re-derive it by content matching, which is only sound while
	/// leaves are unique and the uniqueness sweep runs later.
	@discardableResult
	public mutating func apply(_ proposal: MLS.RFC9420.Proposal, sender: MLS.LeafIndex)
		throws -> MLS.LeafIndex?
	{
		var addedIndex: MLS.LeafIndex?
		switch proposal {
		case .add(let keyPackage):
			let newIndex = try insertLeaf(keyPackage.leafNode.record)
			for step in MLS.TreeMath.directPath(
				from: 2 * newIndex.value, leafCount: leafCount)
			{
				try addUnmergedLeaf(newIndex, to: step.path)
			}
			addedIndex = newIndex
		case .update(let leafNode):
			// The leaf gets the *new* LeafNode, not a blank -- only the
			// ancestor chain (whose keys nobody can vouch for against the
			// member's new encryption key) goes blank.
			try setLeaf(sender, to: leafNode.record)
			try blankDirectPath(of: sender)
		case .remove(let removed):
			try blankLeafAndDirectPath(removed)
		case .preSharedKey, .reInit, .externalInit, .groupContextExtensions,
			.appDataUpdate:
			throw MLS.RFC9420.TreeEditError.notATreeEditingProposal
		}
		truncate()
		return addedIndex
	}
}
