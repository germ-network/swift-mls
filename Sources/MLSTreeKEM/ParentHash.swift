import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM {
	/// RFC 9420 §7.9: `ParentHashInput = HPKEPublicKey encryption_key;
	/// opaque parent_hash<V>; opaque original_sibling_tree_hash<V>;`
	static func parentHash(
		publicKey: MLS.HpkePublicKey, parentHash: Data, originalSiblingTreeHash: Data,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> Data {
		var writer = MLS.Writer()
		try publicKey.encode(to: &writer)
		try writer.writeOpaque(parentHash)
		try writer.writeOpaque(originalSiblingTreeHash)
		return try provider.hash(Data(writer.bytes))
	}
}

extension MLS.TreeKEM.RatchetTree {
	/// Computes the parent-hash chain for `leafIndex`'s own new commit
	/// path: walks the *direct copath* root-down, chaining each level's
	/// parent hash into the next, and installs the result into each
	/// parent node along the way (`parent.parentHash = ` the hash computed
	/// one level closer to the root — empty at the topmost node, which
	/// has nothing above it to chain from). The value that falls out at
	/// the bottom is the leaf's own `parent_hash`.
	///
	/// A blank copath child contributes nothing (its resolution is empty,
	/// so nobody would be encrypting a path secret to it) — those direct-
	/// path entries are skipped, exactly `filteredDirectPath`'s `true`
	/// positions. No filtering is needed here: the committer just cleared
	/// their own path's parent nodes' `unmergedLeaves` (RFC 9420's commit
	/// construction step, done by the caller before this runs), so there
	/// is nothing stale for `original_sibling_tree_hash` to filter out —
	/// this is the *build* direction; filtering only matters when
	/// *validating* an existing chain, in `validateParentHashChain` below.
	public mutating func parentHashForLeaf(
		_ leafIndex: MLS.LeafIndex, _ provider: any MLS.CipherSuiteProvider
	) throws -> Data {
		var hash = Data()
		let path = MLS.TreeMath.directPath(
			from: 2 * leafIndex.value, leafCount: leafCount)
		for step in path.reversed() {
			guard !resolution(of: step.sibling).isEmpty else { continue }
			// Both current callers (`beginCommitPath`, `applyUpdatePath`)
			// always install a parent at every unfiltered position before
			// reaching here -- a blank one at this point is a caller
			// contract violation, not a legitimate "nothing to do" case
			// (mls-rs's `borrow_as_parent_mut` errors here too, it doesn't
			// skip).
			guard var parentNode = parent(at: step.path) else {
				throw MLS.TreeKEM.TreeError.notAMember
			}
			let siblingHash = try treeHash(at: step.sibling, provider)
			let calculated = try MLS.TreeKEM.parentHash(
				publicKey: parentNode.encryptionKey, parentHash: hash,
				originalSiblingTreeHash: siblingHash, provider)
			parentNode.parentHash = hash
			try setParent(step.path, to: parentNode)
			hash = calculated
		}
		return hash
	}

	/// RFC 9420 §7.9.2's parent-hash chain validation, done "bottom up":
	/// "verifying that all non-blank parent nodes are covered by exactly
	/// one such chain," walked leaf-to-root. *Every* non-blank parent
	/// needs coverage, the root included -- a node's own `parent_hash`
	/// being empty (as a chain's topmost node's always is) says nothing
	/// about whether some descendant's hash chains up to it, which is
	/// what "covered" means.
	///
	/// A chain ends (without error) the moment a hash doesn't match —
	/// that's simply as far as the most recent committer through that
	/// region got. What makes an unmatched node an error is the coverage
	/// sweep at the end, not the mismatch itself.
	public func validateParentHashChain(_ provider: any MLS.CipherSuiteProvider) throws {
		var toValidate = Set<UInt32>()
		for i in stride(from: UInt32(1), to: physicalNodeCount, by: 2) {
			if parent(at: i) != nil { toValidate.insert(i) }
		}
		for (leafIndex, _) in nonBlankLeaves() {
			try validateChain(
				from: 2 * leafIndex.value, provider, toValidate: &toValidate)
		}
		guard toValidate.isEmpty else { throw MLS.TreeKEM.TreeError.parentHashMismatch }
	}

	/// `origin` is the node whose chain we're walking (fixed for the whole
	/// call); `n` is the current position in that chain, which becomes an
	/// ancestor (`ancestor`) once we walk up past any blanks to find the
	/// next non-blank parent to check.
	private func validateChain(
		from origin: UInt32, _ provider: any MLS.CipherSuiteProvider,
		toValidate: inout Set<UInt32>
	) throws {
		var n = origin
		while let immediateParent = MLS.TreeMath.parent(n, leafCount: leafCount) {
			var ancestor = immediateParent
			var copathChild = MLS.TreeMath.sibling(n, leafCount: leafCount)!
			while isBlank(at: ancestor) {
				guard
					let nextAncestor = MLS.TreeMath.parent(
						ancestor, leafCount: leafCount)
				else {
					// reached the root while still blank: done with this chain
					return
				}
				copathChild = MLS.TreeMath.sibling(ancestor, leafCount: leafCount)!
				ancestor = nextAncestor
			}

			guard let ancestorNode = parent(at: ancestor) else {
				throw MLS.TreeKEM.TreeError.notAMember
			}
			let claimed: Data?
			if MLS.TreeMath.isLeaf(n) {
				claimed = leaf(at: .init(value: n / 2))?.parentHash
			} else {
				claimed = parent(at: n)?.parentHash
			}

			let filter = Set(ancestorNode.unmergedLeaves)
			let originalSiblingHash = try treeHash(
				at: copathChild, filteredUnmergedLeaves: filter, provider)
			let calculated = try MLS.TreeKEM.parentHash(
				publicKey: ancestorNode.encryptionKey,
				parentHash: ancestorNode.parentHash,
				originalSiblingTreeHash: originalSiblingHash, provider)

			// A mismatch means the chain simply ends here -- not an error.
			guard claimed == calculated else { return }

			// "n is in the resolution of c, and the intersection of the
			// ancestor's unmergedLeaves with c's subtree equals the
			// resolution of c with n removed" -- c is copathChild's
			// sibling, i.e. the child of `ancestor` on the same side as
			// the blank-walk we just did (so c == n when no blanks were
			// skipped, or a blank ancestor of n otherwise).
			guard let c = MLS.TreeMath.sibling(copathChild, leafCount: leafCount) else {
				throw MLS.TreeKEM.TreeError.parentHashMismatch
			}
			var cResolution = Set(resolution(of: c))
			guard cResolution.remove(n) != nil else {
				throw MLS.TreeKEM.TreeError.parentHashMismatch
			}
			let ancestorUnmergedInSubtree = Set(
				ancestorNode.unmergedLeaves.map { 2 * $0.value }.filter {
					isDescendant($0, ofSubtreeRootedAt: c)
				})
			guard cResolution == ancestorUnmergedInSubtree else {
				throw MLS.TreeKEM.TreeError.parentHashMismatch
			}

			guard toValidate.remove(ancestor) != nil else {
				throw MLS.TreeKEM.TreeError.parentHashCoveredTwice
			}

			n = ancestor
		}
	}

	private func isDescendant(_ node: UInt32, ofSubtreeRootedAt root: UInt32) -> Bool {
		if node == root { return true }
		guard !MLS.TreeMath.isLeaf(root) else { return false }
		return isDescendant(node, ofSubtreeRootedAt: MLS.TreeMath.left(root))
			|| isDescendant(node, ofSubtreeRootedAt: MLS.TreeMath.right(root))
	}
}
