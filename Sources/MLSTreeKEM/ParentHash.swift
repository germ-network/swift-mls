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
	///
	/// ``validateUnmergedLeaves()`` runs first: it needs no hashing, so an
	/// invalid `unmerged_leaves` list is rejected before any hash is computed,
	/// and the filtered subtree hashes below can rely on every list being
	/// ascending and naming only leaves under its own parent.
	public func validateParentHashChain(_ provider: any MLS.CipherSuiteProvider) throws {
		try validateUnmergedLeaves()
		var toValidate = Set<UInt32>()
		for i in stride(from: UInt32(1), to: serializedNodeCount, by: 2) {
			if parent(at: i) != nil { toValidate.insert(i) }
		}
		var memo = ChainMemo()
		for (leafIndex, _) in nonBlankLeaves() {
			try validateChain(
				from: 2 * leafIndex.value, provider, toValidate: &toValidate,
				memo: &memo)
		}
		guard toValidate.isEmpty else { throw MLS.TreeKEM.TreeError.parentHashMismatch }
	}

	/// `origin` is the node whose chain we're walking (fixed for the whole
	/// call); `n` is the current position in that chain, which becomes an
	/// ancestor (`ancestor`) once we walk up past any blanks to find the
	/// next non-blank parent to check.
	private func validateChain(
		from origin: UInt32, _ provider: any MLS.CipherSuiteProvider,
		toValidate: inout Set<UInt32>, memo: inout ChainMemo
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

			// Depends only on the ancestor and which child is the copath
			// child, so every chain through this ancestor's side shares one
			// computation. Looked up before any work proportional to the
			// ancestor's `unmerged_leaves` or the subtree's size.
			let calculated: Data
			if let cached = memo.calculated[copathChild] {
				calculated = cached
			} else {
				let originalSiblingHash = try originalSiblingTreeHash(
					copathChild, unmergedLeavesOf: ancestorNode, provider,
					memo: &memo)
				calculated = try MLS.TreeKEM.parentHash(
					publicKey: ancestorNode.encryptionKey,
					parentHash: ancestorNode.parentHash,
					originalSiblingTreeHash: originalSiblingHash, provider)
				memo.calculated[copathChild] = calculated
			}

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
			let subtreeSpan = (UInt32(1) << UInt32((~c).trailingZeroBitCount)) - 1
			let subtree = (c - subtreeSpan)...(c + subtreeSpan)
			let ancestorUnmergedInSubtree = Set(
				ancestorNode.unmergedLeaves.map { 2 * $0.value }.filter(
					subtree.contains))
			guard cResolution == ancestorUnmergedInSubtree else {
				throw MLS.TreeKEM.TreeError.parentHashMismatch
			}

			guard toValidate.remove(ancestor) != nil else {
				throw MLS.TreeKEM.TreeError.parentHashCoveredTwice
			}

			n = ancestor
		}
	}

	/// Hashes memoised across one `validateParentHashChain` call.
	private struct ChainMemo {
		/// The parent hash an ancestor computes for the chain through the
		/// given copath child, keyed by that child.
		var calculated: [UInt32: Data] = [:]
		/// Unfiltered subtree hashes of children of non-blank parents, so
		/// memory stays proportional to the non-blank parents.
		var subtreeHash: [UInt32: Data] = [:]
	}

	/// The tree hash of `index`'s subtree before the leaves its parent lists
	/// as unmerged were added (RFC 9420 §7.9's `original_sibling_tree_hash`).
	private func originalSiblingTreeHash(
		_ index: UInt32, unmergedLeavesOf ancestor: MLS.TreeKEM.ParentNode,
		_ provider: any MLS.CipherSuiteProvider, memo: inout ChainMemo
	) throws -> Data {
		let span = (UInt32(1) << UInt32((~index).trailingZeroBitCount)) - 1
		let listed = ancestor.unmergedLeaves.map(\.value)[...]
		let filter = listed.drop { $0 < (index - span) / 2 }.prefix {
			$0 <= (index + span) / 2
		}
		return try subtreeHash(
			at: index, withoutLeaves: filter, parentIsNonBlank: true, provider,
			memo: &memo)
	}

	/// Tree hash of `index`'s subtree with `filter` (sorted leaf indices, all
	/// inside the subtree) treated as blank and unlisted. Only subtrees that
	/// contain a filtered leaf are rehashed; the rest are taken unfiltered.
	/// Matches ``treeHash(at:filteredUnmergedLeaves:_:)`` for any tree that
	/// passes ``validateUnmergedLeaves()``: every `unmerged_leaves` list is
	/// ascending and names only leaves under its own parent, so a subtree
	/// holding no filtered leaf hashes the same filtered or not.
	private func subtreeHash(
		at index: UInt32, withoutLeaves filter: ArraySlice<UInt32>, parentIsNonBlank: Bool,
		_ provider: any MLS.CipherSuiteProvider, memo: inout ChainMemo
	) throws -> Data {
		if filter.isEmpty, let cached = memo.subtreeHash[index] { return cached }
		let hash: Data
		if MLS.TreeMath.isLeaf(index) {
			let leafIndex = MLS.LeafIndex(value: index / 2)
			hash = try Self.leafHash(
				leafIndex, record: filter.isEmpty ? leaf(at: leafIndex) : nil,
				provider)
		} else {
			var parentNode = parent(at: index)
			if !filter.isEmpty {
				parentNode?.unmergedLeaves.removeAll {
					filter.binarySearchContains($0.value)
				}
			}
			let firstRightLeaf = (index + 1) / 2
			let split = filter.partitionPoint { $0 >= firstRightLeaf }
			let isNonBlank = parentNode != nil
			let left = try subtreeHash(
				at: MLS.TreeMath.left(index), withoutLeaves: filter[..<split],
				parentIsNonBlank: isNonBlank, provider, memo: &memo)
			let right = try subtreeHash(
				at: MLS.TreeMath.right(index), withoutLeaves: filter[split...],
				parentIsNonBlank: isNonBlank, provider, memo: &memo)
			hash = try Self.parentNodeHash(parentNode, left, right, provider)
		}
		if filter.isEmpty && parentIsNonBlank { memo.subtreeHash[index] = hash }
		return hash
	}
}

extension ArraySlice where Element == UInt32 {
	/// Whether `value` is in this ascending slice.
	fileprivate func binarySearchContains(_ value: UInt32) -> Bool {
		let point = partitionPoint { $0 >= value }
		return point < endIndex && self[point] == value
	}

	/// The first index whose element satisfies `predicate`, given that the
	/// predicate is false then true across the ascending slice.
	fileprivate func partitionPoint(_ predicate: (UInt32) -> Bool) -> Index {
		var low = startIndex
		var high = endIndex
		while low < high {
			let mid = low + (high - low) / 2
			if predicate(self[mid]) { high = mid } else { low = mid + 1 }
		}
		return low
	}
}
