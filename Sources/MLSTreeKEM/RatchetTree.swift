import MLSCodec
import MLSTreeMath

extension MLS.TreeKEM {
	/// RFC 9420's ratchet tree: an array-indexed binary tree (`MLSTreeMath`'s
	/// index arithmetic) whose leaves carry group members (`LeafRecord`)
	/// and whose internal nodes carry `ParentNode`s, either of which may be
	/// blank (`nil`).
	///
	/// The backing array is not always `2 * leafCount - 1` long: RFC 9420
	/// trims trailing blank slots before the tree is serialized (see
	/// `MLS.TreeMath.paddedLeafCount`'s doc comment), so a shorter array is
	/// normal, not malformed. Every accessor below treats an index beyond
	/// the physical array as blank, exactly like a stored `nil`.
	public struct RatchetTree: Sendable, Equatable {
		private var nodes: [TreeNode?]

		/// The padded leaf count implied by the current (possibly trimmed)
		/// array length — recomputed on access, not cached, since it must
		/// always agree with `nodes.count` and mutation never invalidates
		/// that relationship on its own.
		public var leafCount: MLS.LeafCount {
			// **This can trap, and the caller's contract is what stops
			// it.** An earlier version of this comment claimed otherwise --
			// that every grower only reaches tree-math-derived indices, so
			// the array could never exceed what `paddedLeafCount` accepts.
			// That was false. `setLeaf`/`setParent` are public and
			// unconditional by design, and `LeafIndex` is bounded only by
			// its own 2^24 ceiling, never against the tree it indexes. A
			// `setLeaf` at leaf 2^23 pads `nodes` toward 2^25 entries and
			// the next `leafCount` read traps here -- reproduced directly,
			// not argued.
			//
			// The invariant is therefore a *precondition on callers*: an
			// index handed to `setLeaf`/`setParent` must already have been
			// bounded against this tree. `MLS.RFC9420.CommitProcessing`
			// carries that obligation for both wire-supplied indices it
			// applies (`updateFromNonMember`, `removeOfNonMember`).
			//
			// Making it structural instead -- bounding growth inside
			// `setNode` and turning the setters throwing -- is GER-2363.
			// It changes signatures across this module, so it is not
			// bolted on here.
			try! MLS.TreeMath.paddedLeafCount(nodeArrayCount: nodes.count)
		}

		public var nodeCount: UInt32 { MLS.TreeMath.nodeCount(leafCount: leafCount) }

		/// The backing array's actual current length — possibly less than
		/// `nodeCount` (trailing blanks trimmed), possibly more (before a
		/// caller has trimmed a just-edited tree). This is what a byte-exact
		/// re-serialization must iterate, not the padded `nodeCount`.
		public var physicalNodeCount: UInt32 { UInt32(nodes.count) }

		/// Validates the array's length implies a valid padded leaf count
		/// (throwing `MLS.TreeMathError.invalidLeafCount` otherwise) but
		/// does not otherwise check the array's contents — node-kind/slot
		/// parity, parent hashes, and every other content invariant are
		/// `TreeValidation`'s job, run separately once a tree is fully
		/// decoded.
		public init(nodes: [TreeNode?]) throws {
			_ = try MLS.TreeMath.paddedLeafCount(nodeArrayCount: nodes.count)
			self.nodes = nodes
		}

		public init(singleLeaf record: LeafRecord) {
			self.nodes = [.leaf(record)]
		}

		func node(at index: UInt32) -> TreeNode? {
			guard let i = Int(exactly: index), i < nodes.count else { return nil }
			return nodes[i]
		}

		mutating func setNode(at index: UInt32, to value: TreeNode?) {
			if let i = Int(exactly: index), i < nodes.count {
				nodes[i] = value
				return
			}
			// Growing past the current array happens through `insertLeaf`
			// (mirrors mls-rs `NodeVec::insert_leaf`, growing exactly as
			// far as needed) and through `setParent`/`setLeaf` on an index
			// past a trimmed tree's current physical length —
			// `applyUpdatePath` does the latter routinely, since a
			// direct-path ancestor can legitimately sit past where trailing
			// blanks were trimmed away.
			while UInt32(nodes.count) < index { nodes.append(nil) }
			nodes.append(value)
		}

		public func leaf(at index: MLS.LeafIndex) -> LeafRecord? {
			guard case .leaf(let record) = node(at: 2 * index.value) else { return nil }
			return record
		}

		public func parent(at nodeIndex: UInt32) -> ParentNode? {
			guard case .parent(let parentNode) = node(at: nodeIndex) else { return nil }
			return parentNode
		}

		public func isBlank(at nodeIndex: UInt32) -> Bool { node(at: nodeIndex) == nil }

		public mutating func setLeaf(_ index: MLS.LeafIndex, to record: LeafRecord?) {
			setNode(at: 2 * index.value, to: record.map(TreeNode.leaf))
		}

		public mutating func setParent(_ nodeIndex: UInt32, to parentNode: ParentNode?) {
			setNode(at: nodeIndex, to: parentNode.map(TreeNode.parent))
		}

		/// Every non-blank leaf, in ascending index order.
		public func nonBlankLeaves() -> [(index: MLS.LeafIndex, record: LeafRecord)] {
			stride(from: 0, to: leafCount.value, by: 1).compactMap { i in
				let index = MLS.LeafIndex(value: i)
				return leaf(at: index).map { (index, $0) }
			}
		}

		/// Remove nodes from the end of the array while the last one is
		/// blank. RFC 9420 §12.4.3.3 requires the *serialized* form end
		/// non-blank ("the sender MUST NOT include blank nodes after the
		/// last non-blank node"); Remove additionally truncates trailing
		/// all-blank subtrees as part of applying the proposal (§12.1.3).
		/// Load-bearing for byte-exact re-serialization
		/// (`tree-operations.json`'s `tree_after` check) — an untrimmed
		/// tail would round-trip to different bytes than what a
		/// well-formed peer sent.
		public mutating func trim() {
			while nodes.last == .some(nil) { nodes.removeLast() }
		}

		/// Blanks every node on `index`'s direct path — the ancestor chain
		/// only, never the sibling/copath nodes, and never `index`'s own
		/// leaf slot. This is what Update blanks: the leaf itself gets the
		/// *new* `LeafNode` installed instead of going blank, since Update
		/// changes a member's content without removing them.
		public mutating func blankDirectPath(of index: MLS.LeafIndex) {
			for step in MLS.TreeMath.directPath(
				from: 2 * index.value, leafCount: leafCount)
			{
				setNode(at: step.path, to: nil)
			}
		}

		/// Blanks a leaf and every node on its direct path — what Remove
		/// does: the member is gone, so both the leaf and the ancestor
		/// chain (which nobody can re-derive without them) go blank.
		public mutating func blankLeafAndDirectPath(_ index: MLS.LeafIndex) {
			setLeaf(index, to: nil)
			blankDirectPath(of: index)
		}

		/// The leftmost blank leaf at or after `hint` (wrapping is not
		/// RFC 9420 behavior — `hint` only ever narrows the *search start*,
		/// mirroring mls-rs's `add_leaf`), or `nil` if the tree is full and
		/// must grow instead.
		public func leftmostBlankLeaf(
			atOrAfter hint: MLS.LeafIndex = MLS.LeafIndex(value: 0)
		)
			-> MLS.LeafIndex?
		{
			guard hint.value < leafCount.value else { return nil }
			for i in hint.value..<leafCount.value {
				let index = MLS.LeafIndex(value: i)
				if leaf(at: index) == nil { return index }
			}
			return nil
		}

		/// Installs `record` at the leftmost blank leaf at or after `hint`,
		/// or grows the tree by exactly one leaf slot pair if none exists
		/// (mirrors mls-rs `NodeVec::insert_leaf`, which never grows to a
		/// full new power-of-two doubling — only as far as the newly
		/// inserted leaf's own node index requires).
		public mutating func insertLeaf(
			_ record: LeafRecord, hint: MLS.LeafIndex = MLS.LeafIndex(value: 0)
		) -> MLS.LeafIndex {
			if let blank = leftmostBlankLeaf(atOrAfter: hint) {
				setLeaf(blank, to: record)
				return blank
			}
			let newIndex = MLS.LeafIndex(value: leafCount.value)
			setNode(at: 2 * newIndex.value, to: .leaf(record))
			return newIndex
		}

		/// Inserts `leafIndex` into `nodeIndex`'s `unmergedLeaves`, keeping
		/// the list sorted ascending — RFC 9420 §7.1: "The entries in the
		/// unmerged_leaves vector MUST be sorted in increasing order." A
		/// real invariant `TreeValidation` checks, not incidental tidiness
		/// — the RFC states the MUST with no rationale. Throws rather than
		/// silently deduplicating: a duplicate means the caller's own
		/// bookkeeping is wrong, not a normal occurrence.
		public mutating func addUnmergedLeaf(
			_ leafIndex: MLS.LeafIndex, to nodeIndex: UInt32
		)
			throws
		{
			guard var parentNode = parent(at: nodeIndex) else { return }
			let position = parentNode.unmergedLeaves.firstIndex {
				$0.value >= leafIndex.value
			}
			if let position, parentNode.unmergedLeaves[position] == leafIndex {
				throw TreeError.duplicateUnmergedLeaf
			}
			parentNode.unmergedLeaves.insert(
				leafIndex, at: position ?? parentNode.unmergedLeaves.count)
			setParent(nodeIndex, to: parentNode)
		}

		/// Every non-blank slot's node kind (leaf vs. parent) must match
		/// its array index's parity — nothing in the wire format enforces
		/// this on its own, since a `Node`'s type tag travels with the
		/// node itself, independent of where it sits in the vector. A
		/// malicious or corrupt tree can claim a `ParentNode` at an even
		/// (leaf) index; left unchecked, `leaf(at:)` would just read it as
		/// blank rather than surfacing the mismatch.
		public func validateNodeKinds() throws {
			for i in 0..<UInt32(nodes.count) {
				guard let treeNode = node(at: i) else { continue }
				switch (treeNode, MLS.TreeMath.isLeaf(i)) {
				case (.leaf, true), (.parent, false): continue
				default: throw TreeError.wrongNodeKind(index: i)
				}
			}
		}

		/// RFC 9420 requires trimming trailing blanks before a tree is
		/// serialized (`trim()` above does this); a tree that arrives with
		/// one anyway is malformed on the wire, not merely untidy —
		/// checked separately from `trim()` itself so a decoder can reject
		/// it instead of silently normalizing it.
		public func validateNoTrailingBlank() throws {
			guard let last = nodes.last else { throw TreeError.emptyTree }
			guard last != nil else { throw TreeError.trailingBlankLeaves }
		}
	}
}
