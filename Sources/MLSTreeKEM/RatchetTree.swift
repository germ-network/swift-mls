import MLSCodec
import MLSTreeMath

extension MLS.TreeKEM {
	/// RFC 9420's ratchet tree: an array-indexed binary tree (`MLSTreeMath`'s
	/// index arithmetic) whose leaves carry group members (`LeafRecord`)
	/// and whose internal nodes carry `ParentNode`s, either of which may be
	/// blank (`nil`).
	///
	/// The tree owns its **dimension**: `leafCount` is stored, and `nodes` is
	/// held at full width (`nodeCount` slots, `nil`-padded), so every in-tree
	/// index is a real slot. Size changes in exactly two places — `init` and
	/// the `insertLeaf`/`truncate` pair — never as a side effect of a set. The
	/// wire format's trailing-blank trimming is *not* a storage concern here:
	/// it is applied at encode time (`serializedNodeCount`) and undone at
	/// decode (`init(nodes:)` pads), so the in-memory tree is always canonical
	/// for its `leafCount`.
	public struct RatchetTree: Sendable, Equatable {
		/// The tree's size, the single source of truth for its shape. Only
		/// `init`, `insertLeaf`, and `truncate` change it, each in lockstep
		/// with `nodes.count`.
		public private(set) var leafCount: MLS.LeafCount

		/// Invariant: `nodes.count == nodeCount`. Interior blanks are stored
		/// `nil`; there is no trimmed-or-overlong transient state.
		private var nodes: [TreeNode?]

		public var nodeCount: UInt32 { MLS.TreeMath.nodeCount(leafCount: leafCount) }

		/// The number of leading slots up to and including the last non-blank
		/// one — what the wire form carries (RFC 9420 §12.4.3.3 forbids blank
		/// nodes after the last non-blank), and a tight upper bound for any
		/// sweep over the tree's content. Scans from the end, so it costs only
		/// the trailing-blank run. A well-formed tree always has ≥ 1 non-blank
		/// node, so this is ≥ 1.
		public var serializedNodeCount: UInt32 {
			guard let last = nodes.lastIndex(where: { $0 != nil }) else { return 0 }
			return UInt32(last + 1)
		}

		/// Decodes a wire node array. Its length determines `leafCount`
		/// (`(count / 2 + 1)` rounded up — a shorter, trailing-trimmed array
		/// resolves to the same size), after which the array is padded to full
		/// width. A trailing blank would inflate `leafCount`; rejecting that is
		/// the caller's decode-time job (see the profile's
		/// `validateNoTrailingBlank(_:)`), kept separate so a decoder rejects
		/// rather than silently normalizes.
		public init(nodes wireNodes: [TreeNode?]) throws {
			let leafCount = try MLS.LeafCount(nodeArrayCount: wireNodes.count)
			let fullCount = Int(MLS.TreeMath.nodeCount(leafCount: leafCount))
			var padded = wireNodes
			if padded.count < fullCount {
				padded.append(
					contentsOf: repeatElement(
						nil, count: fullCount - padded.count))
			}
			self.leafCount = leafCount
			self.nodes = padded
		}

		public init(singleLeaf record: LeafRecord) {
			self.leafCount = .single
			self.nodes = [.leaf(record)]
		}

		func node(at index: UInt32) -> TreeNode? {
			guard let i = Int(exactly: index), i < nodes.count else { return nil }
			return nodes[i]
		}

		/// The one mutation path: a bounds-checked assign into a slot that
		/// always physically exists. It cannot resize the tree — that is what
		/// makes the class of "a setter silently grew the tree and aborted 24
		/// calls later" (twice reopened, twice caught by review, under the old
		/// length-is-truth storage) unrepresentable rather than guarded. An
		/// out-of-range index throws; growth is `insertLeaf`'s job alone.
		mutating func setNode(at index: UInt32, to value: TreeNode?) throws {
			guard index < nodeCount else {
				throw MLS.TreeKEM.TreeError.nodeIndexOutOfBounds(
					index: index, nodeCount: nodeCount)
			}
			nodes[Int(index)] = value
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

		public mutating func setLeaf(_ index: MLS.LeafIndex, to record: LeafRecord?) throws
		{
			try setNode(at: 2 * index.value, to: record.map(TreeNode.leaf))
		}

		public mutating func setParent(_ nodeIndex: UInt32, to parentNode: ParentNode?)
			throws
		{
			try setNode(at: nodeIndex, to: parentNode.map(TreeNode.parent))
		}

		/// Every non-blank leaf, in ascending index order.
		public func nonBlankLeaves() -> [(index: MLS.LeafIndex, record: LeafRecord)] {
			stride(from: 0, to: leafCount.value, by: 1).compactMap { i in
				let index = MLS.LeafIndex(value: i)
				return leaf(at: index).map { (index, $0) }
			}
		}

		/// RFC 9420 §7.7 tree truncation: after a Remove empties the rightmost
		/// subtree, shrink to the smallest power-of-two size that still holds
		/// every non-blank node. Halve while the whole upper half (root + right
		/// subtree) is blank. This is the `leafCount`-shrinking half of what
		/// the old length-derived `trim()` did for free; it is semantically
		/// load-bearing (a too-large `leafCount` gives a larger root and a
		/// wrong tree hash, though the wire bytes still match), so it runs
		/// after every applied proposal. The wire-byte trimming is separate —
		/// `serializedNodeCount` at encode. Non-throwing, via `halved()`.
		public mutating func truncate() {
			while let smaller = leafCount.halved() {
				let leftNodeCount = Int(MLS.TreeMath.nodeCount(leafCount: smaller))
				guard nodes[leftNodeCount...].allSatisfy({ $0 == nil }) else {
					break
				}
				nodes.removeSubrange(leftNodeCount...)
				leafCount = smaller
			}
		}

		/// Blanks every node on `index`'s direct path — the ancestor chain
		/// only, never the sibling/copath nodes, and never `index`'s own
		/// leaf slot. This is what Update blanks: the leaf itself gets the
		/// *new* `LeafNode` installed instead of going blank, since Update
		/// changes a member's content without removing them. `throws` only
		/// nominally: every direct-path index is in range by construction.
		public mutating func blankDirectPath(of index: MLS.LeafIndex) throws {
			for step in MLS.TreeMath.directPath(
				from: 2 * index.value, leafCount: leafCount)
			{
				try setNode(at: step.path, to: nil)
			}
		}

		/// Blanks a leaf and every node on its direct path — what Remove
		/// does: the member is gone, so both the leaf and the ancestor
		/// chain (which nobody can re-derive without them) go blank.
		public mutating func blankLeafAndDirectPath(_ index: MLS.LeafIndex) throws {
			try setNode(at: 2 * index.value, to: nil)
			try blankDirectPath(of: index)
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
		/// or grows the tree by doubling if none exists (mirrors mls-rs
		/// `NodeVec::insert_leaf` — the new leaf lands at index `leafCount`,
		/// which doubling makes room for). The doubling guard is
		/// `LeafCount.doubled()` returning `nil` at the ceiling — the single
		/// place the tree grows, so the single place that guard lives.
		public mutating func insertLeaf(
			_ record: LeafRecord, hint: MLS.LeafIndex = MLS.LeafIndex(value: 0)
		) throws -> MLS.LeafIndex {
			if let blank = leftmostBlankLeaf(atOrAfter: hint) {
				try setNode(at: 2 * blank.value, to: .leaf(record))
				return blank
			}
			guard let bigger = leafCount.doubled() else {
				throw MLS.TreeKEM.TreeError.treeFull
			}
			let newIndex = MLS.LeafIndex(value: leafCount.value)
			let newNodeCount = Int(MLS.TreeMath.nodeCount(leafCount: bigger))
			nodes.append(
				contentsOf: repeatElement(nil, count: newNodeCount - nodes.count))
			leafCount = bigger
			try setNode(at: 2 * newIndex.value, to: .leaf(record))
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
			try setParent(nodeIndex, to: parentNode)
		}

		/// Every non-blank slot's node kind (leaf vs. parent) must match
		/// its array index's parity — nothing in the wire format enforces
		/// this on its own, since a `Node`'s type tag travels with the
		/// node itself, independent of where it sits in the vector. A
		/// malicious or corrupt tree can claim a `ParentNode` at an even
		/// (leaf) index; left unchecked, `leaf(at:)` would just read it as
		/// blank rather than surfacing the mismatch.
		public func validateNodeKinds() throws {
			for i in 0..<serializedNodeCount {
				guard let treeNode = node(at: i) else { continue }
				switch (treeNode, MLS.TreeMath.isLeaf(i)) {
				case (.leaf, true), (.parent, false): continue
				default: throw TreeError.wrongNodeKind(index: i)
				}
			}
		}
	}
}
