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
		public var leafCount: UInt32 {
			// Never throws in practice: `nodes.count` only grows by
			// `insertLeaf`/`setParent`, both of which only ever produce a
			// count `paddedLeafCount` already accepted once at `init`, or
			// grow it by exactly the amount `insertLeaf` needs to reach the
			// next valid leaf slot.
			try! MLS.TreeMath.paddedLeafCount(nodeArrayCount: nodes.count)
		}

		public var nodeCount: UInt32 { MLS.TreeMath.nodeCount(leafCount: leafCount) }

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
			// Growing past the current array only happens through
			// `insertLeaf`, which grows exactly as far as needed
			// (mirrors mls-rs `NodeVec::insert_leaf`) — reached here only
			// by that path, never by `setParent`/`blank*` on an
			// already-in-range index.
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
			stride(from: 0, to: leafCount, by: 1).compactMap { i in
				let index = MLS.LeafIndex(value: i)
				return leaf(at: index).map { (index, $0) }
			}
		}

		/// RFC 9420 requires trimming after every edit: remove nodes from
		/// the end of the array while the last one is blank. Load-bearing
		/// for byte-exact re-serialization (`tree-operations.json`'s
		/// `tree_after` check) — an untrimmed tail would round-trip to
		/// different bytes than what a well-formed peer sent.
		public mutating func trim() {
			while nodes.last == .some(nil) { nodes.removeLast() }
		}

		/// Blanks a leaf and every node on its direct path (not the
		/// sibling/copath nodes — RFC 9420's Remove and the receiving side
		/// of Update both blank only the ancestor chain, leaving copath
		/// nodes' contents untouched).
		public mutating func blankLeafAndDirectPath(_ index: MLS.LeafIndex) throws {
			setLeaf(index, to: nil)
			for step in try MLS.TreeMath.directPath(
				from: 2 * index.value, leafCount: leafCount)
			{
				setNode(at: step.path, to: nil)
			}
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
			guard hint.value < leafCount else { return nil }
			for i in hint.value..<leafCount {
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
			let newIndex = MLS.LeafIndex(value: leafCount)
			setNode(at: 2 * newIndex.value, to: .leaf(record))
			return newIndex
		}

		/// Inserts `leafIndex` into `nodeIndex`'s `unmergedLeaves`, keeping
		/// the list sorted ascending — a real invariant `TreeValidation`
		/// checks, not incidental tidiness (RFC 9420 §7.7, and the
		/// resolution/parent-hash algorithms both assume ascending order to
		/// binary-search subtree membership). Throws rather than silently
		/// deduplicating: a duplicate means the caller's own bookkeeping
		/// is wrong, not a normal occurrence.
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
