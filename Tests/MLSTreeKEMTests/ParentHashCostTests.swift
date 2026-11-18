import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// `validateParentHashChain` makes at most nodeCount·(depth + 1) hash calls on
/// any input, plus a constant per non-blank parent, and rejects invalid
/// `unmerged_leaves` before making any. Counted through a hash-counting
/// provider, not wall-clock.
@Suite("Parent-hash validation cost")
struct ParentHashCostTests {
	/// Four non-blank leaves under a non-blank root listing `rootUnmerged`;
	/// the other parents are blank.
	static func fourLeafTree(rootUnmerged: [UInt32]) throws -> MLS.TreeKEM.RatchetTree {
		try MLS.TreeKEM.RatchetTree(
			nodes: [
				.leaf(syntheticLeaf(1)), nil, .leaf(syntheticLeaf(2)),
				.parent(syntheticParent(10, unmerged: rootUnmerged)),
				.leaf(syntheticLeaf(3)), nil, .leaf(syntheticLeaf(4)),
			])
	}

	@Test("unmerged_leaves entries no leaf's walk reaches are rejected with zero hash calls")
	func unreachedUnmergedLeavesRejectedWithoutHashing() throws {
		let tree = try Self.fourLeafTree(rootUnmerged: (0..<UInt32(1 << 16)).map { $0 })
		let provider = HashCountingProvider()
		#expect(throws: MLS.TreeKEM.TreeError.unmergedLeafNotAtExpectedPosition) {
			try tree.validateParentHashChain(provider)
		}
		#expect(provider.hashCalls == 0)
	}

	@Test("an unsorted unmerged_leaves list is rejected with zero hash calls")
	func unsortedUnmergedLeavesRejectedWithoutHashing() throws {
		let tree = try Self.fourLeafTree(rootUnmerged: [1, 0])
		let provider = HashCountingProvider()
		#expect(throws: MLS.TreeKEM.TreeError.unmergedLeavesNotSorted) {
			try tree.validateParentHashChain(provider)
		}
		#expect(provider.hashCalls == 0)
	}

	@Test(
		"a non-blank root over a blank interior costs at most 3 hash calls per node",
		arguments: [8, 10])
	func blankInteriorUnderNonBlankRootStaysWithinThreePerNode(log2LeafCount: Int) throws {
		var builder = try ChainBuilder(log2LeafCount: log2LeafCount)
		let leaves = UInt32(1) << UInt32(log2LeafCount)
		try builder.setParent(
			builder.root, unmerged: Array(1..<leaves / 2))
		try builder.commit(0)
		try expectWithinThreePerNode(builder.tree)
	}

	@Test(
		"a fully non-blank tree costs at most 3 hash calls per node",
		arguments: [8, 10])
	func fullyPopulatedTreeStaysWithinThreePerNode(log2LeafCount: Int) throws {
		var builder = try ChainBuilder(log2LeafCount: log2LeafCount)
		try builder.populateAllParents { _ in [] }
		for leaf in stride(from: 0, to: builder.leafCount, by: 2) {
			try builder.commit(leaf)
		}
		try expectWithinThreePerNode(builder.tree)
	}

	@Test(
		"one merged leaf per half, every other leaf unmerged at the root, stays in bound",
		arguments: [8, 10])
	func allLeavesUnmergedAtRootStaysWithinDepthBound(log2LeafCount: Int) throws {
		var builder = try ChainBuilder(log2LeafCount: log2LeafCount)
		let half = builder.leafCount / 2
		let unmerged = (0..<builder.leafCount).filter { $0 != 0 && $0 != half }
		try builder.setParent(builder.root, unmerged: unmerged)
		try builder.commit(0)
		try expectWithinDepthBound(builder.tree, log2LeafCount: log2LeafCount)
	}

	@Test(
		"unmerged leaves listed at every non-blank ancestor stay within the depth bound",
		arguments: [8, 10])
	func unmergedAtEveryLevelStaysWithinDepthBound(log2LeafCount: Int) throws {
		var builder = try ChainBuilder(log2LeafCount: log2LeafCount)
		try builder.populateAllParents { subtree in subtree.filter { $0 % 2 == 1 } }
		for leaf in stride(from: 0, to: builder.leafCount, by: 2) {
			try builder.commit(leaf)
		}
		try expectWithinDepthBound(builder.tree, log2LeafCount: log2LeafCount)
	}

	@Test(
		"blank regions under ancestors listing an unmerged leaf stay within the depth bound",
		arguments: [8, 10])
	func blankRegionsUnderListingAncestorsStayWithinDepthBound(log2LeafCount: Int) throws {
		var builder = try ChainBuilder(log2LeafCount: log2LeafCount)
		let regionLog2 = 4
		let regionSize = UInt32(1) << UInt32(regionLog2)
		// Leaf `base` commits, leaf `base + 1` is added later, and every other
		// leaf of the region is blank under blank parents.
		for leaf in 0..<builder.leafCount where leaf % regionSize > 1 {
			try builder.blankLeaf(leaf)
		}
		try builder.populateAncestors(
			aboveLevel: regionLog2,
			unmerged: { subtree in
				subtree.filter { $0 % regionSize == 1 }
			})
		for base in stride(from: UInt32(0), to: builder.leafCount, by: Int(regionSize)) {
			try builder.commit(base)
		}
		try expectWithinDepthBound(builder.tree, log2LeafCount: log2LeafCount)
	}

	// MARK: - Memoised subtree hashes

	@Test("a subtree hashed unfiltered for one ancestor and filtered for another validates")
	func subtreeNeededUnfilteredThenFiltered() throws {
		var builder = try ChainBuilder(log2LeafCount: 2)
		try builder.setParent(1, unmerged: [])
		try builder.setParent(3, unmerged: [])
		try builder.setParent(5, unmerged: [3])
		try builder.commit(2)
		try builder.commit(0)
		try builder.tree.validateParentHashChain(HashCountingProvider())
	}

	@Test("a subtree hashed filtered for one ancestor and unfiltered for another validates")
	func subtreeNeededFilteredThenUnfiltered() throws {
		var builder = try ChainBuilder(log2LeafCount: 2)
		try builder.setParent(1, unmerged: [1])
		try builder.setParent(3, unmerged: [])
		try builder.setParent(5, unmerged: [])
		try builder.commit(0)
		try builder.commit(2)
		try builder.tree.validateParentHashChain(HashCountingProvider())
	}

	@Test("a parent whose two children both carry its matching parent_hash is rejected")
	func parentCoveredByTwoChainsIsRejected() throws {
		var builder = try ChainBuilder(log2LeafCount: 2)
		try builder.populateAllParents { _ in [] }
		try builder.commit(0)
		try builder.commit(1)
		#expect(throws: MLS.TreeKEM.TreeError.parentHashCoveredTwice) {
			try builder.tree.validateParentHashChain(HashCountingProvider())
		}
	}

	// MARK: - Bounds

	private func countedValidation(_ tree: MLS.TreeKEM.RatchetTree) throws -> Int {
		let provider = HashCountingProvider()
		try tree.validateParentHashChain(provider)
		return provider.hashCalls
	}

	private func nonBlankParents(_ tree: MLS.TreeKEM.RatchetTree) -> Int {
		stride(from: UInt32(1), to: tree.serializedNodeCount, by: 2)
			.filter { tree.parent(at: $0) != nil }.count
	}

	private func expectWithinThreePerNode(
		_ tree: MLS.TreeKEM.RatchetTree, _ location: SourceLocation = #_sourceLocation
	) throws {
		let calls = try countedValidation(tree)
		#expect(calls <= 3 * Int(tree.nodeCount), sourceLocation: location)
	}

	private func expectWithinDepthBound(
		_ tree: MLS.TreeKEM.RatchetTree, log2LeafCount: Int,
		_ location: SourceLocation = #_sourceLocation
	) throws {
		let calls = try countedValidation(tree)
		let bound = Int(tree.nodeCount) * (log2LeafCount + 1) + 2 * nonBlankParents(tree)
		#expect(calls <= bound, sourceLocation: location)
	}
}

/// Builds trees whose parent-hash chains are valid: `commit(_:)` installs a
/// leaf's chain through its non-blank ancestors the way a committer would,
/// skipping blank ancestors, with each ancestor's original sibling tree hash
/// filtered by that ancestor's `unmerged_leaves`.
struct ChainBuilder {
	var tree: MLS.TreeKEM.RatchetTree
	let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .init(id: 1))!
	let leafCount: UInt32

	var root: UInt32 { MLS.TreeMath.root(leafCount: tree.leafCount) }

	init(log2LeafCount: Int) throws {
		leafCount = UInt32(1) << UInt32(log2LeafCount)
		var nodes: [MLS.TreeKEM.TreeNode?] = Array(
			repeating: nil, count: Int(2 * leafCount - 1))
		for leaf in 0..<leafCount {
			nodes[Int(2 * leaf)] = .leaf(Self.leafRecord(leaf))
		}
		tree = try MLS.TreeKEM.RatchetTree(nodes: nodes)
	}

	private static func leafRecord(_ leaf: UInt32) -> MLS.TreeKEM.LeafRecord {
		var bytes = Data()
		withUnsafeBytes(of: leaf.bigEndian) { bytes.append(contentsOf: $0) }
		return MLS.TreeKEM.LeafRecord(
			encryptionKey: .init(bytes), parentHash: nil, encoded: bytes)
	}

	mutating func blankLeaf(_ leaf: UInt32) throws {
		try tree.setLeaf(MLS.LeafIndex(value: leaf), to: nil)
	}

	mutating func setParent(_ node: UInt32, unmerged: [UInt32]) throws {
		var bytes = Data()
		withUnsafeBytes(of: node.bigEndian) { bytes.append(contentsOf: $0) }
		try tree.setParent(
			node,
			to: MLS.TreeKEM.ParentNode(
				encryptionKey: .init(bytes), parentHash: Data(),
				unmergedLeaves: unmerged.map { MLS.LeafIndex(value: $0) }))
	}

	/// Makes every parent non-blank, listing `unmerged(leaves under it)`.
	mutating func populateAllParents(unmerged: ([UInt32]) -> [UInt32]) throws {
		try populateAncestors(aboveLevel: 0, unmerged: unmerged)
	}

	/// Makes every parent at `level` or above non-blank, listing
	/// `unmerged(leaves under it)`; parents below stay blank.
	mutating func populateAncestors(
		aboveLevel level: Int, unmerged: ([UInt32]) -> [UInt32]
	) throws {
		for node in stride(from: UInt32(1), to: tree.nodeCount, by: 2) {
			let nodeLevel = (~node).trailingZeroBitCount
			guard nodeLevel >= max(level, 1) else { continue }
			let span = (UInt32(1) << UInt32(nodeLevel)) - 1
			let leaves = Array(((node - span) / 2)...((node + span) / 2))
			try setParent(node, unmerged: unmerged(leaves))
		}
	}

	mutating func commit(_ leaf: UInt32) throws {
		var steps: [(ancestor: UInt32, copath: UInt32)] = []
		var node = 2 * leaf
		walk: while let immediate = MLS.TreeMath.parent(node, leafCount: tree.leafCount) {
			var ancestor = immediate
			var copath = MLS.TreeMath.sibling(node, leafCount: tree.leafCount)!
			while tree.isBlank(at: ancestor) {
				guard
					let next = MLS.TreeMath.parent(
						ancestor, leafCount: tree.leafCount)
				else { break walk }
				copath = MLS.TreeMath.sibling(ancestor, leafCount: tree.leafCount)!
				ancestor = next
			}
			steps.append((ancestor, copath))
			node = ancestor
		}
		var hash = Data()
		for step in steps.reversed() {
			var parent = tree.parent(at: step.ancestor)!
			let siblingHash = try tree.treeHash(
				at: step.copath, filteredUnmergedLeaves: Set(parent.unmergedLeaves),
				provider)
			let calculated = try MLS.TreeKEM.parentHash(
				publicKey: parent.encryptionKey, parentHash: hash,
				originalSiblingTreeHash: siblingHash, provider)
			parent.parentHash = hash
			try tree.setParent(step.ancestor, to: parent)
			hash = calculated
		}
		let index = MLS.LeafIndex(value: leaf)
		let record = tree.leaf(at: index)!
		try tree.setLeaf(
			index,
			to: MLS.TreeKEM.LeafRecord(
				encryptionKey: record.encryptionKey, parentHash: hash,
				encoded: record.encoded))
	}
}
