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
		Issue.record("pending")
	}

	@Test(
		"a fully non-blank tree costs at most 3 hash calls per node",
		arguments: [8, 10])
	func fullyPopulatedTreeStaysWithinThreePerNode(log2LeafCount: Int) throws {
		Issue.record("pending")
	}

	@Test(
		"one merged leaf per half, every other leaf unmerged at the root, stays in bound",
		arguments: [8, 10])
	func allLeavesUnmergedAtRootStaysWithinDepthBound(log2LeafCount: Int) throws {
		Issue.record("pending")
	}

	@Test(
		"unmerged leaves listed at every non-blank ancestor stay within the depth bound",
		arguments: [8, 10])
	func unmergedAtEveryLevelStaysWithinDepthBound(log2LeafCount: Int) throws {
		Issue.record("pending")
	}

	@Test(
		"blank regions under ancestors listing an unmerged leaf stay within the depth bound",
		arguments: [8, 10])
	func blankRegionsUnderListingAncestorsStayWithinDepthBound(log2LeafCount: Int) throws {
		Issue.record("pending")
	}
}
