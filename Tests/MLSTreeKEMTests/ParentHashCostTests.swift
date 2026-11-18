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
	@Test("unmerged_leaves entries no leaf's walk reaches are rejected with zero hash calls")
	func unreachedUnmergedLeavesRejectedWithoutHashing() throws {
		Issue.record("pending")
	}

	@Test("an unsorted unmerged_leaves list is rejected with zero hash calls")
	func unsortedUnmergedLeavesRejectedWithoutHashing() throws {
		Issue.record("pending")
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
