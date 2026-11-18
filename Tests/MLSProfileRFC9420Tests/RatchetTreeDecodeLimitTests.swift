import Foundation
import MLSCodec
import MLSTreeKEM
import MLSTreeMath
import Testing

@testable import MLSProfileRFC9420

/// A ratchet tree from any source holds at most `maxRatchetTreeNodeCount`
/// nodes, each costing one word of storage in the decoded array and in the
/// tree. Serialized: the over-maximum cases each allocate about 134 MB.
@Suite("Ratchet tree size bounds", .serialized)
struct RatchetTreeDecodeLimitTests {
	@Test("a decoded profile node costs one word in an array")
	func decodedNodeIsCompact() throws {
		Issue.record("pending")
	}

	@Test("a tree node costs one word in a ratchet tree's storage")
	func treeNodeIsCompact() throws {
		Issue.record("pending")
	}

	@Test("maxRatchetTreeNodeCount is the longest array LeafCount admits")
	func maxNodeCountMatchesLeafCountCeiling() throws {
		Issue.record("pending")
	}

	@Test("a ratchet_tree one node over the maximum is rejected while decoding")
	func overlongTreeRejectedWhileDecoding() throws {
		Issue.record("pending")
	}

	@Test("a GroupInfo ratchet_tree one node over the maximum is rejected while decoding")
	func overlongGroupInfoTreeRejected() throws {
		Issue.record("pending")
	}

	@Test("a snapshot ratchet tree one node over the maximum is rejected while decoding")
	func overlongSnapshotTreeRejected() throws {
		Issue.record("pending")
	}

	@Test("a node array one over the maximum is rejected with invalidLeafCount")
	func overlongNodeArrayRejectedWithInvalidLeafCount() throws {
		Issue.record("pending")
	}
}
