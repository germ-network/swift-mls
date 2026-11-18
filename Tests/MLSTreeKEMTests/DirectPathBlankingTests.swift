import Foundation
import MLSCrypto
import MLSTreeMath
import Testing

@testable import MLSTreeKEM

/// RFC 9420 §7.5: sender and recipient both "Blank all nodes on the direct path
/// of the sender's leaf" before setting the filtered direct path, so a stale key
/// on a filtered node never survives a commit.
@Suite("UpdatePath blanks the sender's whole direct path (RFC 9420 §7.5)")
struct DirectPathBlankingTests {
	@Test(
		"merging an UpdatePath blanks a non-blank filtered node on the sender's direct path",
		.disabled("not yet implemented"))
	func applyUpdatePathBlanksFilteredDirectPathNodes() throws {}

	@Test(
		"building an UpdatePath blanks a non-blank filtered node on the sender's direct path",
		.disabled("not yet implemented"))
	func beginCommitPathBlanksFilteredDirectPathNodes() throws {}

	@Test(
		"the tree hash after the commit differs from the hash with the stale filtered node kept",
		.disabled("not yet implemented"))
	func blankingChangesTreeHashWhenFilteredNodeWasNonBlank() throws {}

	@Test(
		"committer and receiver reach the same tree hash when a filtered node was non-blank",
		.disabled("not yet implemented"))
	func committerAndReceiverConvergeWhenFilteredNodeWasNonBlank() throws {}

	@Test(
		"the tree hash is unchanged when every filtered node was already blank",
		.disabled("not yet implemented"))
	func blankingLeavesTreeHashUnchangedWhenFilteredNodesAreBlank() throws {}
}
