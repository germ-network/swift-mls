import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §16.7: tree encryption keys "MUST be distinct from one another".
/// §12.4.2's checks compare an UpdatePath only against the tree before it is
/// merged; this implementation also checks the commit's final tree, path or not,
/// and the send side runs the same checks, so every commit this library builds
/// is one it accepts.
@Suite("Commits never leave two tree nodes with one encryption key (RFC 9420 §16.7)")
struct CommitKeyUniquenessTests {
	@Test(
		"committing twice with one CommitRandomness is refused on the second commit",
		.disabled("not yet implemented"))
	func committingRefusesReusedRandomness() throws {}

	@Test(
		"committing with a path whose leaf key equals one of its node keys throws",
		.disabled("not yet implemented"))
	func committingRefusesPathWhoseLeafKeyEqualsANodeKey() throws {}

	@Test(
		"receiving a commit whose path repeats a node key is rejected",
		.disabled("not yet implemented"))
	func receivingRejectsPathWithDuplicateNodeKeys() throws {}

	@Test(
		"receiving a pathless commit that Adds a leaf whose key equals a parent key is rejected",
		.disabled("not yet implemented"))
	func pathlessCommitRejectsAddWhoseLeafKeyEqualsAParentKey() throws {}

	@Test(
		"committing an Add whose leaf key equals a parent key throws",
		.disabled("not yet implemented"))
	func committingRefusesAddWhoseLeafKeyEqualsAParentKey() throws {}
}
