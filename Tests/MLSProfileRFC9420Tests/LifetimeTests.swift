import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §7.3: for a LeafNode being sent, "the client MUST verify that the
/// current time is within the range of the lifetime field"; for one received,
/// the check is RECOMMENDED. The caller supplies the time; nil skips the check.
@Suite("KeyPackage leaf lifetime is checked against the caller's time (RFC 9420 §7.3)")
struct LifetimeTests {
	@Test("committing an Add of an expired KeyPackage throws", .disabled("not yet implemented"))
	func committingRejectsAddOfExpiredKeyPackage() throws {}

	@Test(
		"committing an Add of a not-yet-valid KeyPackage throws",
		.disabled("not yet implemented"))
	func committingRejectsAddOfNotYetValidKeyPackage() throws {}

	@Test("committing an Add within its lifetime succeeds", .disabled("not yet implemented"))
	func committingAcceptsAddWithinLifetime() throws {}

	@Test(
		"committing an Add accepts a time equal to not_before or not_after",
		.disabled("not yet implemented"))
	func committingAcceptsAddAtLifetimeBoundaries() throws {}

	@Test(
		"committing a by-reference Add of an expired KeyPackage throws",
		.disabled("not yet implemented"))
	func committingRejectsReferencedAddOfExpiredKeyPackage() throws {}

	@Test(
		"committing with an unchecked lifetime skips the check",
		.disabled("not yet implemented"))
	func committingUncheckedSkipsLifetimeCheck() throws {}

	@Test(
		"creating a group from a leaf outside its lifetime throws",
		.disabled("not yet implemented"))
	func createRejectsCreatorLeafOutsideLifetime() throws {}

	@Test(
		"creating a group still accepts a non-key_package creator leaf when checking lifetime",
		.disabled("not yet implemented"))
	func createKeepsAcceptingNonKeyPackageCreatorLeaf() throws {}

	@Test("a 0…UInt64.max lifetime is accepted at any time", .disabled("not yet implemented"))
	func fullRangeLifetimeAcceptedAtAnyTime() throws {}

	@Test(
		"validating a public commit that Adds an expired KeyPackage throws when given a time",
		.disabled("not yet implemented"))
	func validatingPublicCommitRejectsExpiredAddWhenTimeGiven() throws {}

	@Test(
		"validating a private commit that Adds an expired KeyPackage reports it rejected when given a time",
		.disabled("not yet implemented"))
	func validatingPrivateCommitReportsRejectedForExpiredAddWhenTimeGiven() throws {}

	@Test(
		"validating without a time does not check lifetimes",
		.disabled("not yet implemented"))
	func validatingDefaultsToNoLifetimeCheck() throws {}

	@Test(
		"a commit built at a time is accepted when validated at the same time",
		.disabled("not yet implemented"))
	func committedThenValidatedAtSameTimeIsAccepted() throws {}
}
