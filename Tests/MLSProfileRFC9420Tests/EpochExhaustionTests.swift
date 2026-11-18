import Foundation
import MLSCodec
import Testing

@testable import MLSProfileRFC9420

/// The epoch is a `uint64` (RFC 9420 §8.1, which states no bound). Advancing past
/// `UInt64.max` throws rather than trapping; this implementation's choice.
@Suite("Epoch increment cannot trap")
struct EpochExhaustionTests {
	@Test(
		"the next epoch after UInt64.max throws epochExhausted",
		.disabled("not yet implemented"))
	func nextEpochThrowsAtMaximum() throws {}

	@Test("the next epoch below the maximum is one more", .disabled("not yet implemented"))
	func nextEpochIncrementsBelowMaximum() throws {}

	@Test(
		"committing on a group at epoch UInt64.max throws epochExhausted",
		.disabled("not yet implemented"))
	func committingAtMaximumEpochThrowsEpochExhausted() throws {}
}
