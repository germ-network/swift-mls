import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// Every `membershipRemoved` names the committer, including a full eviction,
/// where `epochAdvanced` is absent. This implementation's choice, not an RFC 9420
/// rule.
@Suite("Eviction reports the committer")
struct EvictionCommitterTests {
	@Test("a full eviction reports the committer", .disabled("not yet implemented"))
	func fullEvictionReportsCommitter() throws {}

	@Test("a partial eviction reports the committer", .disabled("not yet implemented"))
	func partialEvictionReportsCommitter() throws {}
}
