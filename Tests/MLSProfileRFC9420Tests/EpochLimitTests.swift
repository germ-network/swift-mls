import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// Join accepts only epochs below `GroupContext.joinEpochLimit`; restore only
/// below `GroupContext.restoreEpochLimit`, which is higher, so a joined group
/// keeps restoring as it commits.
@Suite("Epoch limits at join and restore")
struct EpochLimitTests {
	@Test("a Welcome at epoch 2^64-1 is rejected with epochOutOfRange")
	func welcomeAtMaximumEpochIsRejected() throws {
		Issue.record("pending")
	}

	@Test("a Welcome at exactly joinEpochLimit is rejected with epochOutOfRange")
	func welcomeAtJoinEpochLimitIsRejected() throws {
		Issue.record("pending")
	}

	@Test("a Welcome one below joinEpochLimit joins, commits, and restores from a snapshot")
	func welcomeJustBelowJoinEpochLimitJoinsAndRestores() throws {
		Issue.record("pending")
	}

	@Test("a snapshot at epoch 2^64-1 is rejected with epochOutOfRange")
	func snapshotAtMaximumEpochIsRejected() throws {
		Issue.record("pending")
	}

	@Test("a snapshot at exactly restoreEpochLimit is rejected with epochOutOfRange")
	func snapshotAtRestoreEpochLimitIsRejected() throws {
		Issue.record("pending")
	}

	@Test("a snapshot one below restoreEpochLimit restores")
	func snapshotJustBelowRestoreEpochLimitRestores() throws {
		Issue.record("pending")
	}
}
