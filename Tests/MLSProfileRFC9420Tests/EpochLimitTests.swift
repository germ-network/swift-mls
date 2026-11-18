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
	private typealias Group = MLS.RFC9420.Group
	private static let provider = SelfInteropTests.provider

	// MARK: - Welcome

	private func expectWelcomeRejected(atEpoch epoch: UInt64) throws {
		let scenario = try GroupMutationTests.buildScenario()
		var groupInfo = scenario.groupInfo
		groupInfo.groupContext.epoch = epoch
		let welcome = try GroupMutationTests.reseal(scenario, groupInfo: groupInfo)
		#expect(throws: MLS.RFC9420.GroupError.epochOutOfRange(epoch)) {
			_ = try Group.joining(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}

	@Test("a Welcome at epoch 2^64-1 is rejected with epochOutOfRange")
	func welcomeAtMaximumEpochIsRejected() throws {
		try expectWelcomeRejected(atEpoch: .max)
	}

	@Test("a Welcome at exactly joinEpochLimit is rejected with epochOutOfRange")
	func welcomeAtJoinEpochLimitIsRejected() throws {
		#expect(MLS.RFC9420.GroupContext.joinEpochLimit == 1 << 62)
		try expectWelcomeRejected(atEpoch: 1 << 62)
	}

	// MARK: - Snapshot

	/// A snapshot of `group` with its context epoch replaced and, when `rekey`,
	/// the epoch-keyed stores moved to the new epoch. Rejection tests leave the
	/// stores alone, so only the epoch check can account for their error.
	private static func snapshot(
		of group: Group, atEpoch epoch: UInt64, rekey: Bool
	) throws -> Group.Snapshot {
		var snapshot = try group.makeSnapshot()
		var context = group.context
		context.epoch = epoch
		snapshot.core.groupContext = try context.mlsEncoded()
		if rekey {
			let old = group.context.epoch
			snapshot.core.resumptionPsks.entries = [
				epoch: try #require(snapshot.core.resumptionPsks.entries[old])
			]
			var store = try #require(snapshot.core.messageSecrets.entries[old])
			store.groupContext = snapshot.core.groupContext
			snapshot.core.messageSecrets.entries = [epoch: store]
		}
		return snapshot
	}

	private func expectSnapshotRejected(atEpoch epoch: UInt64) throws {
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let snapshot = try Self.snapshot(of: group, atEpoch: epoch, rekey: false)
		#expect(throws: MLS.RFC9420.GroupError.epochOutOfRange(epoch)) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	@Test("a snapshot at epoch 2^64-1 is rejected with epochOutOfRange")
	func snapshotAtMaximumEpochIsRejected() throws {
		try expectSnapshotRejected(atEpoch: .max)
	}

	@Test("a snapshot at exactly restoreEpochLimit is rejected with epochOutOfRange")
	func snapshotAtRestoreEpochLimitIsRejected() throws {
		#expect(MLS.RFC9420.GroupContext.restoreEpochLimit == 1 << 63)
		try expectSnapshotRejected(atEpoch: 1 << 63)
	}

	@Test("a snapshot one below restoreEpochLimit restores")
	func snapshotJustBelowRestoreEpochLimitRestores() throws {
		let limit = MLS.RFC9420.GroupContext.restoreEpochLimit
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let snapshot = try Self.snapshot(of: group, atEpoch: limit - 1, rekey: true)
		let restored = try Group.restore(from: snapshot, Self.provider)
		#expect(restored.context.epoch == limit - 1)
	}

	// MARK: - Join, commit, restore

	@Test("a Welcome one below joinEpochLimit joins, commits, and restores from a snapshot")
	func welcomeJustBelowJoinEpochLimitJoinsAndRestores() throws {
		let provider = Self.provider
		let limit = MLS.RFC9420.GroupContext.joinEpochLimit
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let founder = try SelfInteropTests.createGroup(alice)
		var groupA = try Group.restore(
			from: try Self.snapshot(of: founder, atEpoch: limit - 2, rekey: true),
			provider)

		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		#expect(groupA.context.epoch == limit - 1)
		var groupB = try Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		#expect(groupB.context.epoch == limit - 1)

		let commit = try groupB.commit(
			provider, proposals: [], signingKey: bob.signingKey,
			randomness: .generate(provider))
		groupB = commit.group
		#expect(groupB.context.epoch == limit)

		let restored = try Group.restore(from: try groupB.archive(), provider)
		#expect(restored.context.epoch == limit)
	}
}
