import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

private typealias Support = CombinerTestSupport

/// The pair-level checks a combiner group enforces for draft-ietf-mls-combiner-02
/// on both establish and join: the halves are distinct sessions, each
/// half's `APQInfo` states the suites the halves actually run, both halves carry
/// the same members, and a join is adjudicable before it is adopted.
@Suite struct PairConformanceTests {

	// MARK: fixtures

	/// The shared fixtures run each pair's halves on two different cipher suites,
	/// as a conforming pair must.
	@Test func establishedPairRunsHalvesOnDistinctSuites() throws {
		Issue.record("pending")
	}

	// MARK: distinct halves

	/// `establish` refuses a classical and a PQ provider of the same cipher suite.
	@Test func establishRejectsEqualCipherSuites() throws {
		Issue.record("pending")
	}

	/// `establish` refuses two `HalfCreation`s carrying the same group id.
	@Test func establishRejectsEqualGroupIDs() throws {
		Issue.record("pending")
	}

	/// The pure pair check rejects an `APQInfo` naming the same suite for both
	/// halves, even when each half's observed suite agrees with it.
	@Test func checkAPQInfoConsistentRejectsEqualCipherSuites() throws {
		Issue.record("pending")
	}

	/// The pure pair check rejects an `APQInfo` naming the same group id for both
	/// halves, even when each half's observed group id agrees with it.
	@Test func checkAPQInfoConsistentRejectsEqualGroupIDs() throws {
		Issue.record("pending")
	}

	// MARK: truthful suites

	/// Each `APQInfo` suite field must equal the suite of the half it describes:
	/// `t_cipher_suite` against the classical group, `pq_cipher_suite` against the
	/// PQ group, each clause rejecting on its own.
	@Test func checkAPQInfoConsistentRejectsSuiteNotMatchingItsGroup() throws {
		Issue.record("pending")
	}

	/// A pair of real groups whose `APQInfo` misstates a half's cipher suite is
	/// rejected by `verifyPair`, the check `join` runs on every Welcome pair.
	@Test func verifyPairRejectsAPQInfoMisstatingASuite() throws {
		Issue.record("pending")
	}

	// MARK: establish membership

	/// `establish` refuses halves that would add different peers.
	@Test func establishRejectsDifferentPeerAcrossHalves() throws {
		Issue.record("pending")
	}

	/// `establish` refuses halves founded under different identities.
	@Test func establishRejectsDifferentFounderAcrossHalves() throws {
		Issue.record("pending")
	}

	// MARK: join adjudication

	/// `joining` reports, for each half, the roster, the Welcome's signer, the
	/// consumed KeyPackage, the group context and the joiner's own leaf — before
	/// anything is adopted.
	@Test func joiningReportsBothHalvesBeforeAdoption() throws {
		Issue.record("pending")
	}

	/// The applied pair is the founder's pair: same group ids and epochs per half,
	/// `verifyPair()` passes, the PSK store is empty, and a classical exported
	/// secret equals the founder's.
	@Test func joiningAppliesToTheFoundersPair() throws {
		Issue.record("pending")
	}

	/// `joining` runs the pair checks before handing anything back: a Welcome pair
	/// that binds the `apq_psk` but whose `APQInfo` misstates a half's suite throws
	/// `apqInfoMismatch` and yields no `PendingJoinPair`.
	@Test func joiningRejectsAPQInfoMisstatingASuite() throws {
		Issue.record("pending")
	}
}
