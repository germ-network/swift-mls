import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// The `CombinerGroup` pair: PQ-first establishment/join (the `apq_psk` PQ→classical
/// binding), `APQInfo` pair verification, membership consistency, and state export.
@Suite struct CombinerGroupTests {
	typealias Support = CombinerTestSupport

	/// Establish a pair and join it from the APQWelcome. A successful classical-half
	/// join is itself the `apq_psk` round-trip: the classical creation commit bound the
	/// PSK exported off the PQ half, and the Welcome's confirmation tag binds the epoch
	/// secret the PSK feeds — so `join` only succeeds if the joiner re-derived the same
	/// `apq_psk` off its own PQ half and resolved it. Both halves land at epoch 1 and
	/// converge.
	@Test func establishAndJoinRoundTrips() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)

		#expect(founder.classical.context.epoch == 1)
		#expect(founder.pq.context.epoch == 1)
		#expect(peer.classical.context.epoch == 1)
		#expect(peer.pq.context.epoch == 1)

		// Both parties derived the same epoch on each half — the classical half's
		// epoch secret includes the apq_psk, so this is the PQ→classical binding
		// converging.
		#expect(founder.classical.context == peer.classical.context)
		#expect(founder.pq.context == peer.pq.context)
		#expect(
			founder.classical.epoch.epochAuthenticator
				== peer.classical.epoch.epochAuthenticator)
		#expect(
			founder.pq.epoch.epochAuthenticator == peer.pq.epoch.epochAuthenticator)
	}

	/// `APQInfo` rides both halves' Welcomes: the joiner reads a `0xF0A1` extension out
	/// of each half's GroupContext, the identity fields agree across halves, each names
	/// the joined group and epoch — i.e. `verifyPair()` holds for the joiner.
	@Test func apqInfoRidesTheWelcome() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (_, peer) = try Support.establishedPair(founder: alice, peer: bob)

		let classicalInfo = try MLS.Combiner.APQInfo.read(
			fromExtensionsOf: peer.classical.context,
			type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)
		let pqInfo = try MLS.Combiner.APQInfo.read(
			fromExtensionsOf: peer.pq.context,
			type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)
		let classical = try #require(classicalInfo)
		let pq = try #require(pqInfo)

		#expect(classical.identityFieldsMatch(pq))
		#expect(classical.tSessionGroupID == peer.classical.context.groupID)
		#expect(classical.pqSessionGroupID == peer.pq.context.groupID)
		#expect(classical.tEpoch == 1)
		#expect(classical.pqEpoch == 1)
		// The joiner's verification passes end to end.
		try peer.verifyPair()
	}

	/// A pair whose halves name different PQ group ids (a spliced/mismatched Welcome)
	/// fails `verifyPair`.
	@Test func verifyPairRejectsMismatchedHalves() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, _) = try Support.establishedPair(founder: alice, peer: bob)
		let carol = try Support.member("carol")
		let dave = try Support.member("dave")
		let (other, _) = try Support.establishedPair(founder: carol, peer: dave)

		// Graft `other`'s PQ half onto `founder`'s classical half: the APQInfo copies
		// no longer name the same pair.
		var spliced = founder
		spliced.pq = other.pq
		#expect(throws: MLS.Combiner.Error.apqInfoMismatch) { try spliced.verifyPair() }
	}

	/// Membership consistency is set-equality of Basic identifiers, order-independent,
	/// with NO party-count constraint: three equal members pass (the `== 2` restriction
	/// is downstream policy, deliberately absent here).
	@Test func membershipConsistentIsSetEqualityWithoutCount() throws {
		let a2 = [
			Support.rosterEntry("alice", leaf: 0), Support.rosterEntry("bob", leaf: 1),
		]
		let b2 = [
			Support.rosterEntry("bob", leaf: 3), Support.rosterEntry("alice", leaf: 7),
		]
		// Equal sets, shuffled order and different leaf indices — consistent.
		try MLS.Combiner.CombinerGroup.checkMembershipConsistent(a2, b2)

		// Three equal members — passes (no ==2 restriction).
		let a3 = [
			Support.rosterEntry("alice", leaf: 0), Support.rosterEntry("bob", leaf: 1),
			Support.rosterEntry("carol", leaf: 2),
		]
		let b3 = [
			Support.rosterEntry("carol", leaf: 5),
			Support.rosterEntry("alice", leaf: 6),
			Support.rosterEntry("bob", leaf: 9),
		]
		try MLS.Combiner.CombinerGroup.checkMembershipConsistent(a3, b3)
	}

	/// Divergent rosters (different identity sets, or different sizes) are rejected.
	@Test func membershipInconsistentRejects() throws {
		let a = [
			Support.rosterEntry("alice", leaf: 0), Support.rosterEntry("bob", leaf: 1),
		]
		let bDifferent = [
			Support.rosterEntry("alice", leaf: 0),
			Support.rosterEntry("mallory", leaf: 1),
		]
		#expect(throws: MLS.Combiner.Error.membershipInconsistent) {
			try MLS.Combiner.CombinerGroup.checkMembershipConsistent(a, bDifferent)
		}
		let bShorter = [Support.rosterEntry("alice", leaf: 0)]
		#expect(throws: MLS.Combiner.Error.membershipInconsistent) {
			try MLS.Combiner.CombinerGroup.checkMembershipConsistent(a, bShorter)
		}
	}

	/// A joined pair's real rosters are consistent across halves.
	@Test func joinedPairRostersAreConsistent() throws {
		// `join` runs `checkMembershipConsistent` internally, so a successful join is
		// the assertion; here we also confirm both halves carry two members.
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, _) = try Support.establishedPair(founder: alice, peer: bob)
		#expect(founder.classical.tree.nonBlankLeaves().count == 2)
		#expect(founder.pq.tree.nonBlankLeaves().count == 2)
	}

	/// Export both halves' state and restore; the restored pair carries the same
	/// contexts and still passes `verifyPair`.
	@Test func stateExportRestoreRoundTrips() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, _) = try Support.establishedPair(founder: alice, peer: bob)

		let state = try founder.exportState()
		let restored = try MLS.Combiner.CombinerGroup.restore(
			from: state, classicalProvider: Support.provider,
			pqProvider: Support.provider)

		#expect(restored.classical.context == founder.classical.context)
		#expect(restored.pq.context == founder.pq.context)
		try restored.verifyPair()
	}
}
