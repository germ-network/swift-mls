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
		let (founder, peer) = try Support.establishedPair(
			founder: try Support.member("alice"), peer: try Support.member("bob"))
		for group in [founder, peer] {
			#expect(group.classical.context.cipherSuite == Support.provider.cipherSuite)
			#expect(group.pq.context.cipherSuite == Support.pqProvider.cipherSuite)
			#expect(group.classical.context.cipherSuite != group.pq.context.cipherSuite)
		}
	}

	// MARK: distinct halves

	/// `establish` refuses a classical and a PQ provider of the same cipher suite.
	@Test func establishRejectsEqualCipherSuites() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		#expect(throws: MLS.Combiner.Error.halvesNotDistinct) {
			_ = try MLS.Combiner.CombinerGroup.establish(
				classical: try Support.halfCreation(founder: alice, peer: bob),
				pq: try Support.halfCreation(founder: alice, peer: bob),
				mode: 0, classicalProvider: Support.provider,
				pqProvider: Support.provider)
		}
	}

	/// `establish` refuses two `HalfCreation`s carrying the same group id.
	@Test func establishRejectsEqualGroupIDs() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let classical = try Support.halfCreation(founder: alice, peer: bob)
		var pq = try Support.halfCreation(founder: alice, peer: bob, half: .pq)
		pq.groupID = classical.groupID
		#expect(throws: MLS.Combiner.Error.halvesNotDistinct) {
			_ = try MLS.Combiner.CombinerGroup.establish(
				classical: classical, pq: pq, mode: 0,
				classicalProvider: Support.provider, pqProvider: Support.pqProvider)
		}
	}

	/// The pure pair check rejects an `APQInfo` naming the same suite for both
	/// halves, even when each half's observed suite agrees with it.
	@Test func checkAPQInfoConsistentRejectsEqualCipherSuites() throws {
		let (classicalID, pqID) = (Data([1, 2, 3]), Data([4, 5, 6]))
		let suite = MLS.CipherSuite(id: 1)
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: classicalID, pqSessionGroupID: pqID, mode: 0,
			tCipherSuite: suite, pqCipherSuite: suite, tEpoch: 1, pqEpoch: 1)
		#expect(throws: MLS.Combiner.Error.halvesNotDistinct) {
			try MLS.Combiner.CombinerGroup.checkAPQInfoConsistent(
				classicalInfo: info, pqInfo: info,
				classicalObserved: (groupID: classicalID, epoch: 1, cipherSuite: suite),
				pqObserved: (groupID: pqID, epoch: 1, cipherSuite: suite))
		}
	}

	/// The pure pair check rejects an `APQInfo` naming the same group id for both
	/// halves, even when each half's observed group id agrees with it.
	@Test func checkAPQInfoConsistentRejectsEqualGroupIDs() throws {
		let groupID = Data([1, 2, 3])
		let (classicalSuite, pqSuite) = (MLS.CipherSuite(id: 1), MLS.CipherSuite(id: 3))
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: groupID, pqSessionGroupID: groupID, mode: 0,
			tCipherSuite: classicalSuite, pqCipherSuite: pqSuite, tEpoch: 1, pqEpoch: 1)
		#expect(throws: MLS.Combiner.Error.halvesNotDistinct) {
			try MLS.Combiner.CombinerGroup.checkAPQInfoConsistent(
				classicalInfo: info, pqInfo: info,
				classicalObserved: (
					groupID: groupID, epoch: 1, cipherSuite: classicalSuite
				),
				pqObserved: (groupID: groupID, epoch: 1, cipherSuite: pqSuite))
		}
	}

	// MARK: truthful suites

	/// Each `APQInfo` suite field must equal the suite of the half it describes:
	/// `t_cipher_suite` against the classical group, `pq_cipher_suite` against the
	/// PQ group, each clause rejecting on its own.
	@Test func checkAPQInfoConsistentRejectsSuiteNotMatchingItsGroup() throws {
		let (classicalID, pqID) = (Data([1, 2, 3]), Data([4, 5, 6]))
		let (suite1, suite3) = (MLS.CipherSuite(id: 1), MLS.CipherSuite(id: 3))
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: classicalID, pqSessionGroupID: pqID, mode: 0,
			tCipherSuite: suite1, pqCipherSuite: suite3, tEpoch: 1, pqEpoch: 1)
		func check(classicalSuite: MLS.CipherSuite, pqSuite: MLS.CipherSuite) throws {
			try MLS.Combiner.CombinerGroup.checkAPQInfoConsistent(
				classicalInfo: info, pqInfo: info,
				classicalObserved: (
					groupID: classicalID, epoch: 1, cipherSuite: classicalSuite
				),
				pqObserved: (groupID: pqID, epoch: 1, cipherSuite: pqSuite))
		}

		try check(classicalSuite: suite1, pqSuite: suite3)
		// `t_cipher_suite` alone disagrees with the classical group.
		#expect(throws: MLS.Combiner.Error.apqInfoMismatch) {
			try check(classicalSuite: suite3, pqSuite: suite3)
		}
		// `pq_cipher_suite` alone disagrees with the PQ group.
		#expect(throws: MLS.Combiner.Error.apqInfoMismatch) {
			try check(classicalSuite: suite1, pqSuite: suite1)
		}
	}

	/// A pair of real groups whose `APQInfo` misstates a half's cipher suite is
	/// rejected by `verifyPair`, the check `join` runs on every Welcome pair.
	@Test func verifyPairRejectsAPQInfoMisstatingASuite() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let classicalCreation = try Support.halfCreation(founder: alice, peer: bob)
		let pqCreation = try Support.halfCreation(founder: alice, peer: bob, half: .pq)
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: classicalCreation.groupID,
			pqSessionGroupID: pqCreation.groupID, mode: 0,
			tCipherSuite: Support.pqProvider.cipherSuite,
			pqCipherSuite: Support.provider.cipherSuite, tEpoch: 0, pqEpoch: 0)
		let infoExtension = try info.asExtension(
			type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)
		let classical = try MLS.RFC9420.Group.create(
			Support.provider, groupID: classicalCreation.groupID,
			leafNode: classicalCreation.leafNode,
			leafSecretKey: classicalCreation.leafSecretKey,
			extensions: [infoExtension], epochSecret: classicalCreation.epochSecret)
		let pq = try MLS.RFC9420.Group.create(
			Support.pqProvider, groupID: pqCreation.groupID,
			leafNode: pqCreation.leafNode, leafSecretKey: pqCreation.leafSecretKey,
			extensions: [infoExtension], epochSecret: pqCreation.epochSecret)
		let pair = MLS.Combiner.CombinerGroup(
			classical: classical, pq: pq, pskStore: MLS.Combiner.PSKStore(),
			codepoints: .deployed)
		#expect(throws: MLS.Combiner.Error.apqInfoMismatch) { try pair.verifyPair() }
	}

	// MARK: establish membership

	/// `establish` refuses halves that would add different peers.
	@Test func establishRejectsDifferentPeerAcrossHalves() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let carol = try Support.member("carol")
		#expect(throws: MLS.Combiner.Error.membershipInconsistent) {
			_ = try MLS.Combiner.CombinerGroup.establish(
				classical: try Support.halfCreation(founder: alice, peer: bob),
				pq: try Support.halfCreation(founder: alice, peer: carol, half: .pq),
				mode: 0, classicalProvider: Support.provider,
				pqProvider: Support.pqProvider)
		}
	}

	/// `establish` refuses halves founded under different identities.
	@Test func establishRejectsDifferentFounderAcrossHalves() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let carol = try Support.member("carol")
		#expect(throws: MLS.Combiner.Error.membershipInconsistent) {
			_ = try MLS.Combiner.CombinerGroup.establish(
				classical: try Support.halfCreation(founder: alice, peer: bob),
				pq: try Support.halfCreation(founder: carol, peer: bob, half: .pq),
				mode: 0, classicalProvider: Support.provider,
				pqProvider: Support.pqProvider)
		}
	}

	// MARK: join adjudication

	/// `joining` reports, for each half, the roster, the Welcome's signer, the
	/// consumed KeyPackage, the group context and the joiner's own leaf — before
	/// anything is adopted.
	@Test func joiningReportsBothHalvesBeforeAdoption() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let welcome = try Support.welcomePair(founder: alice, peer: bob)
		let pending = try MLS.Combiner.CombinerGroup.joining(
			welcome: welcome, classicalCredentials: bob.joinCredentials,
			pqCredentials: bob.pqJoinCredentials, classicalProvider: Support.provider,
			pqProvider: Support.pqProvider)
		let identities = [Support.credential("alice"), Support.credential("bob")]
		let halves = [
			(pending.classical, Support.provider, bob.keyPackage),
			(pending.pq, Support.pqProvider, bob.pqKeyPackage),
		]
		for (half, provider, keyPackage) in halves {
			#expect(half.signer.value == 0)
			#expect(half.myLeafIndex.value == 1)
			#expect(half.consumedKeyPackage == (try keyPackage.reference(provider)))
			#expect(half.context.cipherSuite == provider.cipherSuite)
			#expect(half.roster.map(\.presentation.credential) == identities)
		}
		#expect(pending.classical.context.groupID != pending.pq.context.groupID)
		#expect(pending.classical.consumedKeyPackage != pending.pq.consumedKeyPackage)
	}

	/// `joining` refuses a Welcome pair whose halves were founded by different
	/// members.
	@Test func joiningRejectsDifferentFounderAcrossHalves() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let carol = try Support.member("carol")
		let welcome = try Support.welcomePair(founder: alice, peer: bob, pqFounder: carol)
		#expect(throws: MLS.Combiner.Error.membershipInconsistent) {
			_ = try MLS.Combiner.CombinerGroup.joining(
				welcome: welcome, classicalCredentials: bob.joinCredentials,
				pqCredentials: bob.pqJoinCredentials,
				classicalProvider: Support.provider, pqProvider: Support.pqProvider)
		}
	}

	/// The applied pair is the founder's pair: same group ids and epochs per half,
	/// `verifyPair()` passes, the PSK store is empty, and a classical exported
	/// secret equals the founder's.
	@Test func joiningAppliesToTheFoundersPair() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let classicalCreation = try Support.halfCreation(founder: alice, peer: bob)
		let pqCreation = try Support.halfCreation(founder: alice, peer: bob, half: .pq)
		let (founder, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: classicalCreation, pq: pqCreation, mode: 0,
			classicalProvider: Support.provider, pqProvider: Support.pqProvider)
		let joined = try MLS.Combiner.CombinerGroup.joining(
			welcome: welcome, classicalCredentials: bob.joinCredentials,
			pqCredentials: bob.pqJoinCredentials, classicalProvider: Support.provider,
			pqProvider: Support.pqProvider).apply()
		#expect(joined.classical.context.groupID == founder.classical.context.groupID)
		#expect(joined.pq.context.groupID == founder.pq.context.groupID)
		#expect(joined.classical.context.epoch == founder.classical.context.epoch)
		#expect(joined.pq.context.epoch == founder.pq.context.epoch)
		try joined.verifyPair()

		// The apq_psk is forgotten: an independent re-derivation of it resolves
		// from the joined pair's store.
		var independentPq = try MLS.RFC9420.Group.joining(
			Support.pqProvider, welcome: welcome.pqWelcome,
			credentials: bob.pqJoinCredentials, psk: { _ in nil }
		).apply().group
		let apqPsk = try MLS.Combiner.ExportedPsk.export(
			from: &independentPq, Support.pqProvider,
			componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
		let id = apqPsk.preSharedKeyID(
			nonce: Support.provider.randomBytes(Support.provider.hashSize))
		#expect(try joined.pskStore.resolver()(id) == nil)
		let secret = { (group: MLS.Combiner.CombinerGroup) in
			try group.classical.exportSecret(
				Support.provider, label: "joining", context: Data(), length: 32)
		}
		#expect(try secret(joined) == secret(founder))
	}

	/// `joining` runs the pair checks before handing anything back: a Welcome pair
	/// that binds the `apq_psk` but whose `APQInfo` misstates a half's suite throws
	/// `apqInfoMismatch` and yields no `PendingJoinPair`.
	@Test func joiningRejectsAPQInfoMisstatingASuite() throws {
		let (alice, bob) = (try Support.member("alice"), try Support.member("bob"))
		let welcome = try Support.welcomePair(founder: alice, peer: bob) { classicalID, pqID in
			MLS.Combiner.APQInfo(
				tSessionGroupID: classicalID, pqSessionGroupID: pqID, mode: 0,
				tCipherSuite: Support.pqProvider.cipherSuite,
				pqCipherSuite: Support.provider.cipherSuite, tEpoch: 1, pqEpoch: 1)
		}
		#expect(throws: MLS.Combiner.Error.apqInfoMismatch) {
			_ = try MLS.Combiner.CombinerGroup.joining(
			welcome: welcome, classicalCredentials: bob.joinCredentials,
			pqCredentials: bob.pqJoinCredentials, classicalProvider: Support.provider,
			pqProvider: Support.pqProvider)
		}
	}
}
