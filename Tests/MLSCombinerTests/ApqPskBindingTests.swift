import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import SecretBytes
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// The combiner's own security guarantee (draft-ietf-mls-combiner-02 §6.2/§4.1): the
/// classical (traditional) half of a join or FULL commit must actually fold the
/// `apq_psk` in via a `PreSharedKey` proposal, not merely carry `APQInfo` and the
/// epoch attestation alongside it. §6.2: "each T group commit that is part of a FULL
/// commit MUST include a PreSharedKey proposal with psk_type = application,
/// component_id = XXX and psk_id = apq_psk_id." §4.1: "the sender includes
/// information about the PSK in a PreSharedKey proposal for the traditional
/// session's Commit ... Receivers process the PQ Commit ... and then the
/// traditional Commit (which also includes the PSK proposal) to derive the new
/// epoch in the traditional session."
///
/// `AttestationTests.fullCommitAttestsBothEpochsAndVerifies` covers the positive
/// case (a conforming FULL commit that does bind the PSK); this file covers the
/// negative ones a non-conforming or buggy peer can produce.
@Suite struct ApqPskBindingTests {
	typealias Support = CombinerTestSupport
	static let componentID: MLS.Extensions.ComponentID =
		MLS.Combiner.Codepoints.deployed.apqComponentID

	// MARK: join

	/// A classical Welcome that carries `APQInfo` and the epoch attestation but NO
	/// `apq_psk` `PreSharedKey` proposal — the PQ half is unbound from the classical
	/// half's key schedule even though the pair otherwise looks legitimate. `join`
	/// must reject it, not silently accept a classical half that never folded the PQ
	/// secrecy in.
	@Test func joinRejectsClassicalWelcomeMissingPskProposal() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let welcome = try establishWithoutApqPskProposal(founder: alice, peer: bob)

		#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
			_ = try MLS.Combiner.CombinerGroup.join(
				welcome: welcome, classicalCredentials: bob.joinCredentials,
				pqCredentials: bob.joinCredentials,
				classicalProvider: Support.provider,
				pqProvider: Support.provider)
		}
	}

	/// A conforming founder half (with the PSK proposal) still joins cleanly — this
	/// pins that the new `apqPskNotBound` guard does not reject the legitimate path,
	/// complementing `CombinerGroupTests.establishAndJoinRoundTrips`.
	@Test func joinAcceptsClassicalWelcomeWithPskProposal() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (_, peer) = try Support.establishedPair(founder: alice, peer: bob)
		#expect(peer.classical.context.epoch == 1)
	}

	// MARK: FULL commit

	/// A classical commit that carries the epoch attestation but resolves no PSK at
	/// all (a PARTIAL-shaped classical commit masquerading as part of a FULL one) —
	/// `verifyApqPskBound` must reject it.
	@Test func verifyApqPskBoundRejectsNoResolution() throws {
		let store = MLS.Combiner.PSKStore()
		let (_, record) = store.recordingResolver()
		let expected = try MLS.Combiner.ExportedPsk.fromParts(
			componentID: Self.componentID, pskID: Data([1, 2, 3]),
			psk: SecretBytes(bytes: Data([4, 5, 6])))

		#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
			try MLS.Combiner.verifyApqPskBound(record: record, expected: expected)
		}
	}

	/// A classical commit that resolves a STALE `apq_psk` — real PSK value, but from
	/// an older PQ epoch's export, not the current one — must not satisfy the check.
	/// The storage id `ExportedPsk.export` derives is scoped to `(group, epoch,
	/// component)`, so a stale export's id differs from the current one's even
	/// though both are legitimate `apq_psk` exports of the same component.
	@Test func verifyApqPskBoundRejectsStaleEpoch() throws {
		let staleID = Data([0xAA])
		let currentID = Data([0xBB])
		let stale = try MLS.Combiner.ExportedPsk.fromParts(
			componentID: Self.componentID, pskID: staleID,
			psk: SecretBytes(bytes: Data([1, 2, 3])))
		let current = try MLS.Combiner.ExportedPsk.fromParts(
			componentID: Self.componentID, pskID: currentID,
			psk: SecretBytes(bytes: Data([4, 5, 6])))

		var store = MLS.Combiner.PSKStore()
		store.register(stale)
		let (resolver, record) = store.recordingResolver()

		// The commit's resolver only had the stale PSK to resolve.
		_ = try resolver(stale.preSharedKeyID(nonce: Data()))

		#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
			try MLS.Combiner.verifyApqPskBound(record: record, expected: current)
		}
	}

	/// The positive case at the `verifyApqPskBound` level, directly against
	/// `recordingResolver`: resolving the expected storage id satisfies the check.
	@Test func verifyApqPskBoundAcceptsMatchingResolution() throws {
		let expected = try MLS.Combiner.ExportedPsk.fromParts(
			componentID: Self.componentID, pskID: Data([9, 9, 9]),
			psk: SecretBytes(bytes: Data([1, 1, 1])))
		var store = MLS.Combiner.PSKStore()
		store.register(expected)
		let (resolver, record) = store.recordingResolver()

		_ = try resolver(expected.preSharedKeyID(nonce: Data()))
		try MLS.Combiner.verifyApqPskBound(record: record, expected: expected)
	}

	// MARK: founder half without the PSK proposal

	/// Mirrors `CombinerGroup.establish`, but the classical half's founding commit
	/// carries the epoch attestation and `APQInfo` while deliberately OMITTING the
	/// `apq_psk` `PreSharedKey` proposal — the non-conforming/buggy peer this
	/// finding is about. Only the resulting `APQWelcome` is needed by the tests
	/// above, so unlike `establish` this does not bother advancing past the
	/// founder's own committed (pre-apply) state.
	private func establishWithoutApqPskProposal(
		founder: CombinerTestSupport.Member, peer: CombinerTestSupport.Member
	) throws -> MLS.Combiner.APQWelcome {
		let codepoints = MLS.Combiner.Codepoints.deployed
		return try codepoints.withWireWidth {
			let classicalCreation = try Support.halfCreation(
				founder: founder, peer: peer)
			let pqCreation = try Support.halfCreation(founder: founder, peer: peer)
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: classicalCreation.groupID,
				pqSessionGroupID: pqCreation.groupID, mode: 0,
				tCipherSuite: Support.provider.cipherSuite,
				pqCipherSuite: Support.provider.cipherSuite, tEpoch: 1, pqEpoch: 1)
			let infoExtension = try info.asExtension(
				type: codepoints.apqInfoExtensionType)
			let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 1)
			let attestationProposal = MLS.RFC9420.ProposalOrRef.proposal(
				try attestation.proposal(componentID: codepoints.apqComponentID))

			// PQ half, exactly as `establish` builds it — unbound, as always.
			let pqEpoch0 = try MLS.RFC9420.Group.create(
				Support.provider, groupID: pqCreation.groupID,
				leafNode: pqCreation.leafNode,
				leafSecretKey: pqCreation.leafSecretKey,
				extensions: [infoExtension], epochSecret: pqCreation.epochSecret)
			let pqTransition = try pqEpoch0.committing(
				Support.provider,
				proposals: [
					.proposal(.add(pqCreation.peerKeyPackage)),
					attestationProposal,
				],
				signingKey: pqCreation.signingKey,
				randomness: pqCreation.randomness,
				psk: { _ in nil })
			guard let pqWelcome = pqTransition.takeOutput().welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}

			// Classical half: the attestation and APQInfo ride along, but the
			// apq_psk PreSharedKey proposal is deliberately dropped.
			let classicalEpoch0 = try MLS.RFC9420.Group.create(
				Support.provider, groupID: classicalCreation.groupID,
				leafNode: classicalCreation.leafNode,
				leafSecretKey: classicalCreation.leafSecretKey,
				extensions: [infoExtension],
				epochSecret: classicalCreation.epochSecret)
			let classicalTransition = try classicalEpoch0.committing(
				Support.provider,
				proposals: [
					.proposal(.add(classicalCreation.peerKeyPackage)),
					attestationProposal,
				],
				signingKey: classicalCreation.signingKey,
				randomness: classicalCreation.randomness, psk: { _ in nil })
			guard let classicalWelcome = classicalTransition.takeOutput().welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}

			return MLS.Combiner.APQWelcome(
				tWelcome: classicalWelcome, pqWelcome: pqWelcome)
		}
	}
}
