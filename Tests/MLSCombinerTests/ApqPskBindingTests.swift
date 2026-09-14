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

	/// A REAL stale-epoch case, not a hand-picked pskID mismatch: `ExportedPsk.export`
	/// really does derive a different storage id per PQ epoch of the same group and
	/// component. Export the apq_psk at the join epoch (1), advance the PQ half to
	/// epoch 2, and export again — the two storage ids differ. Then drive a FULL
	/// commit whose classical half references the STALE (epoch-1) apq_psk while the
	/// store holds both exports: `verifyApqPskBound`/`verifyFullCommit`, checked
	/// against the epoch-2 export, must reject it even though the epoch-1 PSK really
	/// was resolved.
	@Test func verifyApqPskBoundRejectsStaleEpoch() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let alice = try Support.member("alice")
			let bob = try Support.member("bob")

			// Raw (non-combiner) group pairs, NOT `Support.establishedPair`: `establish`
			// / `join` each export the apq_psk internally as part of founding the
			// classical half, which would already consume the epoch-1 component this
			// test needs to export itself.
			var (aPq, bPq) = try rawGroupPair(founder: alice, peer: bob)
			var (aClassical, bClassical) = try rawGroupPair(founder: alice, peer: bob)

			// Export the apq_psk at PQ epoch 1 (the join epoch) on both sides.
			let founderEpoch1Psk = try MLS.Combiner.ExportedPsk.export(
				from: &aPq, Support.provider, componentID: Self.componentID)
			let peerEpoch1Psk = try MLS.Combiner.ExportedPsk.export(
				from: &bPq, Support.provider, componentID: Self.componentID)

			// Advance the PQ half to epoch 2, carrying the {2, 2} attestation.
			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqEffects = try process(&bPq, pqCommit)
			#expect(bPq.context.epoch == 2)

			// Export again at epoch 2: a DIFFERENT storage id from epoch 1's, proving
			// `export` is genuinely epoch-scoped (not merely id-scoped).
			let founderEpoch2Psk = try MLS.Combiner.ExportedPsk.export(
				from: &aPq, Support.provider, componentID: Self.componentID)
			let peerEpoch2Psk = try MLS.Combiner.ExportedPsk.export(
				from: &bPq, Support.provider, componentID: Self.componentID)
			#expect(founderEpoch2Psk.storageID != founderEpoch1Psk.storageID)
			#expect(peerEpoch2Psk.storageID != peerEpoch1Psk.storageID)

			// Drive a FULL commit whose classical half references the STALE
			// (epoch-1) apq_psk. Both sides' stores hold BOTH exports, as a client
			// that retained an old export alongside the fresh one would.
			var founderStore = MLS.Combiner.PSKStore()
			founderStore.register(founderEpoch1Psk)
			founderStore.register(founderEpoch2Psk)
			var peerStore = MLS.Combiner.PSKStore()
			peerStore.register(peerEpoch1Psk)
			peerStore.register(peerEpoch2Psk)

			let nonce = Support.provider.randomBytes(Support.provider.hashSize)
			let classicalCommit = try commitAttestingAndBindingPsk(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2,
				psk: founderEpoch1Psk, nonce: nonce,
				resolver: founderStore.resolver())

			let (resolver, record) = peerStore.recordingResolver()
			let classicalEffects = try process(
				&bClassical, classicalCommit, psk: resolver)
			#expect(bClassical.context.epoch == 2)

			// The epoch-1 PSK really was resolved (a real, valid apq_psk — just the
			// wrong epoch), but checking against the epoch-2 export still rejects.
			#expect(record.resolved(peerEpoch1Psk.storageID))
			#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
				try MLS.Combiner.verifyApqPskBound(
					record: record, expected: peerEpoch2Psk)
			}
			#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
				_ = try MLS.Combiner.verifyFullCommit(
					classicalEffects: classicalEffects, pqEffects: pqEffects,
					classicalEpoch: bClassical.context.epoch,
					pqEpoch: bPq.context.epoch,
					record: record, expected: peerEpoch2Psk)
			}
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

	/// Integration negative for the FULL-commit path (not just a hand-built
	/// record): a classical commit carrying the epoch attestation but NO
	/// `PreSharedKey` proposal at all — `verifyFullCommitAttestation` passes (the
	/// attestation itself is well-formed and matches the observed epochs), but
	/// `verifyApqPskBound`/`verifyFullCommit` reject it, since the classical
	/// `validating` call resolved nothing.
	@Test func verifyFullCommitRejectsAttestationOnlyClassicalCommit() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let alice = try Support.member("alice")
			let bob = try Support.member("bob")
			let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)

			var aClassical = founder.classical
			var aPq = founder.pq
			var bClassical = peer.classical
			var bPq = peer.pq

			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqEffects = try process(&bPq, pqCommit)

			// Classical commit: attestation only, no PreSharedKey proposal.
			let classicalCommit = try commitAttesting(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let store = MLS.Combiner.PSKStore()
			let (resolver, record) = store.recordingResolver()
			let classicalEffects = try process(
				&bClassical, classicalCommit, psk: resolver)

			let expected = try MLS.Combiner.ExportedPsk.export(
				from: &bPq, Support.provider, componentID: Self.componentID)

			let verified = try MLS.Combiner.verifyFullCommitAttestation(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: bClassical.context.epoch, pqEpoch: bPq.context.epoch
			)
			#expect(verified == MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 2))

			#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
				try MLS.Combiner.verifyApqPskBound(
					record: record, expected: expected)
			}
			#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
				_ = try MLS.Combiner.verifyFullCommit(
					classicalEffects: classicalEffects, pqEffects: pqEffects,
					classicalEpoch: bClassical.context.epoch,
					pqEpoch: bPq.context.epoch,
					record: record, expected: expected)
			}
		}
	}

	// MARK: commit/process helpers (two-step handshake)

	/// A raw (non-combiner) RFC 9420 group pair at epoch 1, with nothing exported
	/// yet — a founder half and a peer half of the SAME group, via `create` +
	/// `committing` + `Group.joining`, no `APQInfo` or attestation involved.
	/// Deliberately NOT `CombinerGroup.establish`/`join`, which each export the
	/// apq_psk internally while founding the classical half — using either here
	/// would leave the epoch-1 component already consumed before a test gets a
	/// chance to export it itself.
	private func rawGroupPair(
		founder: CombinerTestSupport.Member, peer: CombinerTestSupport.Member
	) throws -> (founder: MLS.RFC9420.Group, peer: MLS.RFC9420.Group) {
		let creation = try Support.halfCreation(founder: founder, peer: peer)
		let epoch0 = try MLS.RFC9420.Group.create(
			Support.provider, groupID: creation.groupID, leafNode: creation.leafNode,
			leafSecretKey: creation.leafSecretKey, epochSecret: creation.epochSecret)
		let transition = try epoch0.committing(
			Support.provider,
			proposals: [.proposal(.add(creation.peerKeyPackage))],
			signingKey: creation.signingKey, randomness: creation.randomness,
			psk: { _ in nil })
		let adopted = transition.group
		let sent = transition.takeOutput()
		guard let welcome = sent.welcome else {
			throw MLS.Combiner.Error.missingWelcome
		}
		let founderGroup = try sent.takePending().apply(onto: adopted).group

		let pending = try MLS.RFC9420.Group.joining(
			Support.provider, welcome: welcome, credentials: peer.joinCredentials,
			psk: { _ in nil })
		let peerGroup = pending.apply().group
		return (founderGroup, peerGroup)
	}

	/// Commit an `ApqInfoUpdate` attestation only — no PreSharedKey proposal — the
	/// two-step handshake: adopt the `committing` transition's group, apply the
	/// pending advance onto it.
	private func commitAttesting(
		_ group: inout MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey,
		tEpoch: UInt64, pqEpoch: UInt64
	) throws -> MLS.RFC9420.Message {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: tEpoch, pqEpoch: pqEpoch)
		let transition = try group.committing(
			Support.provider,
			proposals: [
				.proposal(try attestation.proposal(componentID: Self.componentID))
			],
			signingKey: signingKey, randomness: .generate(Support.provider))
		let adopted = transition.group
		let sent = transition.takeOutput()
		let message = sent.message
		group = try sent.takePending().apply(onto: adopted).group
		return message
	}

	/// Like `commitAttesting`, but also includes a `PreSharedKey` proposal
	/// referencing `psk` alongside the attestation, and resolves it via `resolver`
	/// on the committing (sending) side — the sender must fold the PSK into its own
	/// epoch-secret derivation too.
	private func commitAttestingAndBindingPsk(
		_ group: inout MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey,
		tEpoch: UInt64, pqEpoch: UInt64,
		psk: MLS.Combiner.ExportedPsk, nonce: Data,
		resolver: @escaping (MLS.RFC9420.PreSharedKeyIdentifier) throws -> SecretBytes?
	) throws -> MLS.RFC9420.Message {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: tEpoch, pqEpoch: pqEpoch)
		let transition = try group.committing(
			Support.provider,
			proposals: [
				.proposal(psk.proposal(nonce: nonce)),
				.proposal(try attestation.proposal(componentID: Self.componentID)),
			],
			signingKey: signingKey, randomness: .generate(Support.provider),
			psk: resolver)
		let adopted = transition.group
		let sent = transition.takeOutput()
		let message = sent.message
		group = try sent.takePending().apply(onto: adopted).group
		return message
	}

	private func process(
		_ group: inout MLS.RFC9420.Group, _ message: MLS.RFC9420.Message,
		psk: @escaping (MLS.RFC9420.PreSharedKeyIdentifier) throws -> SecretBytes? = {
			_ in nil
		}
	) throws -> MLS.RFC9420.CommitEffects {
		guard case .privateMessage(let privateCommit) = message else {
			throw MLS.Combiner.Error.commitShapeMismatch
		}
		let transition = try group.validating(
			Support.provider, commit: privateCommit, proposals: .init(),
			psk: psk)
		let adopted = transition.group
		switch transition.takeOutput() {
		case .pending(let pending):
			let applied = try pending.apply(onto: adopted)
			group = applied.group
			return applied.output
		case .rejected(let rejection):
			throw rejection.reason
		}
	}

	// MARK: founder half without the PSK proposal

	/// Mirrors `CombinerGroup.establish`, but the classical half's founding commit
	/// carries the epoch attestation and `APQInfo` while deliberately OMITTING the
	/// `apq_psk` `PreSharedKey` proposal — the non-conforming/buggy peer case under
	/// test above. Only the resulting `APQWelcome` is needed by the tests above, so
	/// unlike `establish` this does not bother advancing past the founder's own
	/// committed (pre-apply) state.
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
