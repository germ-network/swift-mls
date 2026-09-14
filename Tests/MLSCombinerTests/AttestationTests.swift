import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import SecretBytes
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// The `AppDataUpdate` epoch attestation (draft §6.1): the `ApqInfoUpdate` payload, its
/// proposal round-trip and strict decode, and the FULL-commit verification against
/// actual post-commit epochs.
@Suite struct AttestationTests {
	typealias Support = CombinerTestSupport
	static let componentID: MLS.Extensions.ComponentID =
		MLS.Combiner.Codepoints.deployed.apqComponentID

	// MARK: payload + proposal round-trips

	@Test func apqInfoUpdateRoundTrips() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 7, pqEpoch: 3)
		var reader = MLS.Reader(try update.mlsEncoded())
		#expect(try MLS.Combiner.ApqInfoUpdate(from: &reader) == update)
		try reader.finish()
	}

	@Test func proposalRoundTripsThroughEnvelope() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 4, pqEpoch: 9)
		let appDataUpdate = try update.appDataUpdate(componentID: Self.componentID)
		#expect(appDataUpdate.componentID == Self.componentID)
		#expect(
			try MLS.Combiner.ApqInfoUpdate.decode(
				from: appDataUpdate, componentID: Self.componentID) == update)
	}

	@Test func decodeRejectsWrongComponentOpAndTrailing() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 1)
		let payload = try update.mlsEncoded()

		// Wrong component id.
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			try MLS.Combiner.ApqInfoUpdate.decode(
				from: MLS.Extensions.AppDataUpdate(
					componentID: MLS.Extensions.ComponentID(rawValue: 0xFF02),
					operation: .update(payload)),
				componentID: Self.componentID)
		}
		// Wrong op (remove).
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			try MLS.Combiner.ApqInfoUpdate.decode(
				from: MLS.Extensions.AppDataUpdate(
					componentID: Self.componentID, operation: .remove),
				componentID: Self.componentID)
		}
		// Trailing bytes after the payload.
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			try MLS.Combiner.ApqInfoUpdate.decode(
				from: MLS.Extensions.AppDataUpdate(
					componentID: Self.componentID,
					operation: .update(payload + Data([0]))),
				componentID: Self.componentID)
		}
	}

	// MARK: FULL-commit verification

	@Test func fullCommitAttestsBothEpochsAndVerifies() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let alice = try Support.member("alice")
			let bob = try Support.member("bob")
			let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)

			var aClassical = founder.classical
			var aPq = founder.pq
			var bClassical = peer.classical
			var bPq = peer.pq

			// PQ half first (draft §4.1): both sides advance to epoch 2, carrying the
			// {2, 2} attestation. (Alice is the founder; she commits on both halves.)
			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqEffects = try process(&bPq, pqCommit)
			#expect(bPq.context.epoch == 2)

			// Export + register the NEW PQ epoch's apq_psk on both sides, then fold it
			// into the classical FULL commit via a PreSharedKey proposal (draft
			// §6.2/§4.1) -- the binding under test.
			let founderApqPsk = try MLS.Combiner.ExportedPsk.export(
				from: &aPq, Support.provider, componentID: Self.componentID)
			var founderStore = MLS.Combiner.PSKStore()
			founderStore.register(founderApqPsk)

			let peerApqPsk = try MLS.Combiner.ExportedPsk.export(
				from: &bPq, Support.provider, componentID: Self.componentID)
			var peerStore = MLS.Combiner.PSKStore()
			peerStore.register(peerApqPsk)

			let nonce = Support.provider.randomBytes(Support.provider.hashSize)
			let classicalCommit = try commitAttestingAndBindingPsk(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2,
				psk: founderApqPsk, nonce: nonce, resolver: founderStore.resolver())

			let (resolver, record) = peerStore.recordingResolver()
			let classicalEffects = try process(
				&bClassical, classicalCommit, psk: resolver)
			#expect(bClassical.context.epoch == 2)

			let verified = try MLS.Combiner.verifyFullCommit(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: bClassical.context.epoch,
				pqEpoch: bPq.context.epoch,
				record: record, expected: peerApqPsk
			)
			#expect(verified == MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 2))
		}
	}

	@Test func verifyRejectsWrongObservedEpoch() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let alice = try Support.member("alice")
			let bob = try Support.member("bob")
			let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)
			var aClassical = founder.classical
			var aPq = founder.pq
			var bClassical = peer.classical
			var bPq = peer.pq

			let classicalCommit = try commitAttesting(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let classicalEffects = try process(&bClassical, classicalCommit)
			let pqEffects = try process(&bPq, pqCommit)

			// Attested {2,2}, but claim the classical half is at epoch 3.
			#expect(throws: MLS.Combiner.Error.attestationMismatch) {
				_ = try MLS.Combiner.verifyFullCommitAttestation(
					classicalEffects: classicalEffects, pqEffects: pqEffects,
					classicalEpoch: 3, pqEpoch: 2)
			}
		}
	}

	@Test func verifyRejectsDisagreeingCopies() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let alice = try Support.member("alice")
			let bob = try Support.member("bob")
			let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)
			var aClassical = founder.classical
			var aPq = founder.pq
			var bClassical = peer.classical
			var bPq = peer.pq

			// The two halves attest DIFFERENT pairs — classical says {2,2}, pq says {2,9}.
			let classicalCommit = try commitAttesting(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 9)
			let classicalEffects = try process(&bClassical, classicalCommit)
			let pqEffects = try process(&bPq, pqCommit)

			#expect(throws: MLS.Combiner.Error.attestationMismatch) {
				_ = try MLS.Combiner.verifyFullCommitAttestation(
					classicalEffects: classicalEffects, pqEffects: pqEffects,
					classicalEpoch: 2, pqEpoch: 2)
			}
		}
	}

	/// The draft caps a commit at one `AppDataUpdate`; two in one commit's effects is a
	/// bypassed rule, not a pick-one.
	@Test func extractRejectsMoreThanOneAttestation() throws {
		let a = try MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 2)
			.appDataUpdate(componentID: Self.componentID)
		let b = try MLS.Combiner.ApqInfoUpdate(tEpoch: 3, pqEpoch: 3)
			.appDataUpdate(componentID: Self.componentID)
		let effects = MLS.RFC9420.CommitEffects([.appDataUpdate(a), .appDataUpdate(b)])
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			_ = try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID)
		}
	}

	/// A commit carrying no `AppDataUpdate` (a PARTIAL) yields no attestation.
	@Test func extractReturnsNilForNoAttestation() throws {
		let effects = MLS.RFC9420.CommitEffects([.updated(leaf: MLS.LeafIndex(value: 0))])
		#expect(
			try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID) == nil)
	}

	// MARK: commit/process helpers (two-step handshake)

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
	/// referencing `psk` (draft §6.2/§4.1's PQ→classical binding) alongside the
	/// attestation, and resolves it via `resolver` on the committing (sending) side
	/// — the sender must fold the PSK into its own epoch-secret derivation too.
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
}
