import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
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

			// A FULL commit: both halves advance to epoch 2, each carrying the {2, 2}
			// attestation. (Alice is the founder; she commits on both halves.)
			let classicalCommit = try commitAttesting(
				&aClassical, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)
			let pqCommit = try commitAttesting(
				&aPq, signingKey: alice.signingKey, tEpoch: 2, pqEpoch: 2)

			let classicalEffects = try process(&bClassical, classicalCommit)
			let pqEffects = try process(&bPq, pqCommit)
			#expect(bClassical.context.epoch == 2)
			#expect(bPq.context.epoch == 2)

			let verified = try MLS.Combiner.verifyFullCommitAttestation(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: bClassical.context.epoch, pqEpoch: bPq.context.epoch
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

	// MARK: `.customProposal`-wrapped attestation (receiver opted `appDataUpdate`
	// into `customProposalTypes`)

	/// `extract` reads the same attestation whether the profile surfaces it as the
	/// typed `.appDataUpdate` effect or, under `customProposalTypes`, as the wrapped
	/// `.customProposal(type: .appDataUpdate, body:)` effect.
	@Test func extractAcceptsCustomProposalWrappedAttestation() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 5, pqEpoch: 6)
		let appDataUpdate = try update.appDataUpdate(componentID: Self.componentID)
		let body = try appDataUpdate.mlsEncoded()
		let effects = MLS.RFC9420.CommitEffects([
			.customProposal(type: MLS.RFC9420.ProposalType(.appDataUpdate), body: body)
		])
		#expect(
			try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID) == update)
	}

	/// A `.customProposal` at some other code point isn't a combiner attestation —
	/// `extract` skips it rather than trying to decode it as one.
	@Test func extractIgnoresCustomProposalAtDifferentType() throws {
		let effects = MLS.RFC9420.CommitEffects([
			.customProposal(
				type: MLS.RFC9420.ProposalType(.reInit), body: Data([1, 2, 3]))
		])
		#expect(
			try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID) == nil)

		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 2)
		let real = try update.appDataUpdate(componentID: Self.componentID)
		let mixed = MLS.RFC9420.CommitEffects([
			.customProposal(
				type: MLS.RFC9420.ProposalType(.reInit), body: Data([1, 2, 3])),
			.appDataUpdate(real),
		])
		#expect(
			try MLS.Combiner.ApqInfoUpdate.extract(
				from: mixed, componentID: Self.componentID) == update)
	}

	/// Trailing bytes after the wrapped `AppDataUpdate` within the `.customProposal`
	/// body are rejected the same way the typed path rejects trailing bytes.
	@Test func extractRejectsTrailingBytesInCustomProposalBody() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 5, pqEpoch: 6)
		let appDataUpdate = try update.appDataUpdate(componentID: Self.componentID)
		let body = try appDataUpdate.mlsEncoded() + Data([0])
		let effects = MLS.RFC9420.CommitEffects([
			.customProposal(type: MLS.RFC9420.ProposalType(.appDataUpdate), body: body)
		])
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			_ = try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID)
		}
	}

	/// The dedup guard applies across shapes: one typed `.appDataUpdate` plus one
	/// wrapped `.customProposal(type: .appDataUpdate)` is still two attestations.
	@Test func extractRejectsMixedShapeDuplicateAttestation() throws {
		let a = try MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 2)
			.appDataUpdate(componentID: Self.componentID)
		let bBody = try MLS.Combiner.ApqInfoUpdate(tEpoch: 3, pqEpoch: 3)
			.appDataUpdate(componentID: Self.componentID)
			.mlsEncoded()
		let effects = MLS.RFC9420.CommitEffects([
			.appDataUpdate(a),
			.customProposal(
				type: MLS.RFC9420.ProposalType(.appDataUpdate), body: bBody),
		])
		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			_ = try MLS.Combiner.ApqInfoUpdate.extract(
				from: effects, componentID: Self.componentID)
		}
	}

	/// `verifyFullCommitAttestation` succeeds when both halves surface the wrapped
	/// `.customProposal(type: .appDataUpdate)` shape, built by hand like the other
	/// `CommitEffects`-constructing tests above (no need to drive a real commit under
	/// `customProposalTypes` for this unit-level check).
	@Test func verifyFullCommitAttestationAcceptsCustomProposalShape() throws {
		let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 2)
		let body = try update.appDataUpdate(componentID: Self.componentID).mlsEncoded()
		let effect = MLS.RFC9420.CommitEffect.customProposal(
			type: MLS.RFC9420.ProposalType(.appDataUpdate), body: body)
		let classicalEffects = MLS.RFC9420.CommitEffects([effect])
		let pqEffects = MLS.RFC9420.CommitEffects([effect])

		let verified = try MLS.Combiner.verifyFullCommitAttestation(
			classicalEffects: classicalEffects, pqEffects: pqEffects,
			classicalEpoch: 2, pqEpoch: 2)
		#expect(verified == update)
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

	private func process(
		_ group: inout MLS.RFC9420.Group, _ message: MLS.RFC9420.Message
	) throws -> MLS.RFC9420.CommitEffects {
		guard case .privateMessage(let privateCommit) = message else {
			throw MLS.Combiner.Error.commitShapeMismatch
		}
		let transition = try group.validating(
			Support.provider, commit: privateCommit, proposals: .init(),
			psk: { _ in nil })
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
