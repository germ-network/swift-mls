import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import Testing

@testable import MLSProfileRFC9420

/// The `.appDataUpdate` proposal seam (draft-ietf-mls-extensions §4.7, code point
/// 0x0008): the typed `Proposal` case and its wiring, that unknown proposal types
/// still hard-reject, that an `AppDataUpdate` commit is pathless-valid (§7.2.1 Path
/// Required N) and surfaces as a `CommitEffect`, and that the §4.7 list rule gates
/// commit construction.
@Suite("AppDataUpdate proposal seam (§4.7 / §7.2.1)")
struct AppDataUpdateProposalTests {
	static let provider = ConstructedRejectionTests.provider

	static func sendEffects(
		of transition: consuming MLS.RFC9420.Transition<MLS.RFC9420.SentCommit>
	) -> [MLS.RFC9420.CommitEffect] {
		transition.takeOutput().pending.effects.events
	}

	static func anUpdate(_ id: MLS.Extensions.ComponentID = 0xFF01)
		-> MLS.Extensions
		.AppDataUpdate
	{
		MLS.Extensions.AppDataUpdate(componentID: id, operation: .update(Data([1, 2, 3])))
	}

	// MARK: codec + classification

	@Test("KnownProposalType.appDataUpdate is 0x0008 and maps to the typed case")
	func typeMapping() {
		#expect(MLS.RFC9420.KnownProposalType.appDataUpdate.rawValue == 8)
		let proposal = MLS.RFC9420.Proposal.appDataUpdate(Self.anUpdate())
		#expect(proposal.type == MLS.RFC9420.ProposalType(.appDataUpdate))
	}

	/// It is an *extension* proposal type, so — unlike RFC 9420's seven — it is NOT
	/// a default type. A leaf that supports it lists it in `capabilities.proposals`;
	/// a group may require it via `required_capabilities`. This is the capability
	/// plumbing: the existing generic machinery covers it once the classification is
	/// right.
	@Test("appDataUpdate is not a default proposal type")
	func notADefaultProposalType() {
		#expect(
			!MLS.RFC9420.defaultProposalTypes.contains(
				MLS.RFC9420.ProposalType(.appDataUpdate)))
	}

	@Test("Proposal round-trips the typed .appDataUpdate case")
	func proposalRoundTrip() throws {
		for operation in [
			MLS.Extensions.AppDataUpdate.Operation.update(Data([9])), .remove,
		] {
			let proposal = MLS.RFC9420.Proposal.appDataUpdate(
				MLS.Extensions.AppDataUpdate(
					componentID: 0x1234, operation: operation))
			let bytes = try proposal.mlsEncoded()
			// ProposalType 0x0008, then the AppDataUpdate body (uint16 component_id).
			#expect(bytes.prefix(4) == Data([0x00, 0x08, 0x12, 0x34]))
			#expect(try MLS.RFC9420.Proposal(mlsEncoded: bytes) == proposal)
		}
	}

	/// The seam adds a typed case; it does NOT add an opaque-body path. An
	/// unrecognized proposal type is still a hard decode error.
	@Test("an unknown proposal type is still rejected (no opaque-body path added)")
	func unknownProposalTypeStillRejected() throws {
		var reader = MLS.Reader(Data([0x00, 0xFF]))  // ProposalType 0x00FF, unknown
		#expect(throws: MLS.RFC9420.WireError.unknownProposalType(0x00FF)) {
			try MLS.RFC9420.Proposal(from: &reader)
		}
	}

	// MARK: commit integration

	/// §7.2.1 Path Required N: a commit whose only proposal is an AppDataUpdate is
	/// valid with no UpdatePath, and the envelope surfaces as a `CommitEffect` for
	/// the application.
	@Test("an AppDataUpdate-only commit is pathless-valid and surfaces the effect (send)")
	func pathlessCommitSurfacesEffect() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let groupA = try SelfInteropTests.createGroup(alice)
		let update = Self.anUpdate()
		let transition = try groupA.committing(
			provider, proposals: [.proposal(.appDataUpdate(update))],
			signingKey: alice.signingKey, randomness: .generate(provider),
			includePath: false)
		#expect(Self.sendEffects(of: transition).contains(.appDataUpdate(update)))
	}

	/// The receiver validates and surfaces the same effect.
	@Test("a received AppDataUpdate commit surfaces the effect")
	func receivedCommitSurfacesEffect() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let update = Self.anUpdate()

		var alice = t.aliceView
		let out = try alice.commit(
			provider, proposals: [.proposal(.appDataUpdate(update))],
			signingKey: t.alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		guard case .publicMessage(let commit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}
		let pending = try t.bobView.validating(
			provider, commit: commit, proposals: .init(), psk: { _ in nil })
		#expect(pending.effects.events.contains(.appDataUpdate(update)))
	}

	/// §4.7: a proposal list that both updates and removes one component_id is
	/// invalid — and `committing` runs the list check, so a committer can't build
	/// it.
	@Test("a §4.7-violating AppDataUpdate list is rejected at commit construction")
	func conflictingListRejected() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let groupA = try SelfInteropTests.createGroup(alice)
		#expect(throws: MLS.Extensions.AppDataUpdate.ValidityError.updateAndRemove(0xFF01))
		{
			_ = try groupA.committing(
				provider,
				proposals: [
					.proposal(
						.appDataUpdate(
							.init(
								componentID: 0xFF01,
								operation: .update(Data([1])))
						)),
					.proposal(
						.appDataUpdate(
							.init(
								componentID: 0xFF01,
								operation: .remove))),
				],
				signingKey: alice.signingKey, randomness: .generate(provider))
		}
	}

	/// The receive-side twin: a hand-crafted commit (bypassing send-side
	/// validation) whose AppDataUpdate list violates §4.7 is rejected on process.
	/// `validateProposalList` runs before the path-required and confirmation-tag
	/// checks, so the garbage tag never matters — the §4.7 rule is what rejects it.
	@Test("a §4.7-violating AppDataUpdate list is rejected on receive")
	func conflictingListRejectedOnReceive() throws {
		let pair = try ConstructedRejectionTests.pair()
		let conflicting: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				.appDataUpdate(
					.init(componentID: 0xFF01, operation: .update(Data([1]))))),
			.proposal(.appDataUpdate(.init(componentID: 0xFF01, operation: .remove))),
		]
		var groupB = pair.groupB
		#expect(throws: MLS.Extensions.AppDataUpdate.ValidityError.updateAndRemove(0xFF01))
		{
			try groupB.process(
				Self.provider,
				commit: try ConstructedRejectionTests.craftedCommit(
					pair, proposals: conflicting, path: nil),
				proposals: .init(), psk: { _ in nil })
		}
	}
}
