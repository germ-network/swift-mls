import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D17 slice 3a — `committing` as a send-side transition. Sealing a private
/// commit spends the committer's own next handshake generation in the old
/// epoch; that consumption lives in `Transition.group`, which the caller adopts
/// before its next private send. Adopting it is what stops the committer from
/// reusing the generation (the §9.1 key/nonce-reuse the non-mutating
/// `committing` used to allow).
@Suite("Send-side commit transition (D17 §1.1)")
struct SentCommitTests {
	static let provider = ConstructedRejectionTests.provider

	/// The generation-reuse repro, both directions: after a private commit, a private
	/// send from the ADOPTED group uses the next generation (distinct from the
	/// commit's), while a private send from the PRE-commit value reuses the
	/// commit's generation — which a receiver rejects as already consumed.
	@Test(
		"a private send after committing uses the next generation from the adopted group, and reuses it from the pre-commit value"
	)
	func privateSendAfterCommitDoesNotReuseGeneration() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()

		// Alice commits privately — sealed at her handshake generation 0. The
		// committer stays put (committing never mutates); the consumption is in
		// the transition's group.
		let transition = try pair.groupA.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		guard case .privateMessage(let commitMessage) = transition.output.message
		else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}

		// Bob decrypts the commit, consuming Alice's handshake generation 0 on his
		// view of her chain.
		var bob = pair.groupB
		_ = try bob.unprotect(provider, message: commitMessage)

		// From the ADOPTED group, Alice's next private send is generation 1 — Bob
		// decrypts it fine (distinct generation).
		var aliceAdopted = transition.group
		let (goodProposal, _) = try aliceAdopted.proposeUpdate(
			provider, signingKey: pair.alice.signingKey, framing: .privateMessage)
		guard case .privateMessage(let goodMessage) = goodProposal else {
			Issue.record("expected a privateMessage-framed proposal")
			return
		}
		_ = try bob.unprotect(provider, message: goodMessage)

		// From the PRE-commit value — the generation-reuse bug: not adopting the
		// consumption — Alice's next private send REUSES generation 0. Bob rejects
		// it: that generation was already spent by the commit.
		var alicePreCommit = pair.groupA
		let (reusedProposal, _) = try alicePreCommit.proposeUpdate(
			provider, signingKey: pair.alice.signingKey, framing: .privateMessage)
		guard case .privateMessage(let reusedMessage) = reusedProposal else {
			Issue.record("expected a privateMessage-framed proposal")
			return
		}
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try bob.unprotect(provider, message: reusedMessage)
		}
	}

	/// The pending epoch advance applies onto the adopted group (which already
	/// holds the seal's consumption) exactly as a receiver applies one, and
	/// `staleBase` if a competing commit advanced the group first.
	@Test("SentCommit.pending applies onto the adopted group, and staleBase after a competitor")
	func pendingAppliesAfterAffirmation() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		let baseEpoch = pair.groupA.context.epoch

		let transition = try pair.groupA.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		let adopted = transition.group
		let advanced = try transition.takeOutput().takePending().apply(onto: adopted)
			.group
		#expect(advanced.context.epoch == baseEpoch + 1)

		// A second commit from the same base (the adopted old-epoch group), whose
		// pending is then stale against the already-advanced group.
		let competitor = try adopted.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		let stalePending = competitor.takeOutput().takePending()
		do {
			_ = try stalePending.apply(onto: advanced)
			Issue.record("expected staleBase")
		} catch MLS.RFC9420.GroupError.staleBase {
			// expected
		}
	}
}
