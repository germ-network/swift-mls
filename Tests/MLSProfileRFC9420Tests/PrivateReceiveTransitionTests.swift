import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D17 slice 2b — the private-receive transition family. Decrypting a
/// `PrivateMessage` advances a ratchet (a §9.2 consumption), so the receive
/// entries hand back a `Transition`: the `group` is the post-consumption state
/// to adopt, the `output` is the decrypted content / `CommitValidation` /
/// `VerifiedProposal`. `peeking` is the one read-only exception (no consumption,
/// application only).
@Suite("Private-receive transitions (D17 §1.1)")
struct PrivateReceiveTransitionTests {
	static let provider = ConstructedRejectionTests.provider

	/// The consumption-on-validate property, and its "decline keeps it consumed"
	/// corollary: `validating(commit:)` advances the receiver's ratchet at
	/// validation, so an application that adopts the transition's group but
	/// declines to apply the delta still rejects a replay of the same commit.
	@Test("validating(commit:) consumes at validation; declining still rejects a replay")
	func validatingPrivateCommitConsumesOnValidate() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		let alice = pair.groupA
		let bob = pair.groupB

		let commitOut = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		guard case .privateMessage(let privateCommit) = commitOut.output.message else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}

		// Decline: adopt the post-consumption group, drop the (valid) delta.
		var declined = try bob.validating(
			provider, commit: privateCommit, proposals: .init(), psk: { _ in nil }
		).group

		// The ratchet advanced at validation, so a replay of the same commit is
		// rejected — the consumption survived the decline.
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try declined.unprotect(provider, message: privateCommit)
		}
	}

	/// A `.pending` (valid) commit: adopt the group, then apply the delta to
	/// advance the epoch.
	@Test("validating(commit:) then apply advances the epoch")
	func validatingPrivateCommitThenApply() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		let alice = pair.groupA
		let bob = pair.groupB
		let baseEpoch = bob.context.epoch

		let commitOut = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		guard case .privateMessage(let privateCommit) = commitOut.output.message else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}

		let transition = try bob.validating(
			provider, commit: privateCommit, proposals: .init(), psk: { _ in nil })
		let consumed = transition.group
		switch transition.takeOutput() {
		case .pending(let pending):
			let advanced = try pending.apply(onto: consumed).group
			#expect(advanced.context.epoch == baseEpoch + 1)
		case .rejected(let rejection):
			Issue.record("expected .pending, got .rejected: \(rejection.reason)")
		}
	}

	/// An authentic but invalid commit is `.rejected`, not thrown: its
	/// consumption is kept (a §9.2 MUST — the AEAD opened), and the app (the AS)
	/// learns who sent it. Here Bob's proposal store lacks the referenced
	/// proposal Alice committed, so validation fails after a successful decrypt.
	@Test("an authentic-but-invalid commit is .rejected with its consumption kept")
	func validatingPrivateCommitRejectedKeepsConsumption() throws {
		let provider = Self.provider
		let pair = try ProposalValidationTests.pair()
		var alice = pair.groupA
		var bob = pair.groupB
		let aliceLeaf = alice.myLeafIndex
		let epoch = bob.context.epoch

		// Bob proposes (private); Alice verifies it and commits it by reference.
		let (proposalMessage, ref) = try bob.proposeUpdate(
			provider, signingKey: pair.bob.signingKey)
		guard case .privateMessage(let framedProposal) = proposalMessage else {
			Issue.record("expected a privateMessage-framed proposal")
			return
		}
		let verified = try alice.verifying(provider, proposal: framedProposal)
		alice = verified.group
		var aliceStore = MLS.RFC9420.ProposalStore()
		_ = try aliceStore.insert(verified.output, provider)
		let commitOut = try alice.committing(
			provider, proposals: [.reference(ref)], proposalStore: aliceStore,
			signingKey: pair.alice.signingKey, randomness: .generate(provider),
			framing: .privateMessage)
		guard case .privateMessage(let privateCommit) = commitOut.output.message else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}

		// Bob validates with an EMPTY store — the reference cannot resolve, so the
		// (authentically framed) commit is rejected AFTER its AEAD opened.
		let transition = try bob.validating(
			provider, commit: privateCommit, proposals: .init(), psk: { _ in nil })
		var adopted = transition.group
		switch transition.takeOutput() {
		case .pending:
			Issue.record("expected .rejected (Bob's store lacks the reference)")
		case .rejected(let rejection):
			#expect(rejection.sender == aliceLeaf)
			#expect(rejection.epoch == epoch)
		}

		// The consumption was kept on the adopted group: a replay is rejected.
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try adopted.unprotect(provider, message: privateCommit)
		}
	}

	/// `unprotecting` an application message consumes and carries the epoch-bound
	/// attribution 2a added; the transition's group reflects the consumption.
	@Test("unprotecting carries epoch-bound attribution and consumes")
	func unprotectingApplicationMessage() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var alice = pair.groupA
		let bob = pair.groupB
		let epoch = bob.context.epoch

		let message = try alice.protect(
			provider, applicationData: Data("hi".utf8),
			signingKey: pair.alice.signingKey)

		let transition = try bob.unprotecting(provider, message)
		#expect(transition.output.epoch == epoch)
		#expect(transition.output.sender == alice.myLeafIndex)
		guard case .application(let data) = transition.output.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("hi".utf8))

		// The transition's group has the consumption: replaying the same message
		// against it is rejected.
		var adopted = transition.group
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try adopted.unprotect(provider, message: message)
		}
	}

	/// The receive-side twin of the §4 interleaving invariant: a private commit's
	/// consumption is applied at validation, and an application message consumed
	/// on the adopted group afterward must survive the epoch advance too — the
	/// delta reads no message-secret state, so `apply` composes onto the
	/// more-consumed group.
	@Test("consumption interleaved between validate and apply survives the advance")
	func interleavedConsumptionSurvives() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var alice = pair.groupA
		let bob = pair.groupB

		let commitOut = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		guard case .privateMessage(let privateCommit) = commitOut.output.message else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}

		let transition = try bob.validating(
			provider, commit: privateCommit, proposals: .init(), psk: { _ in nil })
		var live = transition.group  // adopt the commit's consumption
		let outcome = transition.takeOutput()
		guard case .pending(let pending) = outcome else {
			Issue.record("expected .pending")
			return
		}

		// Interleave: Alice sends an epoch-N application message; Bob consumes it
		// on the live group before applying the commit.
		let appMessage = try alice.protect(
			provider, applicationData: Data("interleaved".utf8),
			signingKey: pair.alice.signingKey)
		live = try live.unprotecting(provider, appMessage).group

		var advanced = try pending.apply(onto: live).group
		// Both consumptions survived: the epoch advanced, and a replay of the
		// application message is rejected from the retained epoch-N store.
		#expect(advanced.context.epoch == bob.context.epoch + 1)
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try advanced.unprotect(provider, message: appMessage)
		}
	}

	/// `peeking` is read-only: it recovers application content without advancing
	/// the ratchet — `self`'s chains are untouched — so the same generation still
	/// opens for real afterward, and it refuses handshake content.
	@Test("peeking is read-only and refuses handshakes")
	func peekingReadOnly() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var alice = pair.groupA
		var bob = pair.groupB
		let epoch = bob.context.epoch

		let message = try alice.protect(
			provider, applicationData: Data("peek".utf8),
			signingKey: pair.alice.signingKey)

		let peeked = try bob.peeking(provider, message)
		guard case .application(let data) = peeked.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("peek".utf8))

		// Peeking touched nothing on `self`: the epoch's chains are still empty
		// (no bootstrap, no consumption leaked onto the live group).
		#expect(bob.messageSecrets[epoch]!.chains.isEmpty)

		// And the same message still opens for real.
		let opened = try bob.unprotect(provider, message: message)
		guard case .application(let again) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(again == Data("peek".utf8))

		// A handshake cannot be peeked (M5: no applicable handshake from a peek).
		let commitOut = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .privateMessage)
		guard case .privateMessage(let privateCommit) = commitOut.output.message else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}
		#expect(throws: MLS.RFC9420.GroupError.wrongContentType(.commit)) {
			_ = try bob.peeking(provider, privateCommit)
		}
	}

	/// `verifying(proposal:)` for a private-framed proposal is a transition too:
	/// it consumes and hands back a `VerifiedProposal` for the store.
	@Test("verifying(proposal:) private consumes and yields a VerifiedProposal")
	func verifyingPrivateProposal() throws {
		let provider = Self.provider
		let pair = try ProposalValidationTests.pair()
		var bob = pair.groupB
		let alice = pair.groupA

		let (proposalMessage, ref) = try bob.proposeUpdate(
			provider, signingKey: pair.bob.signingKey)
		guard case .privateMessage(let framedProposal) = proposalMessage else {
			Issue.record("expected a privateMessage-framed proposal")
			return
		}

		let transition = try alice.verifying(provider, proposal: framedProposal)
		var store = MLS.RFC9420.ProposalStore()
		let insertedRef = try store.insert(transition.output, provider)
		#expect(insertedRef == ref)

		// The transition's group consumed the generation: a replay is rejected.
		var adopted = transition.group
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try adopted.unprotect(provider, message: framedProposal)
		}
	}
}
