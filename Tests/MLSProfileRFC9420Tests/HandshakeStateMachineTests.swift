import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D17 slice 1 — the `Transition`/`PendingCommit` foundation (the interleaved-consumption
/// fix). `validating(commit:)` produces an epoch *delta*, and `apply(onto:)`
/// composes it onto the live group the application kept operating on, so
/// consumption made while the commit was pending is never rolled back and a
/// pending applied onto a diverged base is an error, not a fork.
@Suite("Handshake state machine (D17 §2/§4)")
struct HandshakeStateMachineTests {
	static let provider = ConstructedRejectionTests.provider

	/// The §4 invariant: the delta reads no message-secret state, so composing
	/// it onto a more-consumed live group preserves the interleaved
	/// consumption. Bob validates Alice's public commit, then decrypts an
	/// application message (consuming Alice's epoch-N generation on the live
	/// store), then applies. Replaying that message must fail — under the
	/// interleaved-consumption bug, `apply` would restore the validation-time store and the
	/// replay would succeed.
	@Test(
		"apply(onto:) preserves consumption made on the live group while the commit was pending"
	)
	func applyPreservesInterleavedConsumption() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var bob = pair.groupB
		var alice = pair.groupA

		let commitOut = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pubCommit) = commitOut.commit else {
			Issue.record("expected a public commit")
			return
		}
		let pending = try bob.validating(
			provider, commit: pubCommit, proposals: .init(), psk: { _ in nil })

		// Interleaved: Alice sends two epoch-N messages; Bob decrypts the first
		// (consuming generation 0 on his live store) before applying.
		let gen0 = try alice.protect(
			provider, applicationData: Data("hello".utf8),
			signingKey: pair.alice.signingKey)
		let gen1 = try alice.protect(
			provider, applicationData: Data("world".utf8),
			signingKey: pair.alice.signingKey)
		_ = try bob.unprotect(provider, message: gen0)

		bob = try pending.apply(onto: bob).group

		// The epoch-N store carried through apply reflects the consumption
		// *exactly*: generation 0's replay is rejected with the specific
		// consumed-generation error — not restored to a fresh store, as the
		// interleaved-consumption bug would, which would let the replay succeed.
		#expect(
			throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)
		) {
			_ = try bob.unprotect(provider, message: gen0)
		}
		// And the store is still *live*, not dead: generation 1, untouched before
		// apply, decrypts — proving apply preserved the live ratchet, not merely
		// broke it.
		let opened = try bob.unprotect(provider, message: gen1)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("world".utf8))
	}

	/// The other half of the §4 invariant: apply installs the NEW epoch's
	/// resumption PSK and replaces the exporter tree with only the new epoch's
	/// fresh one (single-epoch, draft-ietf-mls-extensions §4.4 forward secrecy),
	/// so a stale export or resumption secret cannot be resurrected across the
	/// advance.
	@Test(
		"apply(onto:) installs the new epoch's resumption PSK and a single fresh exporter tree"
	)
	func applyComposesResumptionPskAndExporterTree() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var bob = pair.groupB
		let alice = pair.groupA

		let commit = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pub) = commit.commit else {
			Issue.record("expected a public commit")
			return
		}
		let newEpoch = bob.context.epoch + 1
		let pending = try bob.validating(
			provider, commit: pub, proposals: .init(), psk: { _ in nil })
		bob = try pending.apply(onto: bob).group

		#expect(bob.context.epoch == newEpoch)
		#expect(bob.resumptionPsks[newEpoch] != nil)
		#expect(Array(bob.exporterTrees.keys) == [newEpoch])
	}

	/// A pending applied onto a live group that has moved past its base throws
	/// `staleBase` rather than forking — the check that turns "applying a
	/// superseded pending" (D-then-A) into an error.
	@Test("apply(onto:) throws staleBase once the live group has moved past the pending's base")
	func applyThrowsStaleBaseAfterAnotherCommit() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var bob = pair.groupB
		let alice = pair.groupA

		// Two distinct public commits from the same epoch-N base.
		let commitA = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		let commitD = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pubA) = commitA.commit,
			case .publicMessage(let pubD) = commitD.commit
		else {
			Issue.record("expected public commits")
			return
		}

		let pendingA = try bob.validating(
			provider, commit: pubA, proposals: .init(), psk: { _ in nil })
		let pendingD = try bob.validating(
			provider, commit: pubD, proposals: .init(), psk: { _ in nil })

		// D wins: applying it advances Bob past pendingA's base.
		bob = try pendingD.apply(onto: bob).group

		do {
			_ = try pendingA.apply(onto: bob)
			Issue.record("expected staleBase")
		} catch MLS.RFC9420.GroupError.staleBase {
			// expected
		}
	}

	/// The delta installs per-membership key material keyed by leaf index, so a
	/// pending applied onto a group whose local-membership *set* has changed
	/// since validation throws `membershipMismatch` rather than misplacing or
	/// dropping that material (D17 §4 L-2). Distinct from `staleBase`: the
	/// GroupContext is untouched, so only the membership check catches it.
	@Test("apply(onto:) throws membershipMismatch when the live local-membership set changed")
	func applyThrowsMembershipMismatchWhenLocalSetChanged() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var bob = pair.groupB
		let alice = pair.groupA

		let commit = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pub) = commit.commit else {
			Issue.record("expected a public commit")
			return
		}
		let pending = try bob.validating(
			provider, commit: pub, proposals: .init(), psk: { _ in nil })

		// A second local membership appears between validate and apply (context
		// unchanged, so `staleBase` does not fire).
		bob.memberships.append(
			MLS.RFC9420.Membership(leafIndex: MLS.LeafIndex(value: 7), secretKeys: [:]))
		do {
			_ = try pending.apply(onto: bob)
			Issue.record("expected membershipMismatch")
		} catch MLS.RFC9420.GroupError.membershipMismatch {
			// expected
		}
	}

	/// The lazy `Transition.snapshot()` (D17 §2/H2) is the persisted form of the
	/// state to adopt: it restores to a group one epoch past the base, and is
	/// byte-identical to snapshotting the adopted group directly.
	@Test("Transition.snapshot() persists the adopted, epoch-advanced group")
	func transitionSnapshotPersistsAdvancedGroup() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		let bob = pair.groupB
		let alice = pair.groupA

		let commit = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pub) = commit.commit else {
			Issue.record("expected a public commit")
			return
		}
		let baseEpoch = bob.context.epoch
		let pending = try bob.validating(
			provider, commit: pub, proposals: .init(), psk: { _ in nil })
		let transition = try pending.apply(onto: bob)

		let snapshot = try transition.snapshot()
		let restored = try MLS.RFC9420.Group.restore(from: snapshot, provider)
		#expect(restored.context.epoch == baseEpoch + 1)
		#expect(try restored.makeSnapshot() == (try transition.group.makeSnapshot()))
	}

	/// The two-step lets the application keep operating on the live group while a
	/// commit is pending — including proposing a self-Update, which stashes a
	/// pending-update secret. Applying the commit advances the epoch, which
	/// retires the whole pending-update set (forward secrecy), the interleaved
	/// proposal included — exercising `apply`'s `pendingUpdates` clearing.
	@Test("a self-Update proposed between validate and apply is retired by the epoch advance")
	func proposeUpdateBetweenValidateAndApplyIsCleared() throws {
		let provider = Self.provider
		let pair = try ProposalValidationTests.pair()
		var bob = pair.groupB
		let alice = pair.groupA

		let commit = try alice.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let pub) = commit.commit else {
			Issue.record("expected a public commit")
			return
		}
		let pending = try bob.validating(
			provider, commit: pub, proposals: .init(), psk: { _ in nil })

		_ = try bob.proposeUpdate(provider, signingKey: pair.bob.signingKey)
		#expect(bob.pendingUpdates != nil)

		bob = try pending.apply(onto: bob).group
		#expect(bob.pendingUpdates == nil)
	}
}
