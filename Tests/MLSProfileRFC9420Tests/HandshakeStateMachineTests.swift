import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D17 slice 1 — the `Transition`/`PendingCommit` foundation (the H1/GER-2413
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
	/// H1/GER-2413 bug, `apply` would restore the validation-time store and the
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

		// Interleaved: Alice sends, Bob decrypts — consuming Alice's epoch-N
		// application generation on Bob's live store.
		let message = try alice.protect(
			provider, applicationData: Data("hello".utf8),
			signingKey: pair.alice.signingKey)
		_ = try bob.unprotect(provider, message: message)

		bob = try pending.apply(onto: bob).group

		// The retained epoch-N store still reflects the consumption: a replay of
		// the same message is rejected.
		#expect(throws: (any Error).self) {
			_ = try bob.unprotect(provider, message: message)
		}
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
}
