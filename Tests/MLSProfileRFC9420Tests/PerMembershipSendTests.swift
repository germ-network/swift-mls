import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D18 slice 3b — the per-membership send-ratchet split. Two local memberships
/// on one composite `Group` each hold their own send ratchet (on the
/// `Membership`, seeded from the shared `GroupCore` secret tree), so both can
/// send in the same epoch without sharing a generation — the capability the
/// N > 1 send guard used to fence off. This suite exercises the pure sends
/// (`protect` / `proposeUpdate`) and the committer-scoping guards; the N > 1
/// commit round-trip itself is `PerMembershipReceiveTests` (slice 4a).
@Suite("Per-membership send (D18 3b)")
struct PerMembershipSendTests {
	static let provider = ConstructedRejectionTests.provider

	/// Alice and Bob, in the same group, as two memberships of one composite.
	struct MultiFixture {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var multi: MLS.RFC9420.Group
		/// Standalone receiver views (each pristine, so it can open the other's
		/// message by deriving that sender's chain fresh).
		var aliceView: MLS.RFC9420.Group
		var bobView: MLS.RFC9420.Group
	}

	static func multi() throws -> MultiFixture {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		// One composite holding BOTH real memberships over the shared core.
		let composite = MLS.RFC9420.Group(
			core: groupA.core,
			memberships: [groupA.memberships[0], groupB.memberships[0]])
		return MultiFixture(
			alice: alice, bob: bob, multi: composite, aliceView: groupA,
			bobView: groupB)
	}

	@Test("two memberships send in the same epoch on independent ratchets")
	func twoMembershipsSendIndependently() throws {
		let provider = Self.provider
		var f = try Self.multi()
		let aliceLeaf = f.aliceView.myLeafIndex
		let bobLeaf = f.bobView.myLeafIndex

		let aMsg = try f.multi.protect(
			as: aliceLeaf, provider, applicationData: Data("from-alice".utf8),
			signingKey: f.alice.signingKey)
		let bMsg = try f.multi.protect(
			as: bobLeaf, provider, applicationData: Data("from-bob".utf8),
			signingKey: f.bob.signingKey)

		// Each membership spent its OWN generation 0 — the composite carries two
		// distinct send states, keyed to distinct leaves.
		let aIndex = try f.multi.membershipIndex(of: aliceLeaf)
		let bIndex = try f.multi.membershipIndex(of: bobLeaf)
		#expect(f.multi.memberships[aIndex].ownSend.nextGeneration(isHandshake: false) == 1)
		#expect(f.multi.memberships[bIndex].ownSend.nextGeneration(isHandshake: false) == 1)

		// Cross-decrypt on the pristine standalone views.
		let openedByBob = try f.bobView.unprotect(provider, message: aMsg)
		let openedByAlice = try f.aliceView.unprotect(provider, message: bMsg)
		guard case .application(let da) = openedByBob.content,
			case .application(let db) = openedByAlice.content
		else {
			Issue.record("expected application content")
			return
		}
		#expect(da == Data("from-alice".utf8))
		#expect(db == Data("from-bob".utf8))
	}

	@Test("a membership's own ratchet advances across its own sends")
	func ownRatchetAdvances() throws {
		let provider = Self.provider
		var f = try Self.multi()
		let aliceLeaf = f.aliceView.myLeafIndex

		let first = try f.multi.protect(
			as: aliceLeaf, provider, applicationData: Data("one".utf8),
			signingKey: f.alice.signingKey)
		let second = try f.multi.protect(
			as: aliceLeaf, provider, applicationData: Data("two".utf8),
			signingKey: f.alice.signingKey)
		let aIndex = try f.multi.membershipIndex(of: aliceLeaf)
		#expect(f.multi.memberships[aIndex].ownSend.nextGeneration(isHandshake: false) == 2)

		// Bob's view decrypts both — generation 0 then 1, no reuse.
		let opened0 = try f.bobView.unprotect(provider, message: first)
		let opened1 = try f.bobView.unprotect(provider, message: second)
		guard case .application(let d0) = opened0.content,
			case .application(let d1) = opened1.content
		else {
			Issue.record("expected application content")
			return
		}
		#expect(d0 == Data("one".utf8))
		#expect(d1 == Data("two".utf8))
	}

	@Test("a self-Update proposal is per-membership at N > 1")
	func perMembershipProposeUpdate() throws {
		let provider = Self.provider
		var f = try Self.multi()
		let bobLeaf = f.bobView.myLeafIndex

		let (message, _) = try f.multi.proposingUpdate(
			as: bobLeaf, provider, signingKey: f.bob.signingKey)
		let bIndex = try f.multi.membershipIndex(of: bobLeaf)
		let aIndex = try f.multi.membershipIndex(of: f.aliceView.myLeafIndex)
		// Only Bob's membership gained a pending self-Update.
		#expect(f.multi.memberships[bIndex].pendingUpdate != nil)
		#expect(f.multi.memberships[aIndex].pendingUpdate == nil)

		// Alice's standalone view accepts the proposal Bob framed.
		guard case .privateMessage(let framed) = message else {
			Issue.record("expected a privateMessage-framed proposal")
			return
		}
		let opened = try f.aliceView.unprotect(provider, message: framed)
		guard case .proposal = opened.content else {
			Issue.record("expected a proposal")
			return
		}
	}

	@Test("an N > 1 composite round-trips its per-membership send state through a snapshot")
	func multiMembershipSnapshotRoundTrips() throws {
		let provider = Self.provider
		var f = try Self.multi()
		let aliceLeaf = f.aliceView.myLeafIndex
		let bobLeaf = f.bobView.myLeafIndex

		// Alice sends twice, Bob once — three distinct own-ratchet positions.
		let a1 = try f.multi.protect(
			as: aliceLeaf, provider, applicationData: Data("a1".utf8),
			signingKey: f.alice.signingKey)
		let a2 = try f.multi.protect(
			as: aliceLeaf, provider, applicationData: Data("a2".utf8),
			signingKey: f.alice.signingKey)
		let bobSend = try f.multi.protect(
			as: bobLeaf, provider, applicationData: Data("b1".utf8),
			signingKey: f.bob.signingKey)

		var restored = try MLS.RFC9420.Group.restore(
			from: try f.multi.makeSnapshot(), provider)
		#expect(restored.memberships.count == 2)
		let aIndex = try restored.membershipIndex(of: aliceLeaf)
		let bIndex = try restored.membershipIndex(of: bobLeaf)
		#expect(
			restored.memberships[aIndex].ownSend.nextGeneration(isHandshake: false) == 2
		)
		#expect(
			restored.memberships[bIndex].ownSend.nextGeneration(isHandshake: false) == 1
		)

		// The restored composite continues Alice's ratchet at generation 2 — no
		// reuse of the two already sent. Bob's pristine view opens all three of
		// Alice's in order (generations 0, 1, 2); Alice's view opens Bob's.
		let a3 = try restored.protect(
			as: aliceLeaf, provider, applicationData: Data("a3".utf8),
			signingKey: f.alice.signingKey)
		var bobView = f.bobView
		for (message, expected) in [(a1, "a1"), (a2, "a2"), (a3, "a3")] {
			let opened = try bobView.unprotect(provider, message: message)
			guard case .application(let data) = opened.content else {
				Issue.record("expected application content")
				return
			}
			#expect(data == Data(expected.utf8))
		}
		let openedBob = try f.aliceView.unprotect(provider, message: bobSend)
		guard case .application(let db) = openedBob.content else {
			Issue.record("expected application content")
			return
		}
		#expect(db == Data("b1".utf8))
	}

	@Test("committing(as:) with the wrong membership's signing key is rejected, not forked")
	func committingWithMismatchedSigningKeyRejected() throws {
		let provider = Self.provider
		let f = try Self.multi()
		let bobLeaf = f.bobView.myLeafIndex
		// Commit AS Bob but sign with ALICE's key: the two `(as:)` / `signingKey:`
		// parameters disagree. Must fail loudly (the composite would otherwise fork
		// against a commit every remote member rejects), not advance.
		#expect(throws: MLS.CryptoError.self) {
			_ = try f.multi.committing(
				as: bobLeaf, provider, proposals: [],
				signingKey: f.alice.signingKey,
				randomness: .generate(provider))
		}
	}

	@Test("committing a Remove of a co-located membership evicts it (partial), not a throw")
	func committingRemoveOfLocalMembershipEvicts() throws {
		let provider = Self.provider
		let f = try Self.multi()
		let aliceLeaf = f.aliceView.myLeafIndex
		let bobLeaf = f.bobView.myLeafIndex
		let baseEpoch = f.multi.context.epoch
		// Alice commits a Remove of Bob — the OTHER local membership. Slice 4b: a
		// committer cannot remove itself (§12.2), so this is always a PARTIAL
		// eviction — Bob is dropped and reported, Alice (the committer) survives
		// and advances. (Non-mutating `committing` so we can read the pending.)
		let transition = try f.multi.committing(
			as: aliceLeaf, provider, proposals: [.proposal(.remove(bobLeaf))],
			signingKey: f.alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		let adopted = transition.group
		let sent = transition.takeOutput()
		let effects = sent.pending.effects.events
		#expect(effects.contains(.removed(leaf: bobLeaf)))
		#expect(effects.contains(.membershipRemoved(leaf: bobLeaf)))
		#expect(
			effects.contains(
				.epochAdvanced(
					from: baseEpoch, to: baseEpoch + 1, committer: aliceLeaf)))

		// Applying the pending drops Bob and keeps Alice (the survivor), advanced.
		let advanced = try sent.takePending().apply(onto: adopted).group
		#expect(advanced.memberships.map(\.leafIndex) == [aliceLeaf])
		#expect(advanced.context.epoch == baseEpoch + 1)
	}
}
