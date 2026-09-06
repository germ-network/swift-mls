import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D18 slice 4a — per-membership receive. A composite `Group` holding N local
/// memberships processes a commit by decapping the commit's path **once per
/// membership**, against each membership's own held keys, and installs each
/// membership's new-epoch path keys. Every membership must recover the same
/// whole-group `commit_secret` (a divergence rejects the commit), and the epoch
/// advances once. This is what lifts the N > 1 fences on `validatedDelta`,
/// `committing`, and the sender-side `apply`.
@Suite("Per-membership receive (D18 4a)")
struct PerMembershipReceiveTests {
	static let provider = ConstructedRejectionTests.provider

	/// A 3-member group (Alice, Bob, Carol) with Alice and Bob as two local
	/// memberships of one composite, plus Carol's standalone remote view — the
	/// remote committer these tests receive from. All are at the same epoch.
	struct Trio {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var carol: SelfInteropTests.Member
		/// {Alice (leaf 0), Bob (leaf 1)} — siblings, decap at the same node.
		var multi: MLS.RFC9420.Group
		var aliceView: MLS.RFC9420.Group
		var bobView: MLS.RFC9420.Group
		var carolView: MLS.RFC9420.Group
	}

	static func trio() throws -> Trio {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let carol = try SelfInteropTests.member("carol")

		var groupA = try SelfInteropTests.createGroup(alice)
		let addBob = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		groupA = addBob.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(addBob.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let addCarol = try groupA.commit(
			provider, proposals: [.proposal(.add(carol.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		groupA = addCarol.group
		guard case .publicMessage(let addCarolMsg) = addCarol.commit else {
			throw TestError.expectedPublicCommit
		}
		try groupB.process(
			provider, commit: addCarolMsg, proposals: .init(), psk: { _ in nil })
		let groupC = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(addCarol.welcome),
			credentials: carol.joinCredentials, psk: { _ in nil })

		let multi = MLS.RFC9420.Group(
			core: groupA.core,
			memberships: [groupA.memberships[0], groupB.memberships[0]])
		return Trio(
			alice: alice, bob: bob, carol: carol, multi: multi, aliceView: groupA,
			bobView: groupB, carolView: groupC)
	}

	enum TestError: Error { case expectedPublicCommit }

	/// Carol's commit, public-framed, as the raw message a composite receives.
	static func remoteCommit(
		_ carolView: inout MLS.RFC9420.Group, _ carol: SelfInteropTests.Member
	)
		throws -> MLS.RFC9420.PublicMessage
	{
		let out = try carolView.commit(
			provider, proposals: [], signingKey: carol.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let message) = out.commit else {
			throw TestError.expectedPublicCommit
		}
		return message
	}

	@Test(
		"a restored N = 2 composite receives a remote commit; both memberships install and advance"
	)
	func restoredCompositeReceivesRemoteCommit() throws {
		let provider = Self.provider
		var t = try Self.trio()
		let epoch = t.multi.context.epoch

		// Restore the composite from a format-2 archive, then receive.
		var restored = try MLS.RFC9420.Group.restore(
			from: try t.multi.makeSnapshot(), provider)
		#expect(restored.memberships.count == 2)

		let first = try Self.remoteCommit(&t.carolView, t.carol)
		try restored.process(
			provider, commit: first, proposals: .init(), psk: { _ in nil })
		#expect(restored.context.epoch == epoch + 1)
		#expect(restored.memberships.count == 2)

		// A SECOND remote commit exercises the keys the first receive installed:
		// each membership must decap it against its freshly installed path keys.
		// Success (the memberships agree on a commit_secret) proves both installs.
		let second = try Self.remoteCommit(&t.carolView, t.carol)
		try restored.process(
			provider, commit: second, proposals: .init(), psk: { _ in nil })
		#expect(restored.context.epoch == epoch + 2)

		// Both memberships remain able to send in the new epoch; Carol decrypts.
		let aliceLeaf = t.multi.memberships[0].leafIndex
		let bobLeaf = t.multi.memberships[1].leafIndex
		let fromAlice = try restored.protect(
			as: aliceLeaf, provider, applicationData: Data("a".utf8),
			signingKey: t.alice.signingKey)
		let fromBob = try restored.protect(
			as: bobLeaf, provider, applicationData: Data("b".utf8),
			signingKey: t.bob.signingKey)
		let openedA = try t.carolView.unprotect(provider, message: fromAlice)
		let openedB = try t.carolView.unprotect(provider, message: fromBob)
		guard case .application(let da) = openedA.content,
			case .application(let db) = openedB.content
		else {
			Issue.record("expected application content")
			return
		}
		#expect(da == Data("a".utf8))
		#expect(db == Data("b".utf8))
	}

	@Test("one local membership commits; the other is installed from the same commit")
	func localCommitInstallsOtherMembership() throws {
		let provider = Self.provider
		var t = try Self.trio()
		let epoch = t.multi.context.epoch
		let aliceLeaf = t.multi.memberships[0].leafIndex
		let bobLeaf = t.multi.memberships[1].leafIndex

		// Bob (a local membership) commits; Alice (the other local membership) is
		// installed by decapping Bob's own path.
		var multi = t.multi
		let out = try multi.commit(
			as: bobLeaf, provider, proposals: [], signingKey: t.bob.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		#expect(multi.context.epoch == epoch + 1)
		#expect(multi.memberships.count == 2)
		guard case .publicMessage(let bobCommit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}

		// Carol receives Bob's commit and advances too, confirming Bob committed a
		// well-formed epoch (both local memberships and the remote agree).
		try t.carolView.process(
			provider, commit: bobCommit, proposals: .init(), psk: { _ in nil })
		#expect(t.carolView.context.epoch == epoch + 1)

		// Alice's install is exercised by a subsequent REMOTE commit: Alice must
		// decap it against the keys Bob's commit installed for her. If that install
		// were wrong, this decap would fail or diverge.
		let carolCommit = try Self.remoteCommit(&t.carolView, t.carol)
		try multi.process(
			provider, commit: carolCommit, proposals: .init(), psk: { _ in nil })
		#expect(multi.context.epoch == epoch + 2)

		// And Alice can still send.
		let fromAlice = try multi.protect(
			as: aliceLeaf, provider, applicationData: Data("still-here".utf8),
			signingKey: t.alice.signingKey)
		let opened = try t.carolView.unprotect(provider, message: fromAlice)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("still-here".utf8))
	}

	@Test(
		"a commit one local membership cannot decap is rejected wholesale, not partially applied"
	)
	func undecryptableForOneMembershipRejectsWholeCommit() throws {
		let provider = Self.provider
		var t = try Self.trio()

		// Corrupt Bob's membership: strip its held path keys so it cannot decap
		// Carol's path. The receive must reject the whole commit rather than
		// advance Alice's membership while stranding Bob's (all-or-nothing).
		var multi = t.multi
		multi.memberships[1].secretKeys = [:]

		let commit = try Self.remoteCommit(&t.carolView, t.carol)
		let before = multi.context.epoch
		#expect(throws: (any Error).self) {
			try multi.process(
				provider, commit: commit, proposals: .init(), psk: { _ in nil })
		}
		// `process` assigns only on success, so a rejected commit leaves the group
		// untouched — neither membership advanced.
		#expect(multi.context.epoch == before)
	}

	@Test("memberships at different tree levels each decap their own path-secret subset")
	func differentLevelDecap() throws {
		let provider = Self.provider
		let t = try Self.trio()
		// A NON-sibling composite: Alice (leaf 0) and Carol (leaf 2), with Bob
		// (leaf 1) between them. When Bob commits, Alice decaps at the parent she
		// shares with Bob while Carol decaps at the root — different levels, so the
		// two memberships install DIFFERENT node sets from one commit (the sibling
		// fixtures always decap the same node). Both still agree on `commit_secret`.
		var multi = MLS.RFC9420.Group(
			core: t.aliceView.core,
			memberships: [t.aliceView.memberships[0], t.carolView.memberships[0]])
		let epoch = multi.context.epoch

		var bob = t.bobView
		let out = try bob.commit(
			provider, proposals: [], signingKey: t.bob.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let bobCommit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}
		try multi.process(
			provider, commit: bobCommit, proposals: .init(), psk: { _ in nil })
		#expect(multi.context.epoch == epoch + 1)

		// A second commit exercises the differing key sets each membership just
		// installed: both must decap it against their own (different) node keys.
		let out2 = try bob.commit(
			provider, proposals: [], signingKey: t.bob.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let bobCommit2) = out2.commit else {
			Issue.record("expected a public commit")
			return
		}
		try multi.process(
			provider, commit: bobCommit2, proposals: .init(), psk: { _ in nil })
		#expect(multi.context.epoch == epoch + 2)
	}
}
