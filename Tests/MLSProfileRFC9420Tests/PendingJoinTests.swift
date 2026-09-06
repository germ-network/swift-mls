import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D17 slice 4c — the join-side seam. `joining` runs the full §12.4.3.1 Welcome
/// validation and builds the group, but hands it back as a `PendingJoin` so the
/// app can adjudicate the roster it is about to trust (§5.3.1) before adopting
/// it with `apply()`. The one-time KeyPackage is reported consumed whether or
/// not the app applies.
@Suite("Pending join (D17 4c)")
struct PendingJoinTests {
	static let provider = ConstructedRejectionTests.provider

	/// Alice creates a group and adds Bob; returns Alice's post-add group and the
	/// Welcome she produced for Bob.
	static func addBob() throws -> (
		alice: SelfInteropTests.Member, bob: SelfInteropTests.Member,
		groupA: MLS.RFC9420.Group, welcome: MLS.RFC9420.Welcome
	) {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		return (alice, bob, groupA, try #require(add.welcome))
	}

	@Test("joining surfaces the roster, signer, and consumed KeyPackage before adopting")
	func joiningSurfacesRosterThenApplies() throws {
		let provider = Self.provider
		let f = try Self.addBob()

		let pending = try MLS.RFC9420.Group.joining(
			provider, welcome: f.welcome, credentials: f.bob.joinCredentials,
			psk: { _ in nil })

		// The roster the app adjudicates: Alice (leaf 0) and Bob (leaf 1), each
		// with the presentation their leaf carries.
		let aliceEntry = MLS.RFC9420.RosterEntry(
			leaf: MLS.LeafIndex(value: 0),
			presentation: MLS.RFC9420.CredentialPresentation(
				credential: f.alice.keyPackage.leafNode.credential,
				signatureKey: f.alice.keyPackage.leafNode.signatureKey))
		let bobEntry = MLS.RFC9420.RosterEntry(
			leaf: MLS.LeafIndex(value: 1),
			presentation: MLS.RFC9420.CredentialPresentation(
				credential: f.bob.keyPackage.leafNode.credential,
				signatureKey: f.bob.keyPackage.leafNode.signatureKey))
		// Exactly Alice then Bob, ascending by leaf (roster order is deterministic).
		#expect(pending.roster == [aliceEntry, bobEntry])
		// `context` / `myLeafIndex` are surfaced for the caller-side checks the
		// library cannot do (the §12.4.3.1 group_id uniqueness check, self-exclusion).
		#expect(pending.context.groupID == f.groupA.context.groupID)
		#expect(pending.myLeafIndex == MLS.LeafIndex(value: 1))
		// The Welcome was signed by Alice, the committer who added Bob.
		#expect(pending.signer == MLS.LeafIndex(value: 0))
		// The one-time KeyPackage this join used, for the app to delete.
		#expect(pending.consumedKeyPackage == (try f.bob.keyPackage.reference(provider)))

		// Adopt → the joined group at Bob's leaf, with the JoinEffects roster.
		let transition = pending.apply()
		let joined = transition.group
		#expect(joined.myLeafIndex == MLS.LeafIndex(value: 1))
		#expect(joined.context.epoch == f.groupA.context.epoch)
		let effects = transition.takeOutput()
		#expect(effects.myLeafIndex == MLS.LeafIndex(value: 1))
		#expect(effects.signer == MLS.LeafIndex(value: 0))
		#expect(effects.roster == [aliceEntry, bobEntry])

		// The adopted group is a full member: it decrypts an application message
		// Alice sends and converges with her.
		var alice = f.groupA
		let message = try alice.protect(
			provider, applicationData: Data("hi bob".utf8),
			signingKey: f.alice.signingKey)
		var bob = joined
		let opened = try bob.unprotect(provider, message: message)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("hi bob".utf8))
	}

	@Test("the eager join shim equals joining then apply")
	func joinShimEqualsJoiningThenApply() throws {
		let provider = Self.provider
		let f = try Self.addBob()

		let eager = try MLS.RFC9420.Group.join(
			provider, welcome: f.welcome, credentials: f.bob.joinCredentials,
			psk: { _ in nil })
		let staged = try MLS.RFC9420.Group.joining(
			provider, welcome: f.welcome, credentials: f.bob.joinCredentials,
			psk: { _ in nil }
		).apply().group

		#expect(eager.context == staged.context)
		#expect(eager.myLeafIndex == staged.myLeafIndex)
		#expect((try eager.makeSnapshot()) == (try staged.makeSnapshot()))
	}

	@Test("a declined join still reports the consumed KeyPackage (never applied)")
	func declineStillReportsConsumedKeyPackage() throws {
		let provider = Self.provider
		let f = try Self.addBob()

		// The app validates but declines — it reads `consumedKeyPackage` and never
		// calls `apply()`. The KeyPackage is single-use, so it must be deleted even
		// on decline (D17 §2 L5).
		let pending = try MLS.RFC9420.Group.joining(
			provider, welcome: f.welcome, credentials: f.bob.joinCredentials,
			psk: { _ in nil })
		#expect(pending.consumedKeyPackage == (try f.bob.keyPackage.reference(provider)))
		// `pending` is dropped here without `apply()` — a legitimate decline.
	}

	@Test("the roster reflects the current members — a removed member is absent")
	func rosterReflectsRemovedMember() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let carol = try SelfInteropTests.member("carol")
		let dave = try SelfInteropTests.member("dave")

		var groupA = try SelfInteropTests.createGroup(alice)
		groupA = try groupA.commit(
			provider,
			proposals: [
				.proposal(.add(bob.keyPackage)), .proposal(.add(carol.keyPackage)),
			],
			signingKey: alice.signingKey, randomness: .generate(provider)
		).group  // Bob → leaf 1, Carol → leaf 2

		// Remove Bob and add Dave in one commit: Dave fills Bob's freed leaf 1.
		let commit = try groupA.commit(
			provider,
			proposals: [
				.proposal(.remove(MLS.LeafIndex(value: 1))),
				.proposal(.add(dave.keyPackage)),
			],
			signingKey: alice.signingKey, randomness: .generate(provider))

		let pending = try MLS.RFC9420.Group.joining(
			provider, welcome: try #require(commit.welcome),
			credentials: dave.joinCredentials, psk: { _ in nil })

		// Roster is the CURRENT membership: Alice(0), Dave(1), Carol(2) — Bob gone.
		#expect(pending.roster.map(\.leaf) == [0, 1, 2].map { MLS.LeafIndex(value: $0) })
		#expect(pending.myLeafIndex == MLS.LeafIndex(value: 1))
		#expect(
			pending.roster.contains {
				$0.presentation.signatureKey == dave.signatureKey
			})
		#expect(
			!pending.roster.contains {
				$0.presentation.signatureKey == bob.signatureKey
			})
	}
}
