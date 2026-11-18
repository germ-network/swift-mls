import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §7.3: for a LeafNode being sent, "the client MUST verify that the
/// current time is within the range of the lifetime field"; for one received,
/// the check is RECOMMENDED. The caller supplies the time; `.unchecked` skips the check.
@Suite("KeyPackage leaf lifetime is checked against the caller's time (RFC 9420 §7.3)")
struct LifetimeTests {
	static let provider = SelfInteropTests.provider
	static let window = MLS.RFC9420.Lifetime(notBefore: 100, notAfter: 200)
	static let outOfRange = MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange

	private static func commitAdding(
		_ added: SelfInteropTests.Member, at check: MLS.RFC9420.LifetimeCheck,
		as alice: SelfInteropTests.Member, in group: MLS.RFC9420.Group,
		store: MLS.RFC9420.ProposalStore = .init(),
		proposals: [MLS.RFC9420.ProposalOrRef]? = nil
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.SentCommit> {
		try group.committing(
			provider, proposals: proposals ?? [.proposal(.add(added.keyPackage))],
			proposalStore: store, signingKey: alice.signingKey,
			randomness: .generate(provider), lifetimeCheck: check)
	}

	private static func expectOutOfRange(
		sourceLocation: SourceLocation = #_sourceLocation, _ body: () throws -> Void
	) {
		#expect(throws: outOfRange, sourceLocation: sourceLocation, performing: body)
	}

	@Test("committing an Add of an expired KeyPackage throws")
	func committingRejectsAddOfExpiredKeyPackage() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		Self.expectOutOfRange {
			_ = try Self.commitAdding(
				bob, at: .at(unixSeconds: 201), as: alice, in: group)
		}
	}

	@Test("committing an Add of a not-yet-valid KeyPackage throws")
	func committingRejectsAddOfNotYetValidKeyPackage() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		Self.expectOutOfRange {
			_ = try Self.commitAdding(
				bob, at: .at(unixSeconds: 99), as: alice, in: group)
		}
	}

	@Test("committing an Add within its lifetime succeeds")
	func committingAcceptsAddWithinLifetime() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		_ = try Self.commitAdding(bob, at: .at(unixSeconds: 150), as: alice, in: group)
	}

	@Test("committing an Add accepts a time equal to not_before or not_after")
	func committingAcceptsAddAtLifetimeBoundaries() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		for time in [UInt64(100), 200] {
			_ = try Self.commitAdding(
				bob, at: .at(unixSeconds: time), as: alice, in: group)
		}
	}

	@Test("committing a by-reference Add of an expired KeyPackage throws")
	func committingRejectsReferencedAddOfExpiredKeyPackage() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		let ref = MLS.HashReference(Data(repeating: 7, count: 32))
		var store = MLS.RFC9420.ProposalStore()
		try store.insertMigratedOwnUpdate(
			ref,
			MLS.RFC9420.StoredProposal(
				proposal: .add(bob.keyPackage), sender: .member(group.myLeafIndex),
				epoch: group.context.epoch, groupID: group.context.groupID))
		Self.expectOutOfRange {
			_ = try Self.commitAdding(
				bob, at: .at(unixSeconds: 201), as: alice, in: group, store: store,
				proposals: [.reference(ref)])
		}
		_ = try Self.commitAdding(
			bob, at: .at(unixSeconds: 150), as: alice, in: group, store: store,
			proposals: [.reference(ref)])
	}

	@Test("committing with an unchecked lifetime skips the check")
	func committingUncheckedSkipsLifetimeCheck() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		_ = try Self.commitAdding(bob, at: .unchecked, as: alice, in: group)
	}

	@Test("committing as a named membership applies the same lifetime check")
	func committingAsMembershipRejectsAddOfExpiredKeyPackage() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob", lifetime: Self.window)
		let group = try SelfInteropTests.createGroup(alice)
		Self.expectOutOfRange {
			_ = try group.committing(
				as: group.myLeafIndex, Self.provider,
				proposals: [.proposal(.add(bob.keyPackage))],
				signingKey: alice.signingKey,
				randomness: .generate(Self.provider),
				lifetimeCheck: .at(unixSeconds: 201))
		}
	}

	private static func create(
		_ creator: SelfInteropTests.Member, leaf: MLS.RFC9420.LeafNode? = nil,
		groupID: Data = Data([1]), at check: MLS.RFC9420.LifetimeCheck
	) throws -> MLS.RFC9420.Group {
		try MLS.RFC9420.Group.create(
			provider, groupID: groupID, leafNode: leaf ?? creator.keyPackage.leafNode,
			leafSecretKey: creator.leafSecretKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
			lifetimeCheck: check)
	}

	@Test("creating a group from a leaf outside its lifetime throws")
	func createRejectsCreatorLeafOutsideLifetime() throws {
		let alice = try SelfInteropTests.member("alice", lifetime: Self.window)
		Self.expectOutOfRange { _ = try Self.create(alice, at: .at(unixSeconds: 201)) }
		Self.expectOutOfRange { _ = try Self.create(alice, at: .at(unixSeconds: 99)) }
		_ = try Self.create(alice, at: .at(unixSeconds: 150))
		_ = try Self.create(alice, at: .unchecked)
	}

	@Test(
		"creating a group still accepts a non-key_package creator leaf when checking lifetime"
	)
	func createKeepsAcceptingNonKeyPackageCreatorLeaf() throws {
		let alice = try SelfInteropTests.member("alice")
		let groupID = Data([1])
		var leaf = alice.keyPackage.leafNode
		leaf.source = .update
		leaf.signature = try MLS.signWithLabel(
			Self.provider, privateKey: alice.signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(groupID: groupID, leafIndex: .init(value: 0))))
		_ = try Self.create(alice, leaf: leaf, groupID: groupID, at: .at(unixSeconds: 5))
	}

	@Test("a 0…UInt64.max lifetime is accepted at any time")
	func fullRangeLifetimeAcceptedAtAnyTime() throws {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let group = try SelfInteropTests.createGroup(alice)
		for time in [UInt64(0), .max] {
			_ = try Self.commitAdding(
				bob, at: .at(unixSeconds: time), as: alice, in: group)
			_ = try Self.create(alice, at: .at(unixSeconds: time))
		}
	}

	private struct Setup {
		var alice: SelfInteropTests.Member
		var bob: MLS.RFC9420.Group
		var carol: SelfInteropTests.Member
		var message: MLS.RFC9420.Message
	}

	/// Alice commits an Add of Carol, built at `sendCheck`, to a group Bob has joined.
	private static func setup(
		carolLifetime: MLS.RFC9420.Lifetime,
		sendCheck: MLS.RFC9420.LifetimeCheck = .unchecked,
		framing: MLS.RFC9420.Group.HandshakeFraming
	) throws -> Setup {
		let pair = try ProposalValidationTests.pair()
		let carol = try SelfInteropTests.member("carol", lifetime: carolLifetime)
		let transition = try pair.groupA.committing(
			provider, proposals: [.proposal(.add(carol.keyPackage))],
			signingKey: pair.alice.signingKey, randomness: .generate(provider),
			lifetimeCheck: sendCheck, framing: framing)
		return Setup(
			alice: pair.alice, bob: pair.groupB, carol: carol,
			message: transition.output.message)
	}

	private static func publicCommit(_ setup: Setup) throws -> MLS.RFC9420.PublicMessage {
		guard case .publicMessage(let message) = setup.message else {
			throw Failure.framing
		}
		return message
	}

	enum Failure: Error { case framing }

	@Test("validating a public commit that Adds an expired KeyPackage throws when given a time")
	func validatingPublicCommitRejectsExpiredAddWhenTimeGiven() throws {
		let setup = try Self.setup(carolLifetime: Self.window, framing: .publicMessage)
		let message = try Self.publicCommit(setup)
		Self.expectOutOfRange {
			_ = try setup.bob.validating(
				Self.provider, commit: message, proposals: .init(),
				psk: { _ in nil },
				lifetimeCheck: .at(unixSeconds: 201))
		}
	}

	@Test(
		"validating a private commit that Adds an expired KeyPackage reports it rejected when given a time"
	)
	func validatingPrivateCommitReportsRejectedForExpiredAddWhenTimeGiven() throws {
		let setup = try Self.setup(carolLifetime: Self.window, framing: .privateMessage)
		guard case .privateMessage(let message) = setup.message else {
			throw Failure.framing
		}
		let transition = try setup.bob.validating(
			Self.provider, commit: message, proposals: .init(), psk: { _ in nil },
			lifetimeCheck: .at(unixSeconds: 201))
		guard case .rejected(let rejection) = transition.takeOutput() else {
			Issue.record("expected .rejected")
			return
		}
		#expect(rejection.reason as? MLS.RFC9420.GroupError == Self.outOfRange)
	}

	@Test("validating without a time does not check lifetimes")
	func validatingDefaultsToNoLifetimeCheck() throws {
		let setup = try Self.setup(carolLifetime: Self.window, framing: .publicMessage)
		let message = try Self.publicCommit(setup)
		_ = try setup.bob.validating(
			Self.provider, commit: message, proposals: .init(), psk: { _ in nil })
	}

	@Test("a commit built at a time is accepted when validated at the same time")
	func committedThenValidatedAtSameTimeIsAccepted() throws {
		let time = MLS.RFC9420.LifetimeCheck.at(unixSeconds: 150)
		let setup = try Self.setup(
			carolLifetime: Self.window, sendCheck: time, framing: .publicMessage)
		let message = try Self.publicCommit(setup)
		_ = try setup.bob.validating(
			Self.provider, commit: message, proposals: .init(), psk: { _ in nil },
			lifetimeCheck: time)
	}
}
