import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSFraming
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §12.2's roster-support rule for non-default proposal types: a
/// list is invalid if it "contains a Proposal with a non-default proposal
/// type that is not supported by some members of the group that will
/// process the Commit (i.e., members being added or removed by the Commit
/// do not need to support the proposal type)" — §13.2 restates it as the
/// send-side MUST NOT. `CustomProposalTests` and `AppDataUpdateProposalTests`
/// exercise the seams this rule now gates; this suite pins the rule itself,
/// receive-side first (parsing the sender's bytes, the security-relevant
/// path), plus both exemptions.
@Suite("Non-default proposal type capability enforcement (§12.2 / §13.2)")
struct NonDefaultProposalCapabilitiesTests {
	static let provider = ConstructedRejectionTests.provider

	enum TestError: Error { case unexpectedFraming }

	/// Alice advertising `type`, Bob NOT — exactly one non-advertising
	/// processing member, so a thrown `proposalTypeNotSupported`'s `leaf`
	/// unambiguously names Bob (leaf 1).
	static func asymmetricPair(
		supporting type: MLS.RFC9420.ProposalType
	) throws -> ConstructedRejectionTests.Pair {
		let alice = try SelfInteropTests.member("alice", capabilityProposals: [type])
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		return ConstructedRejectionTests.Pair(alice: alice, groupA: groupA, groupB: groupB)
	}

	/// Hand-crafts a commit carrying exactly `proposals`, signed and
	/// membership-tagged by Alice but with a garbage confirmation tag —
	/// `ConstructedRejectionTests.craftedCommit`'s technique, re-derived here
	/// as real wire bytes (`mlsEncoded()`, not an in-memory `PublicMessage`)
	/// so the receiver's decode path is what actually runs, not a value this
	/// test handed it pre-parsed. §12.2 list validation runs before the
	/// confirmation-tag check, so the garbage tag never matters for the
	/// rejections below.
	static func craftedBytes(
		_ pair: ConstructedRejectionTests.Pair, proposals: [MLS.RFC9420.ProposalOrRef]
	) throws -> Data {
		let content = MLS.RFC9420.FramedContent(
			groupID: pair.groupA.context.groupID, epoch: pair.groupA.context.epoch,
			sender: .member(pair.groupA.myLeafIndex), authenticatedData: Data(),
			content: .commit(.init(proposals: proposals, path: nil)))
		let crafted = try MLS.RFC9420.protectPublic(
			Self.provider, content: content, groupContext: pair.groupA.context,
			confirmationTag: MLS.ConfirmationTag(Data(repeating: 0xAB, count: 32)),
			signingKey: pair.alice.signingKey,
			membershipKey: pair.groupA.epoch.membershipKey)
		return try MLS.RFC9420.Message.publicMessage(crafted).mlsEncoded()
	}

	// MARK: rejection, from bytes

	@Test(
		"a `.custom` non-default type not advertised by a processing member is rejected on receive"
	)
	func customNotAdvertisedRejected() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF002)
		let pair = try Self.asymmetricPair(supporting: type)
		let body = Data([0x01, 0x02, 0x03])
		let bytes = try Self.craftedBytes(
			pair, proposals: [.proposal(.custom(type: type, body: body))])

		try MLS.RFC9420.$customProposalTypes.withValue([type]) {
			guard
				case .publicMessage(let commit) = try MLS.RFC9420.Message(
					mlsEncoded: bytes)
			else { throw TestError.unexpectedFraming }
			var groupB = pair.groupB
			#expect(
				throws: MLS.RFC9420.GroupError.proposalTypeNotSupported(
					type: type, leaf: MLS.LeafIndex(value: 1))
			) {
				try groupB.process(
					Self.provider, commit: commit, proposals: .init(),
					psk: { _ in nil })
			}
		}
	}

	@Test(
		"`.appDataUpdate` (0x0008) not advertised by a processing member is rejected on receive"
	)
	func appDataUpdateNotAdvertisedRejected() throws {
		let type = MLS.RFC9420.ProposalType(.appDataUpdate)
		let pair = try Self.asymmetricPair(supporting: type)
		let update = MLS.Extensions.AppDataUpdate(
			componentID: 0xFF01, operation: .update(Data([9])))
		let bytes = try Self.craftedBytes(
			pair, proposals: [.proposal(.appDataUpdate(update))])

		guard case .publicMessage(let commit) = try MLS.RFC9420.Message(mlsEncoded: bytes)
		else { throw TestError.unexpectedFraming }
		var groupB = pair.groupB
		#expect(
			throws: MLS.RFC9420.GroupError.proposalTypeNotSupported(
				type: type, leaf: MLS.LeafIndex(value: 1))
		) {
			try groupB.process(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	// MARK: acceptance once every processing member advertises the type

	/// The same `.custom` type as `customNotAdvertisedRejected`, but both Alice
	/// and Bob advertise it — a full, validly tagged commit, so this proves
	/// genuine acceptance, not merely "rejected for some other reason."
	@Test("the same `.custom` type is accepted once every processing member advertises it")
	func customAdvertisedByAllAccepted() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF002)
		let alice = try SelfInteropTests.member("alice", capabilityProposals: [type])
		let bob = try SelfInteropTests.member("bob", capabilityProposals: [type])
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let body = Data([0x01, 0x02, 0x03])
		let sent = try groupA.commit(
			Self.provider, proposals: [.proposal(.custom(type: type, body: body))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		groupA = sent.group
		guard case .publicMessage(let commit) = sent.commit else {
			throw TestError.unexpectedFraming
		}
		try groupB.process(
			Self.provider, commit: commit, proposals: .init(), psk: { _ in nil })
		#expect(groupB.context == groupA.context)
	}

	// MARK: current-leaf semantics (§12.2 runs entirely before §12.3)

	/// Frames `updateLeaf` as Bob's own by-reference Update, hand-built rather
	/// than via `Group.proposeUpdate` — that convenience carries the current
	/// leaf's `capabilities` forward unchanged, and these two tests need it to
	/// diverge from the leaf actually installed in the tree. Also seeds
	/// `groupB.pendingUpdates` with the new leaf secret, mirroring what
	/// `proposeUpdate` does internally, so `groupB` can later decap a commit
	/// that applies this Update — hand-building the proposal means hand-seeding
	/// the stash too.
	static func bobUpdateProposal(
		_ bob: SelfInteropTests.Member, in groupB: inout MLS.RFC9420.Group,
		newCapabilityProposals: [MLS.RFC9420.ProposalType]
	) throws -> MLS.RFC9420.PublicMessage {
		guard let bobRecord = groupB.tree.leaf(at: groupB.myLeafIndex) else {
			throw TestError.unexpectedFraming
		}
		var updateLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: bobRecord.encoded)
		let (newSecretKey, newPublicKey) = try Self.provider.hpkeGenerateKeyPair()
		updateLeaf.encryptionKey = newPublicKey
		updateLeaf.capabilities.proposals = newCapabilityProposals
		updateLeaf.source = .update
		updateLeaf.signature = Data()
		updateLeaf.signature = try MLS.signWithLabel(
			Self.provider, privateKey: bob.signingKey, label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: groupB.context.groupID,
					leafIndex: groupB.myLeafIndex)))

		let framed = MLS.RFC9420.FramedContent(
			groupID: groupB.context.groupID, epoch: groupB.context.epoch,
			sender: .member(groupB.myLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(updateLeaf)))
		let (signedContent, signature) = try MLS.RFC9420.signPublic(
			Self.provider, content: framed, groupContext: groupB.context,
			sign: MLS.RFC9420.signingClosure(Self.provider, bob.signingKey))
		let sealed = try MLS.RFC9420.sealPublic(
			Self.provider, content: framed, signedContent: signedContent,
			signature: signature, confirmationTag: nil,
			membershipKey: groupB.epoch.membershipKey)

		groupB.pendingUpdates = (
			epoch: groupB.context.epoch, node: 2 * groupB.myLeafIndex.value,
			updates: [(publicKey: newPublicKey, secret: newSecretKey)]
		)
		return sealed
	}

	/// The decisive direction: Bob's CURRENT leaf does not advertise `type`,
	/// but the Update he proposes in this SAME commit replaces it with a leaf
	/// that does. §12.2 list validation runs before §12.3 applies the Update,
	/// so the roster it judges is still the pre-commit one — the replacement
	/// leaf must not rescue the commit. Rejecting here is what closes the
	/// original gap: judging by the replacement leaf would have ACCEPTED this,
	/// which is exactly the input RFC 9420 documents as invalid.
	@Test(
		"an updated member's CURRENT leaf governs, not its Update's replacement leaf: rejected"
	)
	func updatedMemberCurrentLeafGoverns() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF006)
		let alice = try SelfInteropTests.member("alice", capabilityProposals: [type])
		let bob = try SelfInteropTests.member("bob")  // current leaf: no `type`
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let sealed = try Self.bobUpdateProposal(
			bob, in: &groupB, newCapabilityProposals: [type])
		let verified = try groupA.verifying(Self.provider, proposal: sealed)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)

		let body = Data([0xE1])
		#expect(
			throws: MLS.RFC9420.GroupError.proposalTypeNotSupported(
				type: type, leaf: groupB.myLeafIndex)
		) {
			_ = try groupA.committing(
				Self.provider,
				proposals: [
					.reference(ref), .proposal(.custom(type: type, body: body)),
				],
				proposalStore: store,
				signingKey: alice.signingKey, randomness: .generate(Self.provider))
		}
	}

	/// The mirror direction: Bob's CURRENT leaf advertises `type`, but the
	/// Update he proposes in this SAME commit replaces it with a leaf that
	/// does NOT. Still accepted — the replacement leaf's lack of support is
	/// simply not consulted at list-validation time.
	@Test(
		"an updated member's CURRENT leaf governs even when its Update's replacement leaf would not: accepted"
	)
	func updatedMemberCurrentLeafSufficesDespiteReplacement() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF005)
		let alice = try SelfInteropTests.member("alice", capabilityProposals: [type])
		let bob = try SelfInteropTests.member("bob", capabilityProposals: [type])
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let sealed = try Self.bobUpdateProposal(
			bob, in: &groupB, newCapabilityProposals: [])
		let verified = try groupA.verifying(Self.provider, proposal: sealed)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, Self.provider)

		let body = Data([0xE0])
		let sent = try groupA.commit(
			Self.provider,
			proposals: [.reference(ref), .proposal(.custom(type: type, body: body))],
			proposalStore: store,
			signingKey: alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		groupA = sent.group
		guard case .publicMessage(let commit) = sent.commit else {
			throw TestError.unexpectedFraming
		}
		try groupB.process(
			Self.provider, commit: commit, proposals: store, psk: { _ in nil })
		#expect(groupB.context == groupA.context)
	}

	// MARK: exemptions

	/// §12.2's parenthetical, added half: a member this commit ADDS need not
	/// already advertise the type, even though it carries a non-default
	/// proposal — the added leaf simply isn't in the PRE-commit roster the
	/// check judges.
	@Test("an added member's own leaf need not advertise the type: added members are exempt")
	func addedMemberExempt() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF003)
		let alice = try SelfInteropTests.member("alice", capabilityProposals: [type])
		let bob = try SelfInteropTests.member("bob", capabilityProposals: [type])
		var groupA = try SelfInteropTests.createGroup(alice)
		let addBob = try groupA.commit(
			Self.provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		groupA = addBob.group
		var groupB = try MLS.RFC9420.Group.join(
			Self.provider, welcome: try #require(addBob.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Carol's own leaf does NOT advertise `type` — irrelevant, since she is
		// being added by this very commit.
		let carol = try SelfInteropTests.member("carol")
		let body = Data([0xC0])
		let addCarol = try groupA.commit(
			Self.provider,
			proposals: [
				.proposal(.add(carol.keyPackage)),
				.proposal(.custom(type: type, body: body)),
			],
			signingKey: alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		groupA = addCarol.group
		guard case .publicMessage(let commit) = addCarol.commit else {
			throw TestError.unexpectedFraming
		}
		try groupB.process(
			Self.provider, commit: commit, proposals: .init(), psk: { _ in nil })
		#expect(groupB.context == groupA.context)
	}

	/// §12.2's parenthetical, removed half: a commit that removes the only
	/// member not advertising the type is accepted — that member is exempt
	/// precisely because it will not process this commit.
	@Test("removing the only non-advertising member exempts it: the commit is accepted")
	func removedMemberExempt() throws {
		let type = MLS.RFC9420.ProposalType(rawValue: 0xF004)
		let pair = try Self.asymmetricPair(supporting: type)
		var groupA = pair.groupA
		let body = Data([0xD0])
		let sent = try groupA.commit(
			Self.provider,
			proposals: [
				.proposal(.remove(pair.groupB.myLeafIndex)),
				.proposal(.custom(type: type, body: body)),
			],
			signingKey: pair.alice.signingKey, randomness: .generate(Self.provider))
		#expect(sent.group.context.epoch == pair.groupA.context.epoch + 1)
	}
}
