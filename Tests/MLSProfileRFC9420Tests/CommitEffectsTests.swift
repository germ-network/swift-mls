import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D18 slice 4b — the §5.3.1 membership/credential effects and eviction. A
/// commit reports, at the validate→apply seam, every member it added, removed,
/// or re-credentialed (§5.3.1: the app is the Authentication Service). A
/// commit that removes one of THIS device's local memberships evicts it —
/// partial (a survivor advances) or, when it removes the last one, a terminal
/// full eviction.
@Suite("Commit effects & eviction (D18 4b)")
struct CommitEffectsTests {
	static let provider = ConstructedRejectionTests.provider

	/// The effects a commit produced, read off `committing`'s pending (send side).
	static func effects(
		of transition: consuming MLS.RFC9420.Transition<MLS.RFC9420.SentCommit>
	) -> [MLS.RFC9420.CommitEffect] {
		transition.takeOutput().pending.effects.events
	}

	@Test("an Add reports `added` with the new member's presentation")
	func addedEffect() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let groupA = try SelfInteropTests.createGroup(alice)
		let transition = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		let expected = MLS.RFC9420.CredentialPresentation(
			credential: bob.keyPackage.leafNode.credential,
			signatureKey: bob.keyPackage.leafNode.signatureKey)
		#expect(
			Self.effects(of: transition).contains(
				.added(leaf: MLS.LeafIndex(value: 1), presentation: expected)))
	}

	@Test("a Remove reports `removed` for the removed leaf")
	func removedEffect() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()  // Alice(0), Bob(1), Carol(2)
		let carolLeaf = t.carolView.myLeafIndex
		let transition = try t.aliceView.committing(
			provider, proposals: [.proposal(.remove(carolLeaf))],
			signingKey: t.alice.signingKey, randomness: .generate(provider))
		#expect(Self.effects(of: transition).contains(.removed(leaf: carolLeaf)))
	}

	@Test("an encryption-key-only Update reports `updated`, not `credentialReplaced`")
	func updatedEffect() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		var bob = t.bobView
		let (message, _) = try bob.proposeUpdate(
			provider, signingKey: t.bob.signingKey, framing: .publicMessage)
		guard case .publicMessage(let proposalMessage) = message else {
			Issue.record("expected a public proposal")
			return
		}
		let verified = try t.aliceView.verifying(provider, proposal: proposalMessage)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, provider)
		let transition = try t.aliceView.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: t.alice.signingKey, randomness: .generate(provider))
		let events = Self.effects(of: transition)
		#expect(events.contains(.updated(leaf: bobLeaf)))
		#expect(
			!events.contains {
				if case .credentialReplaced = $0 { true } else { false }
			})
	}

	@Test("a signature-key rotation reports `credentialReplaced` old→new")
	func credentialReplacedEffect() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		let oldRecord = try #require(t.bobView.tree.leaf(at: bobLeaf))
		let oldLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: oldRecord.encoded)
		let (newSigningKey, newSignatureKey) = try GroupMutationTests.signingKeyPair(
			provider)
		let (_, newEncryptionKey) = try provider.hpkeGenerateKeyPair()

		// A valid key-rotation Update: new signature key (the leaf self-signs with
		// it) and a fresh encryption key, keeping Bob's credential; framed by Bob
		// under his CURRENT key.
		var newLeaf = MLS.RFC9420.LeafNode(
			encryptionKey: newEncryptionKey, signatureKey: newSignatureKey,
			credential: oldLeaf.credential, capabilities: oldLeaf.capabilities,
			source: .update, extensions: oldLeaf.extensions, signature: Data())
		newLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: newSigningKey, label: "LeafNodeTBS",
			content: try newLeaf.toBeSigned(
				placement: .inGroup(
					groupID: t.bobView.context.groupID, leafIndex: bobLeaf)))
		let content = MLS.RFC9420.FramedContent(
			groupID: t.bobView.context.groupID, epoch: t.bobView.context.epoch,
			sender: .member(bobLeaf), authenticatedData: Data(),
			content: .proposal(.update(newLeaf)))
		let proposalMessage = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: t.bobView.context,
			confirmationTag: nil, signingKey: t.bob.signingKey,
			membershipKey: t.bobView.epoch.membershipKey)
		let verified = try t.aliceView.verifying(provider, proposal: proposalMessage)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(verified, provider)

		let transition = try t.aliceView.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: t.alice.signingKey, randomness: .generate(provider))
		let old = MLS.RFC9420.CredentialPresentation(
			credential: oldLeaf.credential, signatureKey: oldLeaf.signatureKey)
		let new = MLS.RFC9420.CredentialPresentation(
			credential: oldLeaf.credential, signatureKey: newSignatureKey)
		#expect(
			Self.effects(of: transition).contains(
				.credentialReplaced(leaf: bobLeaf, old: old, new: new)))
	}

	@Test(
		"partial eviction: a remote commit removes one local membership; the survivor advances"
	)
	func partialEvictionReceive() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()  // {Alice, Bob} local, Carol remote
		let aliceLeaf = t.multi.memberships[0].leafIndex
		let bobLeaf = t.multi.memberships[1].leafIndex
		let baseEpoch = t.multi.context.epoch

		let out = try t.carolView.commit(
			provider, proposals: [.proposal(.remove(bobLeaf))],
			signingKey: t.carol.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		guard case .publicMessage(let removeCommit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}
		let pending = try t.multi.validating(
			provider, commit: removeCommit, proposals: .init(), psk: { _ in nil })
		#expect(pending.effects.events.contains(.removed(leaf: bobLeaf)))
		#expect(pending.effects.events.contains(.membershipRemoved(leaf: bobLeaf)))

		var multi = t.multi
		try multi.process(
			provider, commit: removeCommit, proposals: .init(), psk: { _ in nil })
		#expect(multi.context.epoch == baseEpoch + 1)
		#expect(multi.memberships.map(\.leafIndex) == [aliceLeaf])
	}

	@Test(
		"full eviction (public): validating reports terminal membershipRemoved; the eager shim throws"
	)
	func fullEvictionPublic() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex  // Bob's own single-membership view

		var alice = t.aliceView
		let out = try alice.commit(
			provider, proposals: [.proposal(.remove(bobLeaf))],
			signingKey: t.alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		guard case .publicMessage(let removeCommit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}

		let baseEpoch = t.bobView.context.epoch
		let pending = try t.bobView.validating(
			provider, commit: removeCommit, proposals: .init(), psk: { _ in nil })
		#expect(pending.effects.events.contains(.removed(leaf: bobLeaf)))
		#expect(pending.effects.events.contains(.membershipRemoved(leaf: bobLeaf)))
		let terminal = try pending.apply(onto: t.bobView).group
		#expect(terminal.context.epoch == baseEpoch)  // empty delta: no advance
		#expect(terminal.memberships.map(\.leafIndex) == [bobLeaf])  // never shrinks to 0

		#expect(throws: MLS.RFC9420.GroupError.removedFromGroup) {
			_ = try t.bobView.processing(
				provider, commit: removeCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}

	@Test(
		"full eviction (private): the ratchet consumption is kept even though the commit is terminal"
	)
	func fullEvictionPrivateKeepsConsumption() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex

		var alice = t.aliceView
		let out = try alice.commit(
			provider, proposals: [.proposal(.remove(bobLeaf))],
			signingKey: t.alice.signingKey, randomness: .generate(provider),
			framing: .privateMessage)
		guard case .privateMessage(let removeCommit) = out.commit else {
			Issue.record("expected a private commit")
			return
		}
		// `validating(commit: PrivateMessage)` opens the frame (spending Alice's
		// handshake generation on Bob) BEFORE it sees the self-removal — the
		// transition's `group` carries that consumption.
		let transition = try t.bobView.validating(
			provider, commit: removeCommit, proposals: .init(), psk: { _ in nil })
		let consumed = transition.group
		switch transition.takeOutput() {
		case .pending(let pending):
			#expect(pending.effects.events.contains(.removed(leaf: bobLeaf)))
			#expect(pending.effects.events.contains(.membershipRemoved(leaf: bobLeaf)))
			_ = try pending.apply(onto: consumed)
		case .rejected(let rejection):
			Issue.record("expected .pending, got .rejected: \(rejection.reason)")
			return
		}
		// A replay of Alice's commit is rejected — the generation is spent.
		#expect(throws: MLS.RFC9420.GroupError.self) {
			_ = try consumed.validating(
				provider, commit: removeCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}

	@Test("a Remove and an Add refilling the same leaf report `removed` before `added`")
	func removeThenAddSameLeafOrder() throws {
		let provider = Self.provider
		let t = try PerMembershipReceiveTests.trio()  // Alice(0), Bob(1), Carol(2)
		let dave = try SelfInteropTests.member("dave")
		let bobLeaf = t.bobView.myLeafIndex

		// Carol commits Remove(Bob) + Add(Dave): §12.3 applies remove then add, so
		// Dave fills Bob's freed leaf 1. The effect stream MUST free the leaf before
		// refilling it, or an app replaying a leaf-indexed roster deletes Dave.
		let transition = try t.carolView.committing(
			provider,
			proposals: [.proposal(.remove(bobLeaf)), .proposal(.add(dave.keyPackage))],
			signingKey: t.carol.signingKey, randomness: .generate(provider))
		let events = Self.effects(of: transition)
		let removedIndex = try #require(events.firstIndex(of: .removed(leaf: bobLeaf)))
		let addedIndex = try #require(
			events.firstIndex {
				if case .added(let leaf, _) = $0 { return leaf == bobLeaf }
				return false
			})
		#expect(removedIndex < addedIndex)
	}

	@Test("N = 2 full eviction: a commit removing BOTH local memberships is terminal")
	func fullEvictionBothLocalMemberships() throws {
		let provider = Self.provider
		var t = try PerMembershipReceiveTests.trio()  // {Alice, Bob} local, Carol remote
		let aliceLeaf = t.multi.memberships[0].leafIndex
		let bobLeaf = t.multi.memberships[1].leafIndex

		// Carol removes BOTH Alice and Bob — every local membership of the composite.
		let out = try t.carolView.commit(
			provider,
			proposals: [.proposal(.remove(aliceLeaf)), .proposal(.remove(bobLeaf))],
			signingKey: t.carol.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		guard case .publicMessage(let removeCommit) = out.commit else {
			Issue.record("expected a public commit")
			return
		}
		let baseEpoch = t.multi.context.epoch
		let pending = try t.multi.validating(
			provider, commit: removeCommit, proposals: .init(), psk: { _ in nil })
		// Both reported removed + membership-removed; no epoch advance (terminal).
		#expect(pending.effects.events.contains(.membershipRemoved(leaf: aliceLeaf)))
		#expect(pending.effects.events.contains(.membershipRemoved(leaf: bobLeaf)))
		#expect(
			!pending.effects.events.contains {
				if case .epochAdvanced = $0 { return true }
				return false
			})
		// Terminal apply returns the group unchanged (never shrinks to zero).
		let terminal = try pending.apply(onto: t.multi).group
		#expect(terminal.context.epoch == baseEpoch)
		#expect(terminal.memberships.map(\.leafIndex) == [aliceLeaf, bobLeaf])

		// The eager shim throws, since every local membership is gone.
		#expect(throws: MLS.RFC9420.GroupError.removedFromGroup) {
			_ = try t.multi.processing(
				provider, commit: removeCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}
}
