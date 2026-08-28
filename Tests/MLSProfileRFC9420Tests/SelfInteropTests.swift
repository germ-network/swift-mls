import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath
import Testing

@testable import MLSProfileRFC9420

/// Phase 6b's gate: construction driven against the vector-proven receive
/// path, **cross-member** — the committer's derived state must equal what
/// a receiver processing the same bytes derives, on every field that must
/// converge. (Self-processing one's own path commit is structurally
/// impossible: decap never finds the committer's own leaf in its own
/// copath resolutions.)
@Suite("Self-interop: construct at one member, process at the others")
struct SelfInteropTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	struct Member {
		let identity: Data
		let signingKey: MLS.SignatureSecretKey
		let signatureKey: MLS.SignaturePublicKey
		let leafSecretKey: MLS.HpkeSecretKey
		let initSecretKey: MLS.HpkeSecretKey
		let keyPackage: MLS.RFC9420.KeyPackage

		var joinCredentials: MLS.RFC9420.Group.JoinerCredentials {
			.init(
				keyPackage: keyPackage, initKey: initSecretKey,
				encryptionKey: leafSecretKey)
		}
	}

	static func member(_ name: String) throws -> Member {
		let provider = Self.provider
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(provider)
		let (leafSecret, leafPublic) = try provider.hpkeGenerateKeyPair()
		let (initSecret, initPublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublic, signatureKey: signatureKey,
			credential: .basic(identity: Data(name.utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: .curve25519Aes128, initKey: initPublic,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return Member(
			identity: Data(name.utf8), signingKey: signingKey,
			signatureKey: signatureKey, leafSecretKey: leafSecret,
			initSecretKey: initSecret, keyPackage: keyPackage)
	}

	static func createGroup(_ founder: Member) throws -> MLS.RFC9420.Group {
		try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: founder.keyPackage.leafNode,
			leafSecretKey: founder.leafSecretKey,
			epochSecret: provider.randomBytes(provider.hashSize))
	}

	/// The convergence assertion: everything two members' views must agree
	/// on after one epoch, including the private keys they both hold.
	static func assertConverged(
		_ a: MLS.RFC9420.Group, _ b: MLS.RFC9420.Group,
		_ location: SourceLocation = #_sourceLocation
	) {
		#expect(a.context == b.context, sourceLocation: location)
		#expect(a.tree == b.tree, sourceLocation: location)
		#expect(
			a.interimTranscriptHash == b.interimTranscriptHash,
			sourceLocation: location)
		#expect(
			a.epoch.epochAuthenticator == b.epoch.epochAuthenticator,
			sourceLocation: location)
		let shared = Set(a.secretKeys.keys).intersection(b.secretKeys.keys)
		for node in shared {
			#expect(
				a.secretKeys[node]?.data == b.secretKeys[node]?.data,
				"secret key at node \(node)", sourceLocation: location)
		}
	}

	/// The backbone: create → add (full commit + Welcome) → join → empty
	/// PCS commit back → pathless add → external-PSK commit → remove.
	@Test("a constructed group survives five epochs of round trips")
	func backbone() throws {
		let provider = Self.provider
		let alice = try Self.member("alice")
		let bob = try Self.member("bob")
		let carol = try Self.member("carol")

		// Epoch 0 -> 1: Alice adds Bob, full commit, Welcome.
		var groupA = try Self.createGroup(alice)
		let add = try groupA.committing(
			provider,
			proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey,
			randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		Self.assertConverged(groupA, groupB)

		// Epoch 1 -> 2: Bob answers with an empty commit (pure PCS).
		let pcs = try groupB.committing(
			provider, proposals: [], signingKey: bob.signingKey,
			randomness: .generate(provider))
		groupB = pcs.group
		#expect(pcs.welcome == nil)
		try groupA.process(provider, commit: pcs.commit, proposals: [:], psk: { _ in nil })
		Self.assertConverged(groupA, groupB)

		// Epoch 2 -> 3: Alice adds Carol *pathlessly* (§12.4's MAY).
		let addCarol = try groupA.committing(
			provider,
			proposals: [.proposal(.add(carol.keyPackage))],
			signingKey: alice.signingKey,
			randomness: .generate(provider),
			includePath: false)
		groupA = addCarol.group
		try groupB.process(
			provider, commit: addCarol.commit, proposals: [:], psk: { _ in nil })
		var groupC = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(addCarol.welcome),
			credentials: carol.joinCredentials, psk: { _ in nil })
		Self.assertConverged(groupA, groupB)
		Self.assertConverged(groupA, groupC)

		// Epoch 3 -> 4: an external PSK, committed pathlessly by Bob.
		let pskID = Data("interop-psk".utf8)
		let pskSecret = provider.randomBytes(provider.hashSize)
		let resolve: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			guard case .external(let id, _) = id, id == pskID else { return nil }
			return pskSecret
		}
		let psk = try groupB.committing(
			provider,
			proposals: [
				.proposal(
					.preSharedKey(
						.external(
							pskID: pskID,
							nonce: provider.randomBytes(
								provider.hashSize))))
			],
			signingKey: bob.signingKey,
			randomness: .generate(provider),
			includePath: false,
			psk: resolve)
		groupB = psk.group
		try groupA.process(provider, commit: psk.commit, proposals: [:], psk: resolve)
		try groupC.process(provider, commit: psk.commit, proposals: [:], psk: resolve)
		Self.assertConverged(groupA, groupB)
		Self.assertConverged(groupB, groupC)

		// Epoch 4 -> 5: Alice removes Carol; Carol learns she is out.
		let remove = try groupA.committing(
			provider,
			proposals: [.proposal(.remove(groupC.myLeafIndex))],
			signingKey: alice.signingKey,
			randomness: .generate(provider))
		groupA = remove.group
		try groupB.process(
			provider, commit: remove.commit, proposals: [:], psk: { _ in nil })
		#expect(throws: MLS.RFC9420.GroupError.removedFromGroup) {
			try groupC.process(
				provider, commit: remove.commit, proposals: [:], psk: { _ in nil })
		}
		Self.assertConverged(groupA, groupB)
	}

	/// An Update proposed by a non-committer, referenced by the committer —
	/// exercises proposal framing, the store, and §12.3 application end to
	/// end. Bob's own post-update secret is patched directly into his
	/// state: the updater-side key handoff (retaining the new leaf secret
	/// until the update is committed) is a tracked follow-up, not yet API.
	@Test("an Update proposal round-trips by reference")
	func updateByReference() throws {
		let provider = Self.provider
		let alice = try Self.member("alice")
		let bob = try Self.member("bob")

		var groupA = try Self.createGroup(alice)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Bob builds and frames an Update proposal.
		let (newLeafSecret, newLeafPublic) = try provider.hpkeGenerateKeyPair()
		var updateLeaf = bob.keyPackage.leafNode
		updateLeaf.encryptionKey = newLeafPublic
		updateLeaf.source = .update
		updateLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: bob.signingKey, label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: groupB.context.groupID,
					leafIndex: groupB.myLeafIndex)))
		let proposalContent = MLS.RFC9420.FramedContent(
			groupID: groupB.context.groupID, epoch: groupB.context.epoch,
			sender: .member(groupB.myLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(updateLeaf)))
		let framedProposal = try MLS.RFC9420.protectPublic(
			provider, content: proposalContent, groupContext: groupB.context,
			confirmationTag: nil, signingKey: bob.signingKey,
			membershipKey: groupB.epoch.membershipKey)
		let ref = try MLS.RFC9420.proposalRef(
			provider,
			.init(
				wireFormat: .publicMessage, content: framedProposal.content,
				auth: framedProposal.auth))
		let store: MLS.RFC9420.ProposalStore = [
			ref: .init(
				proposal: .update(updateLeaf),
				sender: .member(groupB.myLeafIndex))
		]

		// Alice commits it by reference.
		let commit = try groupA.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = commit.group
		// The updater-side handoff, by hand and *before* processing: the
		// commit replaces Bob's leaf with the update's new key, and decap
		// may need to decrypt the committer's path secret under exactly
		// that key -- a stale held leaf key fails AEAD-open. A real
		// updater holds the new secret from the moment it proposes.
		groupB.secretKeys[2 * groupB.myLeafIndex.value] = newLeafSecret
		try groupB.process(
			provider, commit: commit.commit, proposals: store, psk: { _ in nil })
		Self.assertConverged(groupA, groupB)

		// Both sides keep working: Bob commits the next epoch.
		let next = try groupB.committing(
			provider, proposals: [], signingKey: bob.signingKey,
			randomness: .generate(provider))
		groupB = next.group
		try groupA.process(provider, commit: next.commit, proposals: [:], psk: { _ in nil })
		Self.assertConverged(groupA, groupB)
	}
}
