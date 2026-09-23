import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeKEM
import MLSTreeMath
import SecretBytes
import Testing

@_spi(Migration) @testable import MLSProfileRFC9420

/// `Group.insertMigratedOwnUpdate`: the migration-only SPI that restores a
/// member's own outstanding Update proposal when the prior implementation
/// kept it without the signed framing bytes `ProposalStore.insert` needs.
/// Every rejection here is crafted so ONLY the one check under test fails —
/// everything else about the leaf is genuine — so a mutation that drops that
/// one check is what makes the insert succeed, not a different check's
/// error simply changing identity.
@Suite("Migrated own-Update SPI (@_spi(Migration))")
struct MigratedOwnUpdateTests {
	static let provider = SelfInteropTests.provider

	struct Fixture {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
		var aliceLeaf: MLS.LeafIndex
		var bobLeaf: MLS.LeafIndex
		/// The genuine, validly-signed Update leaf Alice proposed (U1) — exactly
		/// what a pre-migration export would have kept alongside `ref`, minus
		/// the framing bytes. Its `encryptionKey` is recorded in Alice's own
		/// `pendingUpdate`.
		var updateLeaf: MLS.RFC9420.LeafNode
		var ref: MLS.HashReference
		/// Bob's own, unaffected store: he received and verified Alice's real
		/// proposal the ordinary way, so he can commit it by reference.
		var bobStore: MLS.RFC9420.ProposalStore
		/// A store pre-populated with one unrelated, genuinely VERIFIED entry
		/// (Bob's own proposed Update) — every rejection test starts from this,
		/// so "the store is unchanged" is shown against real content, not just
		/// emptiness.
		var baselineStore: MLS.RFC9420.ProposalStore
		var baselineRef: MLS.HashReference
		var baselineProposal: MLS.RFC9420.StoredProposal
	}

	enum Failure: Error { case shape }

	static func fixture() throws -> Fixture {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("migrated-alice")
		let bob = try SelfInteropTests.member("migrated-bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let aliceLeaf = groupA.myLeafIndex
		let bobLeaf = try #require(
			groupA.tree.nonBlankLeaves().map(\.index).first { $0 != aliceLeaf })

		// Alice proposes her own Update (U1/R1) — publicMessage framing so the
		// test can read the leaf straight off the wire content, exactly as
		// another implementation's pre-migration export would have kept it.
		let (message, ref) = try groupA.proposeUpdate(
			provider, signingKey: alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed) = message else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf)) = framed.content.content else {
			throw Failure.shape
		}

		// Bob is unaffected by the migration: he receives and verifies Alice's
		// real proposal the ordinary way, into his own, correctly-paired store.
		var bobStore = MLS.RFC9420.ProposalStore()
		let insertedRef = try bobStore.insert(
			try groupB.verifying(provider, proposal: framed), provider)
		#expect(insertedRef == ref)

		// An unrelated, genuinely-verified baseline entry — Bob's own proposed
		// Update — so every rejection test can start from a non-empty store.
		let (bobMessage, baselineRef) = try groupB.proposeUpdate(
			provider, signingKey: bob.signingKey, framing: .publicMessage)
		guard case .publicMessage(let bobFramed) = bobMessage else { throw Failure.shape }
		var baselineStore = MLS.RFC9420.ProposalStore()
		let insertedBaselineRef = try baselineStore.insert(
			try groupA.verifying(provider, proposal: bobFramed), provider)
		#expect(insertedBaselineRef == baselineRef)
		let baselineProposal = try #require(baselineStore[baselineRef])

		return Fixture(
			alice: alice, bob: bob, groupA: groupA, groupB: groupB,
			aliceLeaf: aliceLeaf, bobLeaf: bobLeaf, updateLeaf: updateLeaf, ref: ref,
			bobStore: bobStore, baselineStore: baselineStore, baselineRef: baselineRef,
			baselineProposal: baselineProposal)
	}

	/// A validly self-signed leaf bound to `(groupID, leafIndex)`, carrying the
	/// GIVEN `encryptionKey` and `source` — the general crafting tool every
	/// rejection test below uses to make exactly one thing wrong.
	static func craftedLeaf(
		encryptionKey: MLS.HpkePublicKey, groupID: Data, leafIndex: MLS.LeafIndex,
		source: MLS.RFC9420.LeafNodeSource = .update, identity: String = "crafted"
	) throws -> MLS.RFC9420.LeafNode {
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(
			Self.provider)
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: encryptionKey, signatureKey: signatureKey,
			credential: .basic(identity: Data(identity.utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: source, extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			Self.provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(groupID: groupID, leafIndex: leafIndex)))
		return leaf
	}

	/// Asserts `store` still holds exactly `baseline`'s entry, untouched, and
	/// (unless it IS the baseline's own ref) that `attemptedRef` was never
	/// added.
	static func assertStoreUnchanged(
		_ store: MLS.RFC9420.ProposalStore, baseline: Fixture,
		attemptedRef: MLS.HashReference,
		_ location: SourceLocation = #_sourceLocation
	) {
		#expect(store.count == 1, sourceLocation: location)
		let stillThere = store[baseline.baselineRef]
		#expect(
			stillThere?.proposal == baseline.baselineProposal.proposal,
			sourceLocation: location)
		#expect(
			stillThere?.sender == baseline.baselineProposal.sender,
			sourceLocation: location)
		#expect(
			stillThere?.epoch == baseline.baselineProposal.epoch,
			sourceLocation: location)
		#expect(
			stillThere?.groupID == baseline.baselineProposal.groupID,
			sourceLocation: location)
		if attemptedRef != baseline.baselineRef {
			#expect(store[attemptedRef] == nil, sourceLocation: location)
		}
	}

	// MARK: - Happy path

	@Test(
		"a migrated store lets Bob's by-reference commit land, restoring Alice's leaf, converged with Bob"
	)
	func happyPath() throws {
		let f = try Self.fixture()

		var migratedStore = MLS.RFC9420.ProposalStore()
		try f.groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &migratedStore, ref: f.ref,
			leafNode: f.updateLeaf, epoch: f.groupA.context.epoch,
			groupID: f.groupA.context.groupID)

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var groupA = f.groupA
		try groupA.process(
			Self.provider, commit: commitMessage, proposals: migratedStore,
			psk: { _ in nil })

		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(groupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
		SelfInteropTests.assertConverged(groupA, groupB)
	}

	@Test(
		"the pending secret survives a snapshot round trip, and the migrated insert still succeeds"
	)
	func pendingSecretSurvivesSnapshotRoundTrip() throws {
		let f = try Self.fixture()

		let snapshot = try f.groupA.makeSnapshot()
		var restoredGroupA = try MLS.RFC9420.Group.restore(from: snapshot, Self.provider)
		#expect(restoredGroupA.context == f.groupA.context)

		var migratedStore = MLS.RFC9420.ProposalStore()
		try restoredGroupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &migratedStore, ref: f.ref,
			leafNode: f.updateLeaf, epoch: restoredGroupA.context.epoch,
			groupID: restoredGroupA.context.groupID)

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		try restoredGroupA.process(
			Self.provider, commit: commitMessage, proposals: migratedStore,
			psk: { _ in nil })

		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(restoredGroupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
	}

	// MARK: - Rejections, each isolating exactly one check

	@Test("a leaf claimed for a leaf this Group doesn't occupy is rejected")
	func rejectsNonOwnLeaf() throws {
		let f = try Self.fixture()
		// Bound to Bob's leaf, but carrying the exact key Alice's own
		// pendingUpdate records — everything BUT ownership of `leaf` checks
		// out, so only the own-leaf check stands between this and success.
		let crafted = try Self.craftedLeaf(
			encryptionKey: f.updateLeaf.encryptionKey,
			groupID: f.groupA.context.groupID,
			leafIndex: f.bobLeaf)
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 1)) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.bobLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: f.groupA.context.epoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a proposal claiming a different epoch than the current one is rejected")
	func rejectsWrongEpoch() throws {
		let f = try Self.fixture()
		var store = f.baselineStore
		let wrongEpoch = f.groupA.context.epoch + 1
		#expect(
			throws: MLS.RFC9420.GroupError.wrongEpoch(
				expected: f.groupA.context.epoch, actual: wrongEpoch)
		) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: wrongEpoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a proposal naming a different group is rejected")
	func rejectsWrongGroup() throws {
		let f = try Self.fixture()
		let foreignGroupID = Data("not this group".utf8)
		var store = f.baselineStore
		// The GENUINE leaf (signed for the real `context.groupID`), only the
		// `groupID:` PARAMETER is foreign. `verifySignature` checks against
		// `context.groupID` directly, never the caller-supplied parameter, so
		// only the groupID guard stands between this and success — a leaf
		// crafted to genuinely verify against the foreign id instead would
		// still fail signature verification if that guard were dropped,
		// which wouldn't isolate this check at all.
		#expect(throws: MLS.RFC9420.GroupError.wrongGroup) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: f.groupA.context.epoch,
				groupID: foreignGroupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a leaf whose own signature doesn't verify is rejected")
	func rejectsBadSignature() throws {
		let f = try Self.fixture()
		var tampered = f.updateLeaf
		var bytes = [UInt8](tampered.signature)
		#expect(!bytes.isEmpty)
		bytes[0] ^= 0xFF
		tampered.signature = Data(bytes)

		var store = f.baselineStore
		#expect(throws: MLS.CryptoError.self) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: tampered, epoch: f.groupA.context.epoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a leaf with no matching pending secret at all is rejected")
	func rejectsNoPendingSecret() throws {
		let f = try Self.fixture()
		// A fresh key Alice never proposed — validly self-signed for her own
		// leaf, so only the pending-secret check catches it.
		let (_, freshKey) = try Self.provider.hpkeGenerateKeyPair()
		let crafted = try Self.craftedLeaf(
			encryptionKey: freshKey, groupID: f.groupA.context.groupID,
			leafIndex: f.aliceLeaf)
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateHasNoPendingSecret) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: f.groupA.context.epoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a leaf proposed in an earlier, now-abandoned epoch is rejected")
	func rejectsStalePendingSecret() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		var groupB = f.groupB

		// Bob commits something else entirely, in Alice's proposal epoch,
		// never referencing it. The epoch advances and Alice's pendingUpdate
		// is cleared — exactly what happens when a migrated proposal is never
		// actually committed before some other commit moves the epoch on.
		let other = try groupB.commit(
			Self.provider, proposals: [], signingKey: f.bob.signingKey,
			randomness: .generate(Self.provider), framing: .publicMessage)
		guard case .publicMessage(let otherCommit) = other.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}
		try groupA.process(
			Self.provider, commit: otherCommit, proposals: .init(), psk: { _ in nil })
		#expect(groupA.context.epoch == f.groupA.context.epoch + 1)

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateHasNoPendingSecret) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a pending record stamped for an OLDER epoch, even with the right key, is rejected")
	func rejectsPlantedOlderEpochPendingRecord() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		// Read back the REAL (publicKey, secret) pair `proposeUpdate` produced,
		// then replant it under an epoch one behind the current one — isolates
		// the `pendingUpdate.epoch == context.epoch` comparison itself, apart
		// from the natural clearing an actual epoch advance performs
		// (`rejectsStalePendingSecret`, above).
		let genuineEntry = try #require(
			groupA.pendingUpdates?.updates.first(where: {
				$0.publicKey == f.updateLeaf.encryptionKey
			}))
		groupA.pendingUpdates = (
			epoch: groupA.context.epoch - 1, node: 2 * f.aliceLeaf.value,
			updates: [genuineEntry]
		)

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateHasNoPendingSecret) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a pending entry whose secret doesn't correspond to its public key is rejected")
	func rejectsSecretPossessionMismatch() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		// A genuinely mismatched pair: `publicKey` and `secret` come from TWO
		// SEPARATE keypairs, planted straight into the membership's own
		// `pendingUpdate` — exactly what a corrupted or buggy archive restore
		// could produce (a snapshot restore stamps `pendingUpdate` entries at
		// the current epoch without cross-checking secret against public key).
		let (_, mismatchedPublicKey) = try Self.provider.hpkeGenerateKeyPair()
		let (unrelatedSecretKey, _) = try Self.provider.hpkeGenerateKeyPair()
		groupA.pendingUpdates = (
			epoch: groupA.context.epoch, node: 2 * f.aliceLeaf.value,
			updates: [(publicKey: mismatchedPublicKey, secret: unrelatedSecretKey)]
		)
		let crafted = try Self.craftedLeaf(
			encryptionKey: mismatchedPublicKey, groupID: groupA.context.groupID,
			leafIndex: f.aliceLeaf)

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test(
		"the pending-secret check is scoped to the membership at `leaf`, not any local membership"
	)
	func pendingSecretCheckIsScopedToOwningMembership() throws {
		let f = try Self.fixture()
		// A genuine multi-membership composite (D18): Alice's and Bob's real
		// memberships over ONE shared core. Alice's own `pendingUpdate` (the
		// fixture's real proposal) is real; Bob's is nil.
		let composite = MLS.RFC9420.Group(
			core: f.groupA.core,
			memberships: [f.groupA.memberships[0], f.groupB.memberships[0]])

		// Bound to Bob's leaf, but carrying ALICE's real pending key — if the
		// check were scoped to "any local membership" instead of the one AT
		// `leaf`, this would wrongly pass via Alice's sibling entry.
		let crafted = try Self.craftedLeaf(
			encryptionKey: f.updateLeaf.encryptionKey,
			groupID: composite.context.groupID,
			leafIndex: f.bobLeaf)
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateHasNoPendingSecret) {
			try composite.insertMigratedOwnUpdate(
				as: f.bobLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: composite.context.epoch,
				groupID: composite.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a key_package-sourced leaf is rejected, not accepted in place of an Update")
	func rejectsKeyPackageSourcedLeaf() throws {
		let f = try Self.fixture()
		// Alice's own pending key again, so only the §7.3 source check catches
		// it — ownership, group/epoch, signature, and the pending secret all
		// check out (a key_package-sourced leaf's TBS doesn't even bind
		// placement, so the signature is valid regardless).
		let crafted = try Self.craftedLeaf(
			encryptionKey: f.updateLeaf.encryptionKey,
			groupID: f.groupA.context.groupID,
			leafIndex: f.aliceLeaf,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)))
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.wrongLeafNodeSource) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: f.groupA.context.epoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a leaf reusing the CURRENT leaf's own encryption key fails validity policy")
	func rejectsReusedCurrentEncryptionKey() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		let currentKey = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(groupA.tree.leaf(at: f.aliceLeaf)).encoded
		).encryptionKey
		let currentSecret = try #require(groupA.secretKeys[2 * f.aliceLeaf.value])

		// Plant a pending entry for Alice's CURRENT (pre-update) key itself —
		// genuinely hers, so presence and possession both check out — then
		// craft a leaf "updating" to that SAME key. Pins `replacing:
		// currentLeaf`: only the §7.3 changed-key rule catches this.
		groupA.pendingUpdates = (
			epoch: groupA.context.epoch, node: 2 * f.aliceLeaf.value,
			updates: [(publicKey: currentKey, secret: currentSecret)]
		)
		let crafted = try Self.craftedLeaf(
			encryptionKey: currentKey, groupID: groupA.context.groupID,
			leafIndex: f.aliceLeaf)

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.updateDidNotChangeEncryptionKey) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a leaf claiming a credential type Bob doesn't support is rejected")
	func rejectsCredentialTypeUnsupportedByMember() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		// A fresh, genuinely-held key (planted the same way the possession
		// check expects), but the leaf claims an `.x509` credential — Bob's
		// (and Alice's own current) capabilities only list `.basic`, so the
		// roster's mutual-support sweep rejects it. `proposeUpdate` itself
		// would ALSO refuse this rotation (the same check runs on send), so
		// this is crafted directly rather than through the real API.
		let (secretKey, publicKey) = try Self.provider.hpkeGenerateKeyPair()
		groupA.pendingUpdates = (
			epoch: groupA.context.epoch, node: 2 * f.aliceLeaf.value,
			updates: [(publicKey: publicKey, secret: secretKey)]
		)
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(
			Self.provider)
		var crafted = MLS.RFC9420.LeafNode(
			encryptionKey: publicKey, signatureKey: signatureKey,
			credential: .other(type: MLS.RFC9420.CredentialType(.x509), data: Data()),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.x509)]),
			source: .update, extensions: [], signature: Data())
		crafted.signature = try MLS.signWithLabel(
			Self.provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try crafted.toBeSigned(
				placement: .inGroup(
					groupID: groupA.context.groupID, leafIndex: f.aliceLeaf)))

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a migrated insert never overwrites an existing VERIFIED entry")
	func noOverwriteOfVerifiedEntry() throws {
		let f = try Self.fixture()
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateRefAlreadyStored) {
			try f.groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.baselineRef,
				leafNode: f.updateLeaf, epoch: f.groupA.context.epoch,
				groupID: f.groupA.context.groupID)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.baselineRef)
	}

	@Test("a migrated insert never overwrites an existing MIGRATED entry either")
	func noOverwriteOfMigratedEntry() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		let (message2, _) = try groupA.proposeUpdate(
			Self.provider, signingKey: f.alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed2) = message2 else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf2)) = framed2.content.content else {
			throw Failure.shape
		}

		var store = MLS.RFC9420.ProposalStore()
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
			leafNode: f.updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID)

		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateRefAlreadyStored) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: updateLeaf2, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID)
		}
		let stillStored = try #require(store[f.ref])
		#expect(stillStored.proposal == .update(f.updateLeaf))
		#expect(stillStored.sender == .member(f.aliceLeaf))
		#expect(stillStored.epoch == groupA.context.epoch)
		#expect(stillStored.groupID == groupA.context.groupID)
		#expect(store.count == 1)
	}

	// MARK: - A ref that resolves to nothing vs. a ref that resolves wrong

	@Test(
		"a ref resolving to no entry fails closed: stuck at this epoch, not misapplied"
	)
	func unresolvedRefFailsClosed() throws {
		let f = try Self.fixture()

		var wrongRefBytes = [UInt8](f.ref.data)
		wrongRefBytes[0] ^= 0xFF
		let unresolvedRef = MLS.HashReference(Data(wrongRefBytes))

		var migratedStore = MLS.RFC9420.ProposalStore()
		try f.groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &migratedStore, ref: unresolvedRef,
			leafNode: f.updateLeaf, epoch: f.groupA.context.epoch,
			groupID: f.groupA.context.groupID)
		#expect(migratedStore[unresolvedRef] != nil)
		#expect(migratedStore[f.ref] == nil)

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var groupA = f.groupA
		#expect(throws: MLS.RFC9420.GroupError.unknownProposalReference) {
			try groupA.process(
				Self.provider, commit: commitMessage, proposals: migratedStore,
				psk: { _ in nil })
		}
	}

	@Test(
		"a ref resolving to the WRONG own proposal makes the commit unprocessable, not merely unresolved"
	)
	func swappedRefMakesCommitUnprocessable() throws {
		let f = try Self.fixture()
		var groupA = f.groupA

		// Alice proposes a SECOND Update in the same epoch (U2) — retained
		// alongside U1 (every self-Update in an epoch is kept, not just the
		// latest: the committer, not the proposer, picks which lands).
		let (message2, _) = try groupA.proposeUpdate(
			Self.provider, signingKey: f.alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed2) = message2 else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf2)) = framed2.content.content else {
			throw Failure.shape
		}

		// The migration bug under test: Alice's store maps R1 (`f.ref`) to U2
		// instead of U1. Each leaf is individually, genuinely hers — both
		// pass every check `insertMigratedOwnUpdate` runs — so nothing here
		// can catch the swap. That's the point: the ref-content pairing is
		// exactly what this SPI cannot verify.
		var swappedStore = MLS.RFC9420.ProposalStore()
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &swappedStore, ref: f.ref,
			leafNode: updateLeaf2, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID)

		// Bob commits by reference against HIS OWN, correctly-paired store
		// (R1 -> U1): his commit's UpdatePath (and its parent-hash chain),
		// tree hash, and confirmation tag are all computed over U1's
		// application, not U2's.
		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		// Applying U2 in place of U1 changes the tree Alice's device merges
		// the UpdatePath onto, so the path's parent-hash chain — computed by
		// Bob against a tree with U1 in Alice's slot — no longer matches.
		// Confirmed empirically: this is the first thing that diverges, well
		// before decap or the confirmation tag.
		let snapshotBefore = try groupA.makeSnapshot()
		#expect(throws: MLS.TreeKEM.TreeError.parentHashMismatch) {
			try groupA.process(
				Self.provider, commit: commitMessage, proposals: swappedStore,
				psk: { _ in nil })
		}
		// A public-framed `process` assigns only on success — a throw leaves
		// `groupA` exactly as it was. Compare full snapshots, not just
		// `context`, so "unchanged" covers the tree and memberships too.
		let snapshotAfter = try groupA.makeSnapshot()
		#expect(snapshotBefore == snapshotAfter)
	}

	// MARK: - The `leafSecret:` parameter

	/// `Group.insertMigratedOwnUpdate(..., leafSecret:)`: for an archive that
	/// kept the Update's leaf secret OUTSIDE the group snapshot entirely,
	/// rather than in a retained `pendingUpdate` record. `groupA` here is
	/// restored from a snapshot taken BEFORE Alice's proposal, so it starts
	/// with no `pendingUpdate` at all — every test below (unless it says
	/// otherwise) exercises `leafSecret` as the ONLY path available.
	struct SecretFixture {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
		var aliceLeaf: MLS.LeafIndex
		var bobLeaf: MLS.LeafIndex
		var updateLeaf: MLS.RFC9420.LeafNode
		/// The genuine leaf secret `proposeUpdate` generated for `updateLeaf`,
		/// test-accessible via `pendingUpdates` (`@testable`) — exactly what a
		/// migration archive keeps apart from the group snapshot.
		var leafSecret: MLS.HpkeSecretKey
		var ref: MLS.HashReference
		/// Alice's own `PublicMessage` framing of the proposal `ref` names — kept
		/// so a test can re-verify it through `groupA.verifying(proposal:)`, the
		/// same way a peer's own copy of the proposal would arrive.
		var framed: MLS.RFC9420.PublicMessage
		var bobStore: MLS.RFC9420.ProposalStore
		var baselineStore: MLS.RFC9420.ProposalStore
		var baselineRef: MLS.HashReference
		var baselineProposal: MLS.RFC9420.StoredProposal
	}

	static func secretFixture() throws -> SecretFixture {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("migrated-secret-alice")
		let bob = try SelfInteropTests.member("migrated-secret-bob")

		var groupWithHistory = try SelfInteropTests.createGroup(alice)
		let add = try groupWithHistory.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupWithHistory = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let aliceLeaf = groupWithHistory.myLeafIndex
		let bobLeaf = try #require(
			groupWithHistory.tree.nonBlankLeaves().map(\.index).first {
				$0 != aliceLeaf
			})

		// The snapshot BEFORE Alice proposes — what a migrated archive's group
		// state looks like: no pendingUpdate entry for the Update it's about
		// to restore.
		let preProposalSnapshot = try groupWithHistory.makeSnapshot()

		let (message, ref) = try groupWithHistory.proposeUpdate(
			provider, signingKey: alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed) = message else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf)) = framed.content.content else {
			throw Failure.shape
		}
		let leafSecret = try #require(
			groupWithHistory.pendingUpdates?.updates.first(where: {
				$0.publicKey == updateLeaf.encryptionKey
			})?.secret)

		let groupA = try MLS.RFC9420.Group.restore(from: preProposalSnapshot, provider)
		#expect(groupA.pendingUpdates == nil)

		var bobStore = MLS.RFC9420.ProposalStore()
		let insertedRef = try bobStore.insert(
			try groupB.verifying(provider, proposal: framed), provider)
		#expect(insertedRef == ref)

		// An unrelated, genuinely-verified baseline entry — Bob's own proposed
		// Update — so every rejection test can start from a non-empty store.
		let (bobMessage, baselineRef) = try groupB.proposeUpdate(
			provider, signingKey: bob.signingKey, framing: .publicMessage)
		guard case .publicMessage(let bobFramed) = bobMessage else { throw Failure.shape }
		var baselineStore = MLS.RFC9420.ProposalStore()
		let insertedBaselineRef = try baselineStore.insert(
			try groupA.verifying(provider, proposal: bobFramed), provider)
		#expect(insertedBaselineRef == baselineRef)
		let baselineProposal = try #require(baselineStore[baselineRef])

		return SecretFixture(
			alice: alice, bob: bob, groupA: groupA, groupB: groupB,
			aliceLeaf: aliceLeaf, bobLeaf: bobLeaf, updateLeaf: updateLeaf,
			leafSecret: leafSecret, ref: ref, framed: framed, bobStore: bobStore,
			baselineStore: baselineStore, baselineRef: baselineRef,
			baselineProposal: baselineProposal)
	}

	/// Same shape as `assertStoreUnchanged` above, for `SecretFixture`.
	static func assertStoreUnchanged(
		_ store: MLS.RFC9420.ProposalStore, baseline: SecretFixture,
		attemptedRef: MLS.HashReference,
		_ location: SourceLocation = #_sourceLocation
	) {
		#expect(store.count == 1, sourceLocation: location)
		let stillThere = store[baseline.baselineRef]
		#expect(
			stillThere?.proposal == baseline.baselineProposal.proposal,
			sourceLocation: location)
		#expect(
			stillThere?.sender == baseline.baselineProposal.sender,
			sourceLocation: location)
		#expect(
			stillThere?.epoch == baseline.baselineProposal.epoch,
			sourceLocation: location)
		#expect(
			stillThere?.groupID == baseline.baselineProposal.groupID,
			sourceLocation: location)
		if attemptedRef != baseline.baselineRef {
			#expect(store[attemptedRef] == nil, sourceLocation: location)
		}
	}

	// MARK: Happy path

	@Test(
		"leafSecret happy path: Bob's by-reference commit lands from a group with no prior pendingUpdate, and Alice decrypts what Bob sends next"
	)
	func leafSecretHappyPath() throws {
		let f = try Self.secretFixture()
		// `let`, not `var`: `insertMigratedOwnUpdate` is non-mutating — this
		// would fail to COMPILE if that ever changed.
		let groupA = f.groupA
		#expect(groupA.pendingUpdates == nil)

		var migratedStore = MLS.RFC9420.ProposalStore()
		let snapshotBeforeInsert = try groupA.makeSnapshot()
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &migratedStore, ref: f.ref,
			leafNode: f.updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID, leafSecret: f.leafSecret)
		// The design's whole point: the insert never mutates the group.
		#expect(try groupA.makeSnapshot() == snapshotBeforeInsert)

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var appliedGroupA = groupA
		try appliedGroupA.process(
			Self.provider, commit: commitMessage, proposals: migratedStore,
			psk: { _ in nil })

		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(appliedGroupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
		SelfInteropTests.assertConverged(appliedGroupA, groupB)

		// Not just a key-material match: Alice's freshly-installed leaf
		// actually decrypts what Bob sends in the new epoch.
		let sent = try groupB.protect(
			Self.provider, applicationData: Data("hello after migration".utf8),
			signingKey: f.bob.signingKey)
		let opened = try appliedGroupA.unprotect(Self.provider, message: sent)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("hello after migration".utf8))
	}

	@Test(
		"the fold installs the genuine migrated secret into secretKeys, not just SOME secret, and nothing about the store entry persists in the group snapshot"
	)
	func foldInstallsTheGenuineMigratedSecretAndNothingElsePersists() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA

		var migratedStore = MLS.RFC9420.ProposalStore()
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &migratedStore, ref: f.ref,
			leafNode: f.updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID, leafSecret: f.leafSecret)

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var appliedGroupA = groupA
		try appliedGroupA.process(
			Self.provider, commit: commitMessage, proposals: migratedStore,
			psk: { _ in nil })

		// Installed as usual, and it's the GENUINE migrated secret byte for
		// byte, not merely a non-nil placeholder.
		#expect(
			appliedGroupA.secretKeys[2 * f.aliceLeaf.value]?.data == f.leafSecret.data)
		// Never persisted through `pendingUpdate` — the migrated secret lived
		// only on the caller-owned, ephemeral store entry, never the group.
		#expect(appliedGroupA.pendingUpdates == nil)

		// The snapshot carries nothing extra either: restoring it reproduces
		// the same live state, not a stashed secret.
		let snapshot = try appliedGroupA.makeSnapshot()
		let restored = try MLS.RFC9420.Group.restore(from: snapshot, Self.provider)
		#expect(restored.pendingUpdates == nil)
		#expect(restored.secretKeys[2 * f.aliceLeaf.value]?.data == f.leafSecret.data)
	}

	// MARK: Precedence

	@Test(
		"fold precedence: a group-held pair wins over a store entry carrying a WRONG secret for the same key — the fold still succeeds"
	)
	func foldPrecedenceGroupHeldWinsOverMismatchedStoreEntry() throws {
		let f = try Self.fixture()
		let groupA = f.groupA

		// A store entry built directly (bypassing `insertMigratedOwnUpdate`'s
		// own probe entirely) carrying a WRONG secret for Alice's real Update
		// key. If fold-time precedence favored the store over the group, this
		// would make decap fail; it must not, since the group's own
		// `pendingUpdate` covers this key.
		let (wrongSecret, _) = try Self.provider.hpkeGenerateKeyPair()
		var corruptedStore = MLS.RFC9420.ProposalStore()
		try corruptedStore.insertMigratedOwnUpdate(
			f.ref,
			MLS.RFC9420.StoredProposal(
				proposal: .update(f.updateLeaf), sender: .member(f.aliceLeaf),
				epoch: groupA.context.epoch, groupID: groupA.context.groupID,
				migratedLeafSecret: wrongSecret))

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var appliedGroupA = groupA
		try appliedGroupA.process(
			Self.provider, commit: commitMessage, proposals: corruptedStore,
			psk: { _ in nil })
		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(appliedGroupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
		SelfInteropTests.assertConverged(appliedGroupA, groupB)
	}

	@Test(
		"fold fallback: the group's pending pair covers a DIFFERENT key, so the fold uses the store's migrated secret for the key actually committed"
	)
	func foldFallbackUsedWhenGroupPendingCoversADifferentKey() throws {
		let f = try Self.fixture()
		var groupA = f.groupA
		let originalSecret = try #require(
			groupA.pendingUpdates?.updates.first(where: {
				$0.publicKey == f.updateLeaf.encryptionKey
			})?.secret)

		// A SECOND self-Update, in the SAME epoch — `proposeUpdate` retains
		// every proposed pair, so `pendingUpdate` now covers both keys.
		let (message2, _) = try groupA.proposeUpdate(
			Self.provider, signingKey: f.alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed2) = message2 else { throw Failure.shape }
		guard case .proposal(.update) = framed2.content.content else {
			throw Failure.shape
		}

		// Strip the ORIGINAL key back out: the group's own `pendingUpdate` now
		// covers only the second, uncommitted key, so the primary branch in
		// `installKeysForMembership` can never match the key Bob's commit
		// actually installs — only the fallback (the store's migrated
		// secret) can seed it.
		if var pending = groupA.pendingUpdates {
			pending.updates.removeAll(where: {
				$0.publicKey == f.updateLeaf.encryptionKey
			})
			groupA.pendingUpdates = pending
		}
		#expect(groupA.pendingUpdates?.updates.count == 1)

		var store = MLS.RFC9420.ProposalStore()
		try store.insertMigratedOwnUpdate(
			f.ref,
			MLS.RFC9420.StoredProposal(
				proposal: .update(f.updateLeaf), sender: .member(f.aliceLeaf),
				epoch: groupA.context.epoch, groupID: groupA.context.groupID,
				migratedLeafSecret: originalSecret))

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		try groupA.process(
			Self.provider, commit: commitMessage, proposals: store, psk: { _ in nil })
		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(groupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
		SelfInteropTests.assertConverged(groupA, groupB)
	}

	@Test(
		"precedence: a group-held pair wins even when the supplied secret is wrong — insertion still succeeds, and the wrong secret is never recorded"
	)
	func precedenceGroupHeldWinsOverWrongSupplied() throws {
		let f = try Self.fixture()
		let groupA = f.groupA
		let (wrongSecret, _) = try Self.provider.hpkeGenerateKeyPair()

		var store = f.baselineStore
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
			leafNode: f.updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID, leafSecret: wrongSecret)

		let stored = try #require(store[f.ref])
		#expect(stored.proposal == .update(f.updateLeaf))
		#expect(stored.sender == .member(f.aliceLeaf))
		// Nothing was recorded on the entry: the group-held pair covered it,
		// so the (wrong) supplied secret was never even consulted.
		#expect(stored.migratedLeafSecret == nil)
	}

	// MARK: Rejections with a supplied secret, each isolating exactly one check

	@Test("wrong leaf is rejected even with a supplied secret")
	func leafSecretRejectsWrongLeaf() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let crafted = try Self.craftedLeaf(
			encryptionKey: f.updateLeaf.encryptionKey,
			groupID: groupA.context.groupID, leafIndex: f.bobLeaf)
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 1)) {
			try groupA.insertMigratedOwnUpdate(
				as: f.bobLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: f.leafSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("wrong epoch is rejected even with a supplied secret")
	func leafSecretRejectsWrongEpoch() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		var store = f.baselineStore
		let wrongEpoch = groupA.context.epoch + 1
		#expect(
			throws: MLS.RFC9420.GroupError.wrongEpoch(
				expected: groupA.context.epoch, actual: wrongEpoch)
		) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: wrongEpoch,
				groupID: groupA.context.groupID, leafSecret: f.leafSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("wrong group is rejected even with a supplied secret")
	func leafSecretRejectsWrongGroup() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let foreignGroupID = Data("not this group".utf8)
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.wrongGroup) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: foreignGroupID, leafSecret: f.leafSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a migrated insert with a supplied secret never overwrites an existing entry either")
	func leafSecretRejectsDuplicateRef() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateRefAlreadyStored) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.baselineRef,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: f.leafSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.baselineRef)
	}

	@Test("a leaf whose own signature doesn't verify is rejected even with a supplied secret")
	func leafSecretRejectsBadSignature() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		var tampered = f.updateLeaf
		var bytes = [UInt8](tampered.signature)
		#expect(!bytes.isEmpty)
		bytes[0] ^= 0xFF
		tampered.signature = Data(bytes)

		var store = f.baselineStore
		#expect(throws: MLS.CryptoError.self) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: tampered, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: f.leafSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test(
		"a leaf claiming a credential type Bob doesn't support is rejected, with a MATCHING supplied secret"
	)
	func leafSecretRejectsPolicy() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		// A genuinely matching key/secret pair (the possession check passes),
		// but the leaf claims an `.x509` credential — only the §7.3 roster
		// mutual-support sweep catches it.
		let (secretKey, publicKey) = try Self.provider.hpkeGenerateKeyPair()
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(
			Self.provider)
		var crafted = MLS.RFC9420.LeafNode(
			encryptionKey: publicKey, signatureKey: signatureKey,
			credential: .other(type: MLS.RFC9420.CredentialType(.x509), data: Data()),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.x509)]),
			source: .update, extensions: [], signature: Data())
		crafted.signature = try MLS.signWithLabel(
			Self.provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try crafted.toBeSigned(
				placement: .inGroup(
					groupID: groupA.context.groupID, leafIndex: f.aliceLeaf)))

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: secretKey)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	// The suite this whole file otherwise runs on (`curve25519Aes128`) has a
	// fixed, unambiguous 32-byte HPKE secret key (Nsk): CryptoKit itself
	// already rejects a wrong-length raw X25519 key, so these two confirm
	// the OBSERVABLE contract (wrong length -> `migratedUpdateSecretMismatch`)
	// without proving the explicit length check is doing independent work.
	// `leafSecretRejectsP521TruncatedSecretByLength`, below, is the test that
	// does: on P-521, a caller-truncated secret can round-trip through
	// `hpkeOpen`'s own zero-padding (`p521Padded`) and so the possession
	// probe ALONE would accept it — only the explicit length check catches
	// it there.

	@Test("a too-short supplied secret is rejected")
	func leafSecretRejectsTooShort() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let tooShort = try MLS.HpkeSecretKey(Data(repeating: 0xAB, count: 31))
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: tooShort)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a too-long supplied secret is rejected")
	func leafSecretRejectsTooLong() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let tooLong = try MLS.HpkeSecretKey(Data(repeating: 0xAB, count: 33))
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: tooLong)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test("a supplied secret that doesn't correspond to the leaf's own key is rejected")
	func leafSecretRejectsProbeMismatch() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let (unrelatedSecret, _) = try Self.provider.hpkeGenerateKeyPair()
		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try groupA.insertMigratedOwnUpdate(
				as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: f.updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: unrelatedSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	@Test(
		"P-521: a secret truncated to its minimal 65-byte encoding is rejected by the length check (the probe alone would accept it), while the genuine full-length secret succeeds"
	)
	func leafSecretRejectsP521TruncatedSecretByLength() throws {
		// No existing MLSProfileRFC9420Tests helper builds a P-521 group —
		// `SelfInteropTests.member`/`createGroup` and
		// `GroupMutationTests.signingKeyPair` are all Curve25519-only, and
		// P-521's own signing key isn't Ed25519 either
		// (`SwiftCryptoProvider.sign` routes `.p521Aes256` through
		// `P521.Signing.PrivateKey`). Built directly here instead: the
		// minimal single-founder group `Group.create` needs, no
		// Add/Welcome/Join required.
		let p521 = try #require(
			SwiftCryptoProvider().cipherSuiteProvider(for: .p521Aes256))

		let founderSigningKey = P521.Signing.PrivateKey()
		let founderSignatureSecret = try MLS.SignatureSecretKey(
			founderSigningKey.rawRepresentation)
		let founderSignaturePublic = MLS.SignaturePublicKey(
			founderSigningKey.publicKey.x963Representation)
		let (founderLeafSecret, founderLeafPublic) = try p521.hpkeGenerateKeyPair()

		var founderLeaf = MLS.RFC9420.LeafNode(
			encryptionKey: founderLeafPublic, signatureKey: founderSignaturePublic,
			credential: .basic(identity: Data("p521-alice".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.p521Aes256],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		founderLeaf.signature = try MLS.signWithLabel(
			p521, privateKey: founderSignatureSecret, label: "LeafNodeTBS",
			content: try founderLeaf.toBeSigned(placement: .keyPackage))

		let groupA = try MLS.RFC9420.Group.create(
			p521, groupID: p521.randomBytes(p521.hashSize),
			leafNode: founderLeaf, leafSecretKey: founderLeafSecret,
			epochSecret: SecretBytes(randomByteCount: p521.hashSize))
		let aliceLeaf = groupA.myLeafIndex

		// Hunt for a genuine P-521 HPKE key pair whose 66-byte raw secret has
		// a leading zero byte — roughly half of all keys, per
		// `P521MinimalKeyTests.opensWithMinimallyEncodedSecretKey` (MLSCrypto
		// target), which vets this exact `p521Padded` round-trip at the
		// provider level. 4096 tries is astronomically more than needed.
		var found: (secretKey: MLS.HpkeSecretKey, publicKey: MLS.HpkePublicKey)?
		for _ in 0..<4096 {
			let (secretKey, publicKey) = try p521.hpkeGenerateKeyPair()
			if secretKey.data.byteCount == 66,
				secretKey.data.withUnsafeBytes({ $0.first == 0 })
			{
				found = (secretKey, publicKey)
				break
			}
		}
		let (fullSecret, updatePublicKey) = try #require(found)

		// The Update leaf genuinely claiming that key, self-signed for
		// Alice's placement.
		var updateLeaf = founderLeaf
		updateLeaf.encryptionKey = updatePublicKey
		updateLeaf.source = .update
		updateLeaf.signature = Data()
		updateLeaf.signature = try MLS.signWithLabel(
			p521, privateKey: founderSignatureSecret, label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: groupA.context.groupID, leafIndex: aliceLeaf)))

		// The caller-supplied secret, truncated to the minimal 65-byte
		// encoding — exactly what a migration archive using a minimal-length
		// codec would have kept, and exactly what `p521Padded`
		// (SwiftCryptoProvider.swift) re-pads back to the genuine 66-byte
		// value on the way into `hpkeOpen`.
		let truncatedSecret = try MLS.HpkeSecretKey(
			fullSecret.data.withUnsafeBytes { Data($0.dropFirst()) })
		#expect(truncatedSecret.data.byteCount == 65)

		var store = MLS.RFC9420.ProposalStore()
		let ref = MLS.HashReference(p521.randomBytes(p521.hashSize))
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try groupA.insertMigratedOwnUpdate(
				as: aliceLeaf, p521, into: &store, ref: ref,
				leafNode: updateLeaf, epoch: groupA.context.epoch,
				groupID: groupA.context.groupID, leafSecret: truncatedSecret)
		}
		#expect(store.count == 0)

		// Positive control: the SAME key pair, at its genuine full 66-byte
		// length, succeeds — the length check doesn't reject a genuinely
		// correct P-521 secret, only a short one.
		var fullStore = MLS.RFC9420.ProposalStore()
		let fullRef = MLS.HashReference(p521.randomBytes(p521.hashSize))
		try groupA.insertMigratedOwnUpdate(
			as: aliceLeaf, p521, into: &fullStore, ref: fullRef,
			leafNode: updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID, leafSecret: fullSecret)
		#expect(fullStore.count == 1)
		#expect(fullStore[fullRef]?.proposal == .update(updateLeaf))
	}

	@Test(
		"in a two-membership composite, a wrong supplied secret is rejected via Bob's OWN scope, not by wrongly matching Alice's sibling entry"
	)
	func leafSecretScopedToOwningMembership() throws {
		let f = try Self.fixture()
		let composite = MLS.RFC9420.Group(
			core: f.groupA.core,
			memberships: [f.groupA.memberships[0], f.groupB.memberships[0]])

		// Bound to Bob's leaf, carrying ALICE's real pending key — if the
		// group-held check were scoped to "any local membership" instead of
		// the one AT `leaf`, this would find Alice's real entry and never
		// even look at the (wrong) supplied secret. Correctly scoped, Bob's
		// OWN `pendingUpdate` (nil) doesn't match, so it falls through to
		// the `leafSecret` branch, where the WRONG secret fails the probe.
		let crafted = try Self.craftedLeaf(
			encryptionKey: f.updateLeaf.encryptionKey,
			groupID: composite.context.groupID, leafIndex: f.bobLeaf)
		let (wrongSecret, _) = try Self.provider.hpkeGenerateKeyPair()

		var store = f.baselineStore
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateSecretMismatch) {
			try composite.insertMigratedOwnUpdate(
				as: f.bobLeaf, Self.provider, into: &store, ref: f.ref,
				leafNode: crafted, epoch: composite.context.epoch,
				groupID: composite.context.groupID, leafSecret: wrongSecret)
		}
		Self.assertStoreUnchanged(store, baseline: f, attemptedRef: f.ref)
	}

	// MARK: Send side (committing)

	@Test(
		"send side: a sibling local membership (Bob) commits Alice's migrated Update by reference via committing(as:)/commit(as:), and the result succeeds and converges with a remote peer"
	)
	func sendSideSiblingCommitsMigratedUpdateByReference() throws {
		// `CommitConstruction.swift`'s own `committing(committerIndex:)` builds
		// the SAME `migratedUpdateSecrets` map `validatedDelta` does and feeds
		// it to `installKeysForMembership` for every OTHER local membership —
		// this exercises that path specifically: Alice (a migrated pending
		// Update, no group-held pair) and Bob (the committer) are BOTH local
		// memberships of one composite, and Carol is a genuinely separate
		// remote party who receives and applies the wire commit.
		let provider = Self.provider
		let alice = try SelfInteropTests.member("migrated-send-alice")
		let bob = try SelfInteropTests.member("migrated-send-bob")
		let carol = try SelfInteropTests.member("migrated-send-carol")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider,
			proposals: [
				.proposal(.add(bob.keyPackage)), .proposal(.add(carol.keyPackage)),
			],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let welcome = try #require(add.welcome)
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: bob.joinCredentials,
			psk: { _ in nil })
		var groupC = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: carol.joinCredentials,
			psk: { _ in nil })

		let aliceLeaf = groupA.myLeafIndex
		let bobLeaf = groupB.myLeafIndex

		// The snapshot BEFORE Alice proposes — the migrated starting point:
		// no `pendingUpdate` entry for the Update it's about to restore.
		let preProposalSnapshot = try groupA.makeSnapshot()

		let (message, ref) = try groupA.proposeUpdate(
			provider, signingKey: alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed) = message else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf)) = framed.content.content else {
			throw Failure.shape
		}
		let leafSecret = try #require(
			groupA.pendingUpdates?.updates.first(where: {
				$0.publicKey == updateLeaf.encryptionKey
			})?.secret)

		let restoredAlice = try MLS.RFC9420.Group.restore(
			from: preProposalSnapshot, provider)
		#expect(restoredAlice.pendingUpdates == nil)

		// Alice's migrated entry alone populates the store the composite will
		// commit from — carrying the leaf secret directly, since no
		// group-held `pendingUpdate` covers it (`restoredAlice` has none).
		// The whole point here is that this entry, NOT an ordinarily-verified
		// one, is what `committing(as:)` resolves `.reference(ref)` to.
		var committingStore = MLS.RFC9420.ProposalStore()
		try restoredAlice.insertMigratedOwnUpdate(
			as: aliceLeaf, provider, into: &committingStore, ref: ref,
			leafNode: updateLeaf, epoch: restoredAlice.context.epoch,
			groupID: restoredAlice.context.groupID, leafSecret: leafSecret)

		// The composite: Alice (migrated, index 0) and Bob (committer, index
		// 1) as ONE group's two local memberships, sharing `restoredAlice`'s
		// core (identical to `groupB`'s at this point — both are the state
		// right after Add/Welcome, before Alice's proposal).
		var composite = MLS.RFC9420.Group(
			core: restoredAlice.core,
			memberships: [restoredAlice.memberships[0], groupB.memberships[0]])

		let result = try composite.commit(
			as: bobLeaf, provider, proposals: [.reference(ref)],
			proposalStore: committingStore, signingKey: bob.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = result.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		// Alice's own leaf, from the COMMITTER's side, landed exactly as
		// migrated.
		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(composite.tree.leaf(at: aliceLeaf)).encoded)
		#expect(installed == updateLeaf)

		// Carol — a genuinely independent remote party, unrelated to the
		// migration — authenticates Alice's real proposal the ordinary way
		// and applies Bob's commit, and converges with the composite's
		// (Alice's) view.
		var carolStore = MLS.RFC9420.ProposalStore()
		let carolRef = try carolStore.insert(
			try groupC.verifying(provider, proposal: framed), provider)
		#expect(carolRef == ref)
		try groupC.process(
			provider, commit: commitMessage, proposals: carolStore, psk: { _ in nil })
		SelfInteropTests.assertConverged(composite, groupC)
	}

	// MARK: Wrong secret at fold time (internal plumbing)

	@Test(
		"wrong secret at fold time: a store entry carrying a mismatched migrated secret (constructed directly, bypassing the SPI's own probe) makes decap fail authentication, group unchanged"
	)
	func foldRejectsStoreEntryWithMismatchedSecret() throws {
		// A pairing this wrong can never pass through `insertMigratedOwnUpdate`
		// itself — its own possession probe would reject it. Constructed
		// directly via the internal (`@testable`) `StoredProposal` shape and
		// `ProposalStore.insertMigratedOwnUpdate`, to exercise
		// `installKeysForMembership`'s fallback with BAD data — a corrupted
		// store entry, or any future insertion path this SPI doesn't gate.
		let f = try Self.secretFixture()
		let groupA = f.groupA
		let (wrongSecret, _) = try Self.provider.hpkeGenerateKeyPair()

		var corruptedStore = MLS.RFC9420.ProposalStore()
		try corruptedStore.insertMigratedOwnUpdate(
			f.ref,
			MLS.RFC9420.StoredProposal(
				proposal: .update(f.updateLeaf), sender: .member(f.aliceLeaf),
				epoch: groupA.context.epoch, groupID: groupA.context.groupID,
				migratedLeafSecret: wrongSecret))

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var appliedGroupA = groupA
		let snapshotBefore = try groupA.makeSnapshot()
		// The wrong key is validly shaped but can't open what the genuine key
		// sealed. The backend reports that differently (CryptoKit:
		// `.authenticationFailure`; BoringSSL: `.underlyingCoreCryptoError`),
		// so pin the error domain; the passing twin below pins the cause.
		#expect(throws: CryptoKitError.self) {
			try appliedGroupA.process(
				Self.provider, commit: commitMessage, proposals: corruptedStore,
				psk: { _ in nil })
		}
		// A public-framed `process` assigns only on success — a throw leaves
		// `appliedGroupA` exactly as it was.
		#expect(try appliedGroupA.makeSnapshot() == snapshotBefore)
	}

	@Test(
		"the same internal construction, with the CORRECT secret, makes the fold succeed — proving the rejection above is genuinely about the wrong secret, not the internal-construction path itself"
	)
	func foldSucceedsWithMatchingStoreEntrySecret() throws {
		let f = try Self.secretFixture()
		let groupA = f.groupA

		var store = MLS.RFC9420.ProposalStore()
		try store.insertMigratedOwnUpdate(
			f.ref,
			MLS.RFC9420.StoredProposal(
				proposal: .update(f.updateLeaf), sender: .member(f.aliceLeaf),
				epoch: groupA.context.epoch, groupID: groupA.context.groupID,
				migratedLeafSecret: f.leafSecret))

		var groupB = f.groupB
		let commit = try groupB.commit(
			Self.provider, proposals: [.reference(f.ref)], proposalStore: f.bobStore,
			signingKey: f.bob.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let commitMessage) = commit.commit else {
			Issue.record("expected a publicMessage-framed commit")
			return
		}

		var appliedGroupA = groupA
		try appliedGroupA.process(
			Self.provider, commit: commitMessage, proposals: store, psk: { _ in nil })
		let installed = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(appliedGroupA.tree.leaf(at: f.aliceLeaf)).encoded)
		#expect(installed == f.updateLeaf)
		SelfInteropTests.assertConverged(appliedGroupA, groupB)
	}

	// MARK: - `ProposalStore.insert` versus a migrated entry (keep-on-match,
	// throw-on-mismatch)

	/// MATCH: a verified proposal arriving under a ref the migration already
	/// populated, with content matching exactly, is idempotent — the existing
	/// (migrated) entry is kept untouched, so its `migratedLeafSecret` survives.
	@Test(
		"insert keeps a migrated entry untouched when the verified proposal's content matches"
	)
	func insertKeepsMigratedEntryOnMatch() throws {
		let f = try Self.secretFixture()
		var store = MLS.RFC9420.ProposalStore()
		try f.groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &store, ref: f.ref,
			leafNode: f.updateLeaf, epoch: f.groupA.context.epoch,
			groupID: f.groupA.context.groupID, leafSecret: f.leafSecret)

		let returnedRef = try store.insert(
			f.groupA.verifying(Self.provider, proposal: f.framed), Self.provider)

		#expect(returnedRef == f.ref)
		#expect(store.count == 1)
		#expect(store[f.ref]?.migratedLeafSecret != nil)
	}

	/// MISMATCH: a verified proposal arriving under a ref the migration
	/// mispaired — same ref, different content — is refused rather than
	/// silently accepted or used to overwrite: the migrated `(ref, leafNode)`
	/// pairing was wrong, which is exactly the mistake `insertMigratedOwnUpdate`
	/// itself cannot check (see its doc comment).
	@Test(
		"insert throws when a verified proposal's content mismatches a migrated entry under the same ref"
	)
	func insertThrowsOnMismatchedMigratedEntry() throws {
		let f = try Self.fixture()
		var groupA = f.groupA

		// Alice proposes a SECOND Update (U2/R2) — retained alongside U1, same as
		// `noOverwriteOfMigratedEntry`.
		let (message2, ref2) = try groupA.proposeUpdate(
			Self.provider, signingKey: f.alice.signingKey, framing: .publicMessage)
		guard case .publicMessage(let framed2) = message2 else { throw Failure.shape }
		guard case .proposal(.update(let updateLeaf2)) = framed2.content.content else {
			throw Failure.shape
		}
		#expect(updateLeaf2 != f.updateLeaf)

		// The migration mispairs R2 with U1 (`f.updateLeaf`) instead of U2 —
		// individually genuine, but the wrong leaf for this ref.
		var store = MLS.RFC9420.ProposalStore()
		try groupA.insertMigratedOwnUpdate(
			as: f.aliceLeaf, Self.provider, into: &store, ref: ref2,
			leafNode: f.updateLeaf, epoch: groupA.context.epoch,
			groupID: groupA.context.groupID)

		// A genuinely verified copy of the REAL proposal (U2) later arrives under
		// R2 — its content disagrees with what the migration stored there.
		#expect(throws: MLS.RFC9420.GroupError.migratedUpdateRefAlreadyStored) {
			try store.insert(
				groupA.verifying(Self.provider, proposal: framed2), Self.provider)
		}
		let stillStored = try #require(store[ref2])
		#expect(stillStored.proposal == .update(f.updateLeaf))
		#expect(store.count == 1)
	}

	/// CONTROL: with no migrated entry involved, inserting the same verified
	/// proposal twice is an idempotent overwrite, so the MATCH/MISMATCH results
	/// above aren't just "insert always throws/keeps".
	@Test("insert accepts the same verified proposal twice when nothing is migrated")
	func insertAcceptsRepeatVerifiedInsertWithNoMigratedEntry() throws {
		let f = try Self.secretFixture()
		var store = MLS.RFC9420.ProposalStore()
		let firstRef = try store.insert(
			f.groupA.verifying(Self.provider, proposal: f.framed), Self.provider)
		let secondRef = try store.insert(
			f.groupA.verifying(Self.provider, proposal: f.framed), Self.provider)

		#expect(firstRef == f.ref)
		#expect(secondRef == f.ref)
		#expect(store.count == 1)
	}
}
