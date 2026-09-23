import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeKEM
import MLSTreeMath
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
}
