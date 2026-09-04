import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// Round-trip coverage for `Group.archive()/restore()` (spec/snapshot.md,
/// format 1). The §8 golden-vector and hostile-decode suites, and the peer
/// differential test, are separately gated; these are the round-trip
/// obligations of the archive/restore PR, with the fatal cases —
/// frontier + chains, retired chains, the on-wire retirement bound —
/// mutation-verified.
@Suite("Snapshot archive/restore (spec/snapshot.md format 1)")
struct SnapshotTests {
	static let provider = SelfInteropTests.provider

	private typealias Group = MLS.RFC9420.Group

	/// Every field the snapshot captures survives archive→restore. Compared via
	/// `makeSnapshot()` equality (order-independent over the integer-keyed
	/// maps), which is exactly the round-trip property.
	private func expectRoundTrips(_ group: Group, _ file: StaticString = #filePath) throws {
		let restored = try Group.restore(from: try group.archive(), Self.provider)
		#expect(try restored.makeSnapshot() == (try group.makeSnapshot()))
	}

	// MARK: - Value-level

	@Test("a real group's Snapshot round-trips through SecretArchive by value")
	func snapshotValueRoundTrips() throws {
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let snapshot = try group.makeSnapshot()
		let decoded = try SecretArchive(encoding: snapshot).decode(Group.Snapshot.self)
		#expect(decoded == snapshot)
	}

	@Test("an empty node_secrets frontier (fully consumed tree) round-trips")
	func emptyNodeSecretsRoundTrips() throws {
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let epoch = group.context.epoch
		// §4.3: node_secrets MAY be empty. Force the fully-consumed state and
		// confirm the empty CBOR map round-trips (spec/snapshot.md §3).
		group.messageSecrets[epoch]!.tree = MLS.RFC9420.Group.ConsumingSecretTree(
			restoringNodeSecrets: [:], leafCount: group.tree.leafCount)
		let snapshot = try group.makeSnapshot()
		#expect(
			snapshot.messageSecrets.entries[epoch]!.secretTree.nodeSecrets.entries
				.isEmpty)
		let decoded = try SecretArchive(encoding: snapshot).decode(Group.Snapshot.self)
		#expect(decoded == snapshot)
	}

	// MARK: - Group round-trips

	@Test("a fresh single-member group round-trips (chains empty, frontier seeded)")
	func freshGroupRoundTrips() throws {
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let epoch = group.context.epoch
		#expect(group.messageSecrets[epoch]!.chains.isEmpty)
		#expect(!group.messageSecrets[epoch]!.tree.nodeSecrets.isEmpty)
		try expectRoundTrips(group)
	}

	/// The fatal-if-wrong path: after one received message the store holds BOTH
	/// the interior `node_secrets` frontier AND the sender's ratchet `chains`.
	/// Restore must carry both — the behavioral check proves the restored
	/// ratchet still decrypts.
	@Test("a receiver with populated chains AND frontier round-trips and keeps decrypting")
	func receiverRoundTrips() throws {
		var duo = try ApplicationMessageTests.duo()
		let first = try duo.groupA.protect(
			Self.provider, applicationData: Data("hello".utf8),
			signingKey: duo.alice.signingKey)
		_ = try duo.groupB.unprotect(Self.provider, message: first)

		let epoch = duo.groupB.context.epoch
		#expect(duo.groupB.messageSecrets[epoch]!.chains.count >= 2)  // both ratchets
		#expect(!duo.groupB.messageSecrets[epoch]!.tree.nodeSecrets.isEmpty)

		try expectRoundTrips(duo.groupB)

		var restored = try Group.restore(from: try duo.groupB.archive(), Self.provider)
		let next = try duo.groupA.protect(
			Self.provider, applicationData: Data("world".utf8),
			signingKey: duo.alice.signingKey)
		let opened = try restored.unprotect(Self.provider, message: next)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("world".utf8))
	}

	@Test("two retained epochs' stores round-trip")
	func multiEpochRoundTrips() throws {
		var duo = try ApplicationMessageTests.duo()
		let old = try duo.groupA.protect(
			Self.provider, applicationData: Data("epoch1".utf8),
			signingKey: duo.alice.signingKey)
		_ = try duo.groupB.unprotect(Self.provider, message: old)

		let commit = try duo.groupA.committing(
			Self.provider, proposals: [], signingKey: duo.alice.signingKey,
			randomness: .generate(Self.provider))
		duo.groupA = commit.group
		guard case .privateMessage(let framed) = commit.commit else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}
		try duo.groupB.process(
			Self.provider, privateCommit: framed, proposals: .init(), psk: { _ in nil })

		#expect(duo.groupB.messageSecrets.count >= 2)
		try expectRoundTrips(duo.groupB)
	}

	// MARK: - Retired chain (the 2^32 mapping and the on-wire skipped bound, H3/L5)

	@Test("a retired chain with skipped keys encodes head_generation 2^32 and restores")
	func retiredChainRoundTrips() throws {
		var duo = try ApplicationMessageTests.duo()
		let first = try duo.groupA.protect(
			Self.provider, applicationData: Data("x".utf8),
			signingKey: duo.alice.signingKey)
		_ = try duo.groupB.unprotect(Self.provider, message: first)

		var group = duo.groupB
		let epoch = group.context.epoch
		// alice is the founder at leaf 0; her application chain was bootstrapped
		// by the received message.
		let chainKey = Group.MessageSecrets.ChainKey(
			leaf: MLS.LeafIndex(value: 0), isHandshake: false)
		#expect(group.messageSecrets[epoch]!.chains[chainKey] != nil)

		let nk = Self.provider.aeadKeySize
		let nn = Self.provider.aeadNonceSize
		// Retire the chain the way the ratchet does: head consumed with nothing
		// retainable (headSecret nil, headGeneration wrapped to 0), and a
		// still-valid generation retained in `skipped`.
		group.messageSecrets[epoch]!.chains[chainKey]!.headSecret = nil
		group.messageSecrets[epoch]!.chains[chainKey]!.headGeneration = 0
		group.messageSecrets[epoch]!.chains[chainKey]!.skipped = [
			3: (
				key: SecretBytes(randomByteCount: nk),
				nonce: Data(Self.provider.randomBytes(nn))
			)
		]

		let snapshot = try group.makeSnapshot()
		let packed = (UInt64(0) << 1) | 1  // leaf 0, application kind bit
		let chainArchive = try #require(
			snapshot.messageSecrets.entries[epoch]!.chains.entries[packed])
		// L5: retirement encodes head_generation = 2^32 with head_secret absent.
		#expect(chainArchive.headGeneration == (1 << 32))
		#expect(chainArchive.headSecret == nil)
		#expect(chainArchive.skipped.entries[3] != nil)

		// H3: restore MUST validate `skipped < head_generation` against the
		// on-wire 2^32, not the narrowed 0 — so this restore SUCCEEDS. Were the
		// check run after narrowing, `3 < 0` is false and it would throw.
		let restored = try Group.restore(from: snapshot, Self.provider)
		let restoredChain = try #require(restored.messageSecrets[epoch]!.chains[chainKey])
		#expect(restoredChain.headSecret == nil)
		#expect(restoredChain.headGeneration == 0)
		#expect(restoredChain.skipped[3] != nil)
	}

	// MARK: - Decode strictness (throws, never traps)

	@Test("an unknown format is rejected")
	func rejectsWrongFormat() throws {
		var snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		snapshot.format = 2
		#expect(throws: MLS.RFC9420.SnapshotError.unsupportedFormat(2)) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	@Test("a present config section is rejected (§4.5)")
	func rejectsPresentConfig() throws {
		var snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		snapshot.config = Group.SnapshotConfig()
		#expect(throws: MLS.RFC9420.SnapshotError.unexpectedConfig) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	@Test("a provider for the wrong suite is rejected")
	func rejectsSuiteMismatch() throws {
		let snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		let wrong = SwiftCryptoProvider().cipherSuiteProvider(for: .p256Aes128)!
		#expect(throws: MLS.RFC9420.SnapshotError.cipherSuiteMismatch) {
			_ = try Group.restore(from: snapshot, wrong)
		}
	}

	@Test("empty tree_secret_keys is rejected (§4.1 key 6, never empty)")
	func rejectsEmptyTreeSecretKeys() throws {
		var snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		snapshot.treeSecretKeys = MLS.RFC9420.IntegerKeyedMap([:])
		#expect(
			throws: MLS.RFC9420.SnapshotError.unexpectedlyEmpty(
				field: "tree_secret_keys")
		) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	@Test("a malformed retirement (head_secret present with head_generation 2^32) is rejected")
	func rejectsMalformedRetirement() throws {
		var duo = try ApplicationMessageTests.duo()
		let first = try duo.groupA.protect(
			Self.provider, applicationData: Data("x".utf8),
			signingKey: duo.alice.signingKey)
		_ = try duo.groupB.unprotect(Self.provider, message: first)
		var snapshot = try duo.groupB.makeSnapshot()
		let epoch = duo.groupB.context.epoch
		let packed = (UInt64(0) << 1) | 1
		// head_secret present but head_generation forced to the retired sentinel.
		snapshot.messageSecrets.entries[epoch]!.chains.entries[packed]!.headGeneration =
			1 << 32
		#expect(throws: MLS.RFC9420.SnapshotError.self) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	@Test("archiving a group with a pending self-Update is refused")
	func rejectsPendingUpdate() throws {
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		// A snapshot cannot capture the pending self-Update's leaf secret in
		// format 1, so makeSnapshot refuses rather than silently drop it.
		group.pendingUpdates = (
			epoch: group.context.epoch, node: 0,
			updates: []
		)
		#expect(throws: MLS.RFC9420.SnapshotError.pendingUpdatesUnsupported) {
			_ = try group.makeSnapshot()
		}
	}

	@Test("a retention value at or above 2^32 is refused on encode (§4.4)")
	func rejectsRetentionOverflowOnEncode() throws {
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		group.retention = .init(maxForwardJump: Int(UInt32.max) + 1)
		#expect(throws: MLS.RFC9420.SnapshotError.self) {
			_ = try group.makeSnapshot()
		}
	}

	@Test("a config section carried in the archive is rejected on decode (§4.5)")
	func rejectsConfigThroughArchive() throws {
		var snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		snapshot.config = Group.SnapshotConfig()
		// Round-trip through a real SecretArchive so key 10 (an empty CBOR map)
		// is actually encoded and decoded — exercising the decodeIfPresent path,
		// not just the in-memory guard.
		let archive = try SecretArchive(encoding: snapshot)
		#expect(throws: MLS.RFC9420.SnapshotError.unexpectedConfig) {
			_ = try Group.restore(from: archive, Self.provider)
		}
	}

	@Test("a my_leaf_index in the trapping overflow window is rejected, not aborted")
	func rejectsOverflowingMyLeafIndex() throws {
		var snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		// In [2^31, 2^32): `leaf(at:)`'s `2 * index` would trap (abort the
		// process) without the pre-guard. It must throw instead.
		snapshot.myLeafIndex = 0x8000_0000
		#expect(throws: MLS.RFC9420.SnapshotError.myLeafIndexBlank(0x8000_0000)) {
			_ = try Group.restore(from: snapshot, Self.provider)
		}
	}

	// MARK: - The send side (own_next_generation must survive — no key/nonce reuse)

	/// The fatal send-side case: every other test archives a non-sender, so a
	/// `restore` that reset `own_next_generation` to (0,0) would pass them all
	/// yet make a restored sender reuse generation 0 — an AEAD key/nonce reuse.
	@Test("a restored sender keeps its own generation counter and does not reuse a generation")
	func senderRoundTripsWithoutGenerationReuse() throws {
		var duo = try ApplicationMessageTests.duo()
		let first = try duo.groupA.protect(
			Self.provider, applicationData: Data("first".utf8),
			signingKey: duo.alice.signingKey)
		let epoch = duo.groupA.context.epoch
		#expect(duo.groupA.messageSecrets[epoch]!.ownNextGeneration.application == 1)

		var restored = try Group.restore(from: try duo.groupA.archive(), Self.provider)
		#expect(restored.messageSecrets[epoch]!.ownNextGeneration.application == 1)

		// The restored sender's next message uses generation 1, not a reused 0.
		let second = try restored.protect(
			Self.provider, applicationData: Data("second".utf8),
			signingKey: duo.alice.signingKey)

		// bob decrypts BOTH. Had restore reset own_next_generation, `second`
		// would reuse generation 0 and collide with `first` (already consumed).
		let opened0 = try duo.groupB.unprotect(Self.provider, message: first)
		let opened1 = try duo.groupB.unprotect(Self.provider, message: second)
		guard case .application(let d0) = opened0.content,
			case .application(let d1) = opened1.content
		else {
			Issue.record("expected application content")
			return
		}
		#expect(d0 == Data("first".utf8))
		#expect(d1 == Data("second".utf8))
	}

	// MARK: - Interior direct-path keys, and the retention-decrease window

	@Test("a committer's strictly-interior direct-path tree_secret_keys round-trip")
	func interiorTreeSecretKeysRoundTrip() throws {
		var duo = try ApplicationMessageTests.duo()
		let carol = try SelfInteropTests.member("carol")
		let add = try duo.groupA.committing(
			Self.provider, proposals: [.proposal(.add(carol.keyPackage))],
			signingKey: duo.alice.signingKey, randomness: .generate(Self.provider))
		duo.groupA = add.group
		guard case .privateMessage(let framed) = add.commit else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}
		try duo.groupB.process(
			Self.provider, privateCommit: framed, proposals: .init(), psk: { _ in nil })

		// An empty commit forces a full UpdatePath, so the committer holds its
		// whole direct path — including a strictly-interior (non-root) parent.
		let empty = try duo.groupA.committing(
			Self.provider, proposals: [], signingKey: duo.alice.signingKey,
			randomness: .generate(Self.provider))
		duo.groupA = empty.group

		let root = MLS.TreeMath.root(leafCount: duo.groupA.tree.leafCount)
		let hasStrictInterior = duo.groupA.secretKeys.keys.contains {
			!MLS.TreeMath.isLeaf($0) && $0 != root
		}
		#expect(hasStrictInterior)
		try expectRoundTrips(duo.groupA)
	}

	/// HIGH-2 regression: the live layer does not prune `messageSecrets` on a
	/// depth decrease (only on epoch entry), so it can transiently hold an
	/// out-of-window epoch. makeSnapshot prunes to the window, keeping the
	/// snapshot restorable — a restore that saw the out-of-window epoch would
	/// throw.
	@Test("a snapshot taken after a messageSecretsDepth decrease still restores")
	func retentionDecreaseRoundTrips() throws {
		var duo = try ApplicationMessageTests.duo()
		let old = try duo.groupA.protect(
			Self.provider, applicationData: Data("old".utf8),
			signingKey: duo.alice.signingKey)
		_ = try duo.groupB.unprotect(Self.provider, message: old)
		let commit = try duo.groupA.committing(
			Self.provider, proposals: [], signingKey: duo.alice.signingKey,
			randomness: .generate(Self.provider))
		duo.groupA = commit.group
		guard case .privateMessage(let framed) = commit.commit else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}
		try duo.groupB.process(
			Self.provider, privateCommit: framed, proposals: .init(), psk: { _ in nil })
		#expect(duo.groupB.messageSecrets.count >= 2)

		let current = duo.groupB.context.epoch
		duo.groupB.retention = .init(messageSecretsDepth: 0)
		#expect(duo.groupB.messageSecrets.count >= 2)  // still unpruned in the live group

		let restored = try Group.restore(from: try duo.groupB.archive(), Self.provider)
		#expect(restored.messageSecrets.count == 1)
		#expect(restored.messageSecrets[current] != nil)
	}

	// MARK: - Field-classification guard
	//
	// Pins the secret/non-secret status of every archive field. Because
	// `SecretBytes` is not `Codable`, a genuinely-secret value can ride the
	// schema only as `@SecretField` (or a `SecretField`-valued container) — so a
	// field that SHOULD be secret but is typed plain `Data` would diverge its
	// pinned class from its reflected type here, and adding or renaming any field
	// breaks the table until it is re-classified in review. Secret-ness is read
	// structurally: the field's reflected value type names `SecretField`.

	private enum FieldClass: Equatable { case secret, plain }

	private func assertClassification<T>(_ value: T, _ expected: [String: FieldClass]) {
		var actual: [String: FieldClass] = [:]
		for child in Mirror(reflecting: value).children {
			guard let raw = child.label else { continue }
			let name = raw.hasPrefix("_") ? String(raw.dropFirst()) : raw
			let carriesSecret = String(describing: type(of: child.value)).contains(
				"SecretField")
			actual[name] = carriesSecret ? .secret : .plain
		}
		#expect(actual == expected)
	}

	@Test("every archive field's secret/non-secret classification is pinned")
	func fieldClassificationsArePinned() throws {
		let secret = SecretBytes(randomByteCount: 4)
		let secretMap = MLS.RFC9420.IntegerKeyedMap([
			UInt64(0): SecretField(wrappedValue: secret)
		])
		let publicMap = MLS.RFC9420.IntegerKeyedMap([UInt64(0): Data([0])])

		// §4.1 top level. treeSecretKeys/resumptionPsks hold secrets directly;
		// the container fields (epoch_secrets, message_secrets, retention) carry
		// their own secrets, classified in the per-struct tables below.
		let snapshot = try SelfInteropTests.createGroup(
			try SelfInteropTests.member("solo")
		).makeSnapshot()
		assertClassification(
			snapshot,
			[
				"format": .plain, "groupContext": .plain, "ratchetTree": .plain,
				"interimTranscriptHash": .plain, "myLeafIndex": .plain,
				"epochSecrets": .plain, "treeSecretKeys": .secret,
				"resumptionPsks": .secret, "messageSecrets": .plain,
				"retention": .plain, "config": .plain,
			])

		// §4.2 — epoch_authenticator is public (RFC 9420 §8.7).
		assertClassification(
			Group.EpochSecretsArchive(
				initSecret: secret, exporterSecret: secret,
				epochAuthenticator: Data([0]), membershipKey: secret),
			[
				"initSecret": .secret, "exporterSecret": .secret,
				"epochAuthenticator": .plain, "membershipKey": .secret,
			])

		// §4.3 store — group_context is public wire bytes; signature_keys are
		// PUBLIC signature keys.
		assertClassification(
			Group.MessageSecretStoreArchive(
				groupContext: Data([0]), senderDataSecret: secret,
				signatureKeys: publicMap,
				secretTree: Group.SecretTreeStateArchive(
					leafCount: 1, nodeSecrets: secretMap),
				chains: MLS.RFC9420.IntegerKeyedMap([:]),
				ownNextGeneration: Group.OwnNextGenerationArchive(
					handshake: 0, application: 0)),
			[
				"groupContext": .plain, "senderDataSecret": .secret,
				"signatureKeys": .plain, "secretTree": .plain, "chains": .plain,
				"ownNextGeneration": .plain,
			])

		assertClassification(
			Group.SecretTreeStateArchive(leafCount: 1, nodeSecrets: secretMap),
			["leafCount": .plain, "nodeSecrets": .secret])

		assertClassification(
			Group.ChainArchive(
				headGeneration: 0, headSecret: SecretField(wrappedValue: secret),
				skipped: MLS.RFC9420.IntegerKeyedMap([:])),
			["headGeneration": .plain, "headSecret": .secret, "skipped": .plain])

		// §4.3 SkippedKey — nonce is an AEAD nonce (public).
		assertClassification(
			Group.SkippedKeyArchive(key: secret, nonce: Data([0])),
			["key": .secret, "nonce": .plain])

		assertClassification(
			Group.OwnNextGenerationArchive(handshake: 0, application: 0),
			["handshake": .plain, "application": .plain])

		assertClassification(
			Group.RetentionArchive(
				resumptionPskDepth: 0, messageSecretsDepth: 0, maxForwardJump: 0,
				maxSkippedKeysPerSender: 0),
			[
				"resumptionPskDepth": .plain, "messageSecretsDepth": .plain,
				"maxForwardJump": .plain, "maxSkippedKeysPerSender": .plain,
			])
	}
}
