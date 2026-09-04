import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

/// `2^32` — the format's one-past-the-last generation. spec/snapshot.md §4.3:
/// a retired `Chain` sets `head_generation` here (`head_secret` absent), and
/// `own_next_generation` uses it as the "exhausted" sentinel. Held as a `UInt64`
/// because it does not fit the in-memory `UInt32` generation counters.
private let generationCeiling: UInt64 = 1 << 32

extension MLS.RFC9420.Group {
	// MARK: - Schema (spec/snapshot.md §4, format 1)

	/// The persisted state of one `MLS.RFC9420` group — the format-1 `Snapshot`
	/// of spec/snapshot.md, a `Codable` value with secrets carried as
	/// `@SecretField`. The API vends this type (design decision D10): a consumer
	/// either composes it into its own archive or seals the standalone
	/// `SecretArchive` from `archive()`. Sealing is out of this format's scope
	/// (spec/snapshot.md §7): the library never holds a key for its own state.
	public struct Snapshot: Codable, Sendable, Equatable {
		var format: UInt64
		var groupContext: Data
		var ratchetTree: Data
		var interimTranscriptHash: Data
		var myLeafIndex: UInt32
		var epochSecrets: EpochSecretsArchive
		var treeSecretKeys: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>
		var resumptionPsks: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>
		var messageSecrets: MLS.RFC9420.IntegerKeyedMap<MessageSecretStoreArchive>
		var retention: RetentionArchive
		/// spec/snapshot.md §4.5: format 1 defines no config keys, so this is
		/// always absent. Modeled as an optional purely so a *present* config
		/// section is decoded (and then rejected at restore) rather than
		/// silently ignored — the one §3 unknown-key rejection this build makes
		/// (the general case is the deferred §8 hostile-decode suite's).
		var config: SnapshotConfig?

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case format = 0
			case groupContext = 1
			case ratchetTree = 2
			case
				interimTranscriptHash = 3
			case myLeafIndex = 4
			case epochSecrets = 5
			case
				treeSecretKeys = 6
			case resumptionPsks = 7
			case messageSecrets = 8
			case
				retention = 9
			case config = 10
		}
	}

	/// spec/snapshot.md §4.2. `epoch_authenticator` is a plain byte string, not
	/// a `@SecretField`: it is RFC 9420 §8.7's out-of-band comparison value,
	/// non-confidential by design.
	struct EpochSecretsArchive: Codable, Sendable, Equatable {
		@SecretField var initSecret: SecretBytes
		@SecretField var exporterSecret: SecretBytes
		var epochAuthenticator: Data
		@SecretField var membershipKey: SecretBytes
		/// draft-ietf-mls-extensions-08 §4.4 Exporter Tree root — a retained
		/// per-epoch secret, persisted like `exporterSecret`. Consumption state
		/// of the tree itself is not persisted; see `Group.safeExportSecret`.
		@SecretField var applicationExportSecret: SecretBytes

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case initSecret = 0
			case exporterSecret = 1
			case epochAuthenticator = 2
			case
				membershipKey = 3
			case applicationExportSecret = 4
		}
	}

	/// spec/snapshot.md §4.3.
	struct MessageSecretStoreArchive: Codable, Sendable, Equatable {
		var groupContext: Data
		@SecretField var senderDataSecret: SecretBytes
		var signatureKeys: MLS.RFC9420.IntegerKeyedMap<Data>
		var secretTree: SecretTreeStateArchive
		var chains: MLS.RFC9420.IntegerKeyedMap<ChainArchive>
		var ownNextGeneration: OwnNextGenerationArchive

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case groupContext = 0
			case senderDataSecret = 1
			case signatureKeys = 2
			case
				secretTree = 3
			case chains = 4
			case ownNextGeneration = 5
		}
	}

	struct SecretTreeStateArchive: Codable, Sendable, Equatable {
		var leafCount: UInt32
		var nodeSecrets: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case leafCount = 0
			case nodeSecrets = 1
		}
	}

	/// spec/snapshot.md §4.3 `Chain`. `headSecret` is a *plain optional* of
	/// `SecretField`, not `@SecretField var … ?`: the wrapper's `Value` must be
	/// `SecretRestorable`, which `Optional<SecretBytes>` is not. Absent
	/// (`nil`) is the retired encoding — `head_generation` is then `2^32`.
	struct ChainArchive: Codable, Sendable, Equatable {
		var headGeneration: UInt64
		var headSecret: SecretField<SecretBytes>?
		var skipped: MLS.RFC9420.IntegerKeyedMap<SkippedKeyArchive>

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case headGeneration = 0
			case headSecret = 1
			case skipped = 2
		}
	}

	/// spec/snapshot.md §4.3 `SkippedKey`. `nonce` is plain: an AEAD nonce is
	/// not confidential (uniqueness, not secrecy, is its requirement), and the
	/// live cache holds it as `Data`.
	struct SkippedKeyArchive: Codable, Sendable, Equatable {
		@SecretField var key: SecretBytes
		var nonce: Data

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case key = 0
			case nonce = 1
		}
	}

	/// spec/snapshot.md §4.3 `own_next_generation`, a fixed two-entry integer
	/// map `{0: handshake, 1: application}`.
	struct OwnNextGenerationArchive: Codable, Sendable, Equatable {
		var handshake: UInt64
		var application: UInt64

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case handshake = 0
			case application = 1
		}
	}

	/// spec/snapshot.md §4.4. Each value < 2^32, so `UInt32` is the exact type.
	struct RetentionArchive: Codable, Sendable, Equatable {
		var resumptionPskDepth: UInt32
		var messageSecretsDepth: UInt32
		var maxForwardJump: UInt32
		var maxSkippedKeysPerSender: UInt32

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case resumptionPskDepth = 0
			case messageSecretsDepth = 1
			case
				maxForwardJump = 2
			case maxSkippedKeysPerSender = 3
		}
	}

	/// Empty by design (spec/snapshot.md §4.5). Its only job is to make a
	/// *present* config section decodable so restore can reject it.
	struct SnapshotConfig: Codable, Sendable, Equatable {}
}

// MARK: - Encode

extension MLS.RFC9420.Group {
	/// Builds the format-1 `Snapshot` of this group's current state.
	///
	/// Throws `SnapshotError.pendingUpdatesUnsupported` if the group holds an
	/// uncommitted self-proposed Update: format 1 has no `pending_updates`
	/// field, so archiving would silently drop the Update's leaf secret
	/// (runtime handoff state, not archivable). The Rust `export_for_swift()`
	/// refuses symmetrically. A Transition is not always an epoch boundary
	/// (spec/snapshot.md §6: application-message decryption is one and does not
	/// clear `pendingUpdates`), so a member holding an outstanding self-Update
	/// cannot snapshot in format 1 — a documented v1 limitation, not a silent
	/// drop.
	public func makeSnapshot() throws -> Snapshot {
		guard pendingUpdates == nil else {
			throw MLS.RFC9420.SnapshotError.pendingUpdatesUnsupported
		}

		var treeWriter = MLS.Writer()
		try treeWriter.encodeVector(try tree.nodes)

		let treeSecretKeysMap = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: self.secretKeys.map {
					(UInt64($0.key), SecretField(wrappedValue: $0.value.data))
				}))
		// Prune to the current retention window before emitting. `messageSecrets`
		// is pruned lazily by the live layer (only on epoch entry), so after a
		// `messageSecretsDepth` decrease it can transiently hold epochs outside
		// the window — which restore rejects per spec/snapshot.md §4.1 key 8.
		// Emitting the window-conformant subset realizes the retention policy the
		// caller set and keeps the snapshot self-consistent. `resumptionPsks` is
		// already window-pruned on the policy change; filtering it here is a
		// defensive no-op for uniformity. The current epoch is always ≥ floor, so
		// the never-empty / current-epoch-present invariants hold.
		let resumptionFloor = Self.retentionFloor(
			epoch: context.epoch, depth: UInt64(retention.resumptionPskDepth))
		let messageFloor = Self.retentionFloor(
			epoch: context.epoch, depth: UInt64(retention.messageSecretsDepth))
		let resumptionPsksMap = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: self.resumptionPsks
					.filter { $0.key >= resumptionFloor }
					.map {
						(
							UInt64($0.key),
							SecretField(wrappedValue: $0.value)
						)
					}))
		let messageSecretsMap = MLS.RFC9420.IntegerKeyedMap(
			try self.messageSecrets
				.filter { $0.key >= messageFloor }
				.mapValues { try Self.makeStore($0) })

		return Snapshot(
			format: 1,
			groupContext: try context.mlsEncoded(),
			ratchetTree: treeWriter.data,
			interimTranscriptHash: interimTranscriptHash,
			myLeafIndex: myLeafIndex.value,
			epochSecrets: EpochSecretsArchive(
				initSecret: epoch.initSecret, exporterSecret: epoch.exporterSecret,
				epochAuthenticator: epoch.epochAuthenticator,
				membershipKey: epoch.membershipKey,
				applicationExportSecret: epoch.applicationExportSecret),
			treeSecretKeys: treeSecretKeysMap,
			resumptionPsks: resumptionPsksMap,
			messageSecrets: messageSecretsMap,
			retention: try Self.makeRetention(retention),
			config: nil)
	}

	/// The standalone artifact convenience of D10: the `Snapshot` encoded into a
	/// `SecretArchive` held entirely in zeroizing storage. The consumer seals it
	/// (`SecretArchive.seal`) at its own boundary.
	public func archive() throws -> SecretArchive {
		try SecretArchive(encoding: makeSnapshot())
	}

	/// The oldest epoch a `depth`-bounded window retains at `epoch` (saturating
	/// at 0). Mirrors the live pruning floors (`pruneResumptionPsks`,
	/// `installMessageSecrets`) so encode, decode, and the live layer agree.
	private static func retentionFloor(epoch: UInt64, depth: UInt64) -> UInt64 {
		epoch >= depth ? epoch - depth : 0
	}

	private static func makeRetention(_ policy: RetentionPolicy) throws -> RetentionArchive {
		func field(_ value: Int, _ name: String) throws -> UInt32 {
			guard let narrowed = UInt32(exactly: value) else {
				throw MLS.RFC9420.SnapshotError.retentionValueOutOfRange(
					field: name, value: UInt64(clamping: value))
			}
			return narrowed
		}
		return RetentionArchive(
			resumptionPskDepth: try field(
				policy.resumptionPskDepth, "resumption_psk_depth"),
			messageSecretsDepth: try field(
				policy.messageSecretsDepth, "message_secrets_depth"),
			maxForwardJump: try field(policy.maxForwardJump, "max_forward_jump"),
			maxSkippedKeysPerSender: try field(
				policy.maxSkippedKeysPerSender, "max_skipped_keys_per_sender"))
	}

	private static func makeStore(_ store: MessageSecrets) throws -> MessageSecretStoreArchive {
		let signatureKeys = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: store.signatureKeys.map {
					(UInt64($0.key.value), $0.value.data)
				}))
		let nodeSecrets = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: store.tree.nodeSecrets.map {
					(UInt64($0.key), SecretField(wrappedValue: $0.value))
				}))
		let chains = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: store.chains.map {
					(packChainKey($0.key), makeChain($0.value))
				}))
		return MessageSecretStoreArchive(
			groupContext: try store.groupContext.mlsEncoded(),
			senderDataSecret: store.senderDataSecret,
			signatureKeys: signatureKeys,
			secretTree: SecretTreeStateArchive(
				leafCount: store.tree.leafCount.value, nodeSecrets: nodeSecrets),
			chains: chains,
			ownNextGeneration: OwnNextGenerationArchive(
				handshake: UInt64(store.ownNextGeneration.handshake),
				application: UInt64(store.ownNextGeneration.application)))
	}

	/// spec/snapshot.md §4.3: `key = (leaf << 1) | kind`, kind bit 0 =
	/// handshake, 1 = application.
	private static func packChainKey(_ key: MessageSecrets.ChainKey) -> UInt64 {
		(UInt64(key.leaf.value) << 1) | (key.isHandshake ? 0 : 1)
	}

	private static func makeChain(_ chain: MLS.KeySchedule.RatchetChain) -> ChainArchive {
		let skipped = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: chain.skipped.map {
					(
						UInt64($0.key),
						SkippedKeyArchive(
							key: $0.value.key, nonce: $0.value.nonce)
					)
				}))
		// spec/snapshot.md §4.3 retirement: a retired chain (no head secret)
		// encodes head_generation = 2^32 with head_secret absent. The in-memory
		// `headGeneration` has wrapped to 0 at retirement, so it is not read
		// here — `headSecret == nil` is the sole retirement signal.
		if let headSecret = chain.headSecret {
			return ChainArchive(
				headGeneration: UInt64(chain.headGeneration),
				headSecret: SecretField(wrappedValue: headSecret), skipped: skipped)
		}
		return ChainArchive(
			headGeneration: generationCeiling, headSecret: nil, skipped: skipped)
	}
}

// MARK: - Decode / restore

extension MLS.RFC9420.Group {
	/// Restores a group from a `SecretArchive` (as produced by `archive()`, or
	/// opened from a sealed blob by the consumer). `provider` must back the
	/// suite named in the snapshot's `group_context`; it is used only for the
	/// §3.1 length checks and suite match, never for a cryptographic operation
	/// at decode (spec/snapshot.md §4.1).
	public static func restore(
		from archive: SecretArchive, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Group {
		try restore(from: try archive.decode(Snapshot.self), provider)
	}

	/// Restores a group from a decoded `Snapshot`, enforcing the format-1
	/// cross-consistency MUSTs of spec/snapshot.md §4/§4.3. Every failure is a
	/// thrown `SnapshotError` (or a propagated codec/tree error), never a trap.
	public static func restore(
		from snapshot: Snapshot, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Group {
		guard snapshot.format == 1 else {
			throw MLS.RFC9420.SnapshotError.unsupportedFormat(snapshot.format)
		}
		guard snapshot.config == nil else {
			throw MLS.RFC9420.SnapshotError.unexpectedConfig
		}

		let context = try MLS.RFC9420.GroupContext(mlsEncoded: snapshot.groupContext)
		guard provider.cipherSuite == context.cipherSuite else {
			throw MLS.RFC9420.SnapshotError.cipherSuiteMismatch
		}
		let nh = provider.hashSize
		let nk = provider.aeadKeySize
		let nn = provider.aeadNonceSize

		try requireLength(
			snapshot.interimTranscriptHash.count, nh, "interim_transcript_hash")
		try requireLength(snapshot.epochSecrets.initSecret.byteCount, nh, "init_secret")
		try requireLength(
			snapshot.epochSecrets.exporterSecret.byteCount, nh, "exporter_secret")
		try requireLength(
			snapshot.epochSecrets.applicationExportSecret.byteCount, nh,
			"application_export_secret")
		try requireLength(
			snapshot.epochSecrets.epochAuthenticator.count, nh, "epoch_authenticator")
		try requireLength(
			snapshot.epochSecrets.membershipKey.byteCount, nh, "membership_key")

		var reader = MLS.Reader(snapshot.ratchetTree)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		try MLS.RFC9420.validateNoTrailingBlank(nodes)
		let tree = try MLS.TreeKEM.RatchetTree(nodes)
		try tree.validateNodeKinds()

		// A leaf index ≥ leaf_count names no leaf. Guard BEFORE `leaf(at:)`,
		// whose `2 * index` is a trapping UInt32 multiply: a decoded
		// my_leaf_index in [2^31, 2^32) would otherwise overflow and abort
		// instead of throwing (spec/snapshot.md §3/§8: decode never traps).
		guard snapshot.myLeafIndex < tree.leafCount.value else {
			throw MLS.RFC9420.SnapshotError.myLeafIndexBlank(snapshot.myLeafIndex)
		}
		let myLeafIndex = MLS.LeafIndex(value: snapshot.myLeafIndex)
		guard tree.leaf(at: myLeafIndex) != nil else {
			throw MLS.RFC9420.SnapshotError.myLeafIndexBlank(snapshot.myLeafIndex)
		}

		let epoch = MLS.RFC9420.Group.EpochSecrets(
			restoringInitSecret: snapshot.epochSecrets.initSecret,
			exporterSecret: snapshot.epochSecrets.exporterSecret,
			applicationExportSecret: snapshot.epochSecrets.applicationExportSecret,
			epochAuthenticator: snapshot.epochSecrets.epochAuthenticator,
			membershipKey: snapshot.epochSecrets.membershipKey)

		let secretKeys = try restoreTreeSecretKeys(
			snapshot.treeSecretKeys, myLeafIndex: myLeafIndex, tree: tree)

		// spec/snapshot.md §4.1 key 7: resumption_psks within the retention
		// window, never empty, current epoch always retained.
		guard !snapshot.resumptionPsks.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "resumption_psks")
		}
		let resumptionFloor = retentionFloor(
			epoch: context.epoch, depth: UInt64(snapshot.retention.resumptionPskDepth))
		var resumptionPsks: [UInt64: SecretBytes] = [:]
		for (epochKey, secret) in snapshot.resumptionPsks.entries {
			try requireLength(secret.wrappedValue.byteCount, nh, "resumption_psk")
			guard epochKey <= context.epoch, epochKey >= resumptionFloor else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"resumption_psk epoch \(epochKey) outside window "
						+ "[\(resumptionFloor), \(context.epoch)]")
			}
			resumptionPsks[epochKey] = secret.wrappedValue
		}
		guard resumptionPsks[context.epoch] != nil else {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"resumption_psks missing current epoch \(context.epoch)")
		}

		// spec/snapshot.md §4.1 key 8: message_secrets ≤ epoch, within depth,
		// never empty, current epoch always present.
		guard !snapshot.messageSecrets.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "message_secrets")
		}
		let messageFloor = retentionFloor(
			epoch: context.epoch, depth: UInt64(snapshot.retention.messageSecretsDepth))
		var messageSecrets: [UInt64: MessageSecrets] = [:]
		for (epochKey, storeArchive) in snapshot.messageSecrets.entries {
			guard epochKey <= context.epoch, epochKey >= messageFloor else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"message_secrets epoch \(epochKey) outside window "
						+ "[\(messageFloor), \(context.epoch)]")
			}
			messageSecrets[epochKey] = try restoreStore(
				storeArchive, epoch: epochKey, topLevel: context,
				topLevelContextBytes: snapshot.groupContext, nh: nh, nk: nk, nn: nn)
		}
		guard messageSecrets[context.epoch] != nil else {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"message_secrets missing current epoch \(context.epoch)")
		}

		let retention = RetentionPolicy(
			resumptionPskDepth: Int(snapshot.retention.resumptionPskDepth),
			messageSecretsDepth: Int(snapshot.retention.messageSecretsDepth),
			maxForwardJump: Int(snapshot.retention.maxForwardJump),
			maxSkippedKeysPerSender: Int(snapshot.retention.maxSkippedKeysPerSender))

		return MLS.RFC9420.Group(
			context: context, tree: tree,
			interimTranscriptHash: snapshot.interimTranscriptHash,
			myLeafIndex: myLeafIndex, epoch: epoch, retention: retention,
			secretKeys: secretKeys, resumptionPsks: resumptionPsks,
			messageSecrets: messageSecrets)
	}

	private static func requireLength(_ actual: Int, _ expected: Int, _ field: String) throws {
		guard actual == expected else {
			throw MLS.RFC9420.SnapshotError.wrongLength(
				field: field, expected: expected, actual: actual)
		}
	}

	/// spec/snapshot.md §4.1 key 6: node indices lie on the member's own direct
	/// path (own leaf included), never empty.
	private static func restoreTreeSecretKeys(
		_ map: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>,
		myLeafIndex: MLS.LeafIndex, tree: MLS.TreeKEM.RatchetTree
	) throws -> [UInt32: MLS.HpkeSecretKey] {
		guard !map.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "tree_secret_keys")
		}
		let ownLeafNode = 2 * myLeafIndex.value
		var onDirectPath: Set<UInt32> = [ownLeafNode]
		for step in MLS.TreeMath.directPath(from: ownLeafNode, leafCount: tree.leafCount) {
			onDirectPath.insert(step.path)
		}
		var secretKeys: [UInt32: MLS.HpkeSecretKey] = [:]
		for (nodeKey, secret) in map.entries {
			guard let node = UInt32(exactly: nodeKey), onDirectPath.contains(node)
			else {
				throw MLS.RFC9420.SnapshotError.treeSecretKeyOffDirectPath(
					node: UInt32(clamping: nodeKey))
			}
			// §4.1 key 6: keys MUST reference non-blank nodes.
			let occupied =
				MLS.TreeMath.isLeaf(node)
				? tree.leaf(at: MLS.LeafIndex(value: node / 2)) != nil
				: tree.parent(at: node) != nil
			guard occupied else {
				throw MLS.RFC9420.SnapshotError.treeSecretKeyOffDirectPath(
					node: node)
			}
			secretKeys[node] = try MLS.HpkeSecretKey(secret.wrappedValue)
		}
		return secretKeys
	}

	private static func restoreStore(
		_ archive: MessageSecretStoreArchive, epoch: UInt64,
		topLevel: MLS.RFC9420.GroupContext, topLevelContextBytes: Data,
		nh: Int, nk: Int, nn: Int
	) throws -> MessageSecrets {
		let storeContext = try MLS.RFC9420.GroupContext(mlsEncoded: archive.groupContext)
		// spec/snapshot.md §4.3: same suite + group_id as the top level, epoch
		// equals the map key, and the current epoch's store is byte-identical.
		guard storeContext.cipherSuite == topLevel.cipherSuite,
			storeContext.groupID == topLevel.groupID
		else {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"store \(epoch) group_context suite/group_id mismatch")
		}
		guard storeContext.epoch == epoch else {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"store map key \(epoch) != group_context.epoch \(storeContext.epoch)"
			)
		}
		if epoch == topLevel.epoch, archive.groupContext != topLevelContextBytes {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"current-epoch store group_context not byte-identical to top level")
		}

		try requireLength(archive.senderDataSecret.byteCount, nh, "sender_data_secret")
		let leafCount = try MLS.LeafCount(validating: archive.secretTree.leafCount)

		// spec/snapshot.md §4.3: signature_keys leaf < leaf_count, never empty.
		guard !archive.signatureKeys.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "signature_keys")
		}
		var signatureKeys: [MLS.LeafIndex: MLS.SignaturePublicKey] = [:]
		for (leafKey, keyBytes) in archive.signatureKeys.entries {
			guard leafKey < UInt64(leafCount.value) else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"signature_keys leaf \(leafKey) >= leaf_count \(leafCount.value)"
				)
			}
			signatureKeys[MLS.LeafIndex(value: UInt32(leafKey))] =
				MLS.SignaturePublicKey(keyBytes)
		}

		// spec/snapshot.md §4.3: node_secrets valid node indices for leaf_count.
		var nodeSecrets: [UInt32: SecretBytes] = [:]
		for (nodeKey, secret) in archive.secretTree.nodeSecrets.entries {
			try requireLength(secret.wrappedValue.byteCount, nh, "node_secret")
			guard nodeKey < 2 * UInt64(leafCount.value) - 1,
				let node = UInt32(exactly: nodeKey)
			else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"node_secrets index \(nodeKey) out of range for leaf_count "
						+ "\(leafCount.value)")
			}
			nodeSecrets[node] = secret.wrappedValue
		}
		let secretTree = MLS.KeySchedule.ConsumingSecretTree(
			restoringNodeSecrets: nodeSecrets, leafCount: leafCount)

		var chains: [MessageSecrets.ChainKey: MLS.KeySchedule.RatchetChain] = [:]
		for (packed, chainArchive) in archive.chains.entries {
			let leafValue = packed >> 1
			guard leafValue < UInt64(leafCount.value) else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"chains leaf \(leafValue) >= leaf_count \(leafCount.value)")
			}
			let chainKey = MessageSecrets.ChainKey(
				leaf: MLS.LeafIndex(value: UInt32(leafValue)),
				isHandshake: packed & 1 == 0)
			chains[chainKey] = try restoreChain(chainArchive, nh: nh, nk: nk, nn: nn)
		}

		let ownNext = try restoreOwnNextGeneration(archive.ownNextGeneration)

		return MessageSecrets(
			groupContext: storeContext, senderDataSecret: archive.senderDataSecret,
			signatureKeys: signatureKeys, tree: secretTree, chains: chains,
			ownNextGeneration: ownNext)
	}

	private static func restoreChain(
		_ archive: ChainArchive, nh: Int, nk: Int, nn: Int
	) throws -> MLS.KeySchedule.RatchetChain {
		// spec/snapshot.md §4.3: skipped keys MUST be < head_generation. This
		// runs on the on-wire UInt64 head_generation (2^32 for a retired chain)
		// BEFORE it is narrowed to the in-memory UInt32 — checking against the
		// narrowed value would reject every retired chain that carries skipped
		// keys, which is a retired chain's entire purpose.
		var skipped: [UInt32: (key: SecretBytes, nonce: Data)] = [:]
		for (generation, skippedKey) in archive.skipped.entries {
			guard generation < archive.headGeneration else {
				throw MLS.RFC9420.SnapshotError.skippedGenerationNotBelowHead(
					generation: generation,
					headGeneration: archive.headGeneration)
			}
			guard let narrowed = UInt32(exactly: generation) else {
				throw MLS.RFC9420.SnapshotError.skippedGenerationNotBelowHead(
					generation: generation,
					headGeneration: archive.headGeneration)
			}
			try requireLength(skippedKey.key.byteCount, nk, "skipped.key")
			try requireLength(skippedKey.nonce.count, nn, "skipped.nonce")
			skipped[narrowed] = (key: skippedKey.key, nonce: skippedKey.nonce)
		}

		if let headSecret = archive.headSecret {
			guard archive.headGeneration < generationCeiling else {
				throw MLS.RFC9420.SnapshotError.malformedChainRetirement(
					headGeneration: archive.headGeneration,
					headSecretPresent: true)
			}
			try requireLength(headSecret.wrappedValue.byteCount, nh, "head_secret")
			return MLS.KeySchedule.RatchetChain(
				headGeneration: UInt32(archive.headGeneration),
				headSecret: headSecret.wrappedValue, skipped: skipped)
		}
		// Retired: head_secret absent ⟹ head_generation MUST be 2^32; the
		// in-memory head_generation is 0 (the wrapped `.max &+ 1`).
		guard archive.headGeneration == generationCeiling else {
			throw MLS.RFC9420.SnapshotError.malformedChainRetirement(
				headGeneration: archive.headGeneration, headSecretPresent: false)
		}
		return MLS.KeySchedule.RatchetChain(
			headGeneration: 0, headSecret: nil, skipped: skipped)
	}

	private static func restoreOwnNextGeneration(
		_ archive: OwnNextGenerationArchive
	) throws -> (handshake: UInt32, application: UInt32) {
		// spec/snapshot.md §4.3: own_next_generation ≤ 2^32, where 2^32 means
		// "exhausted". This build's counters are UInt32 and never reach 2^32
		// (the send guard caps at UInt32.max - 1), so 2^32 has no home here — a
		// peer emitting it cannot be restored. Self-produced archives never do.
		func narrow(_ value: UInt64) throws -> UInt32 {
			guard let narrowed = UInt32(exactly: value) else {
				throw MLS.RFC9420.SnapshotError.ownGenerationUnrepresentable(
					handshake: archive.handshake,
					application: archive.application)
			}
			return narrowed
		}
		return (
			handshake: try narrow(archive.handshake),
			application: try narrow(archive.application)
		)
	}
}
