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
	// MARK: - Schema (spec/snapshot.md §4)

	/// The persisted state of one `MLS.RFC9420` group — the `Snapshot` archive
	/// (spec/snapshot.md documents format 1; this is format 2, folded into the
	/// spec by the migration slice), a `Codable` value with secrets carried as
	/// `@SecretField`. The API vends this type (design decision D10): a consumer
	/// either composes it into its own archive or seals the standalone
	/// `SecretArchive` from `archive()`. Sealing is out of this format's scope
	/// (spec/snapshot.md §7): the library never holds a key for its own state.
	///
	/// **Format 2** (D18, the client-aware shape): a client-agnostic `core` plus
	/// one `MembershipArchive` per local membership, keyed by leaf index — each
	/// with its own tree-path secret keys and pending self-Update. `makeSnapshot`
	/// always emits format 2. Format 1 (the flat, single-membership
	/// `SnapshotFormat1`) is retained **decode-only**, for archives produced
	/// before the split — chiefly the deployed `export_for_swift()` migration
	/// source (#49); a format-1 archive restores to a group with exactly one
	/// membership and, having no `pending_updates` field, never an outstanding
	/// self-Update.
	public struct Snapshot: Codable, Sendable, Equatable {
		var format: UInt64
		var core: CoreArchive
		/// One entry per local membership, keyed by leaf index (membership
		/// identity, D18). Never empty — a group with no local membership is not a
		/// thing a client holds; restore rejects an empty map and the composite
		/// `init(core:memberships:)` has a matching precondition.
		var memberships: MLS.RFC9420.IntegerKeyedMap<MembershipArchive>

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case format = 0
			case core = 1
			case memberships = 2
		}
	}

	/// The client-agnostic half of the schema (D18 / `GroupCore`): every field
	/// identical across a group's local memberships. Coding keys are its own,
	/// independent of `SnapshotFormat1`'s flat numbering.
	struct CoreArchive: Codable, Sendable, Equatable {
		var groupContext: Data
		var ratchetTree: Data
		var interimTranscriptHash: Data
		var epochSecrets: EpochSecretsArchive
		var resumptionPsks: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>
		var messageSecrets: MLS.RFC9420.IntegerKeyedMap<MessageSecretStoreArchive>
		var retention: RetentionArchive
		/// spec/snapshot.md §4.5 defines no config keys for format 1, and format 2
		/// carries none either, so this is always absent. Modeled as an optional
		/// purely so a *present* config section is decoded (and then rejected at
		/// restore) rather than silently ignored.
		var config: SnapshotConfig?
		/// draft-ietf-mls-extensions-08 §4.4 Exporter Tree (`spec/snapshot.md`
		/// §4.6): the current epoch's *consuming* tree persisted as its surviving
		/// node-secret frontier — never the `application_export_secret` root, so a
		/// component consumed before archiving stays unrecoverable (RFC 9420 §9.2
		/// forward secrecy). Reuses `SecretTreeStateArchive`; its `leafCount` is
		/// always 2^16. Absent only in a migration source predating the exporter
		/// tree (see restore) — then the group has none and `safeExportSecret`
		/// throws until it advances an epoch (FS-safe: nothing re-derivable).
		var exporterTree: SecretTreeStateArchive?

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case groupContext = 0
			case ratchetTree = 1
			case interimTranscriptHash = 2
			case epochSecrets = 3
			case resumptionPsks = 4
			case messageSecrets = 5
			case retention = 6
			case config = 7
			case exporterTree = 8
		}
	}

	/// One local membership's per-client state (D18 / `Membership`): its HPKE
	/// secret keys along its own direct path, and its pending self-Update. The
	/// leaf index is the map key in `Snapshot.memberships`, so it is not repeated
	/// here.
	///
	/// `pendingUpdate` is the set of proposed new leaf key pairs directly (a set —
	/// the committer, not the proposer, picks which lands), keyed by dense index
	/// `0..<count`. The epoch and own-leaf node the live tuple also carries are
	/// NOT stored: both are derivable at restore — the epoch is the current epoch
	/// (a pending Update is cleared on every advance, so it is only ever valid for
	/// `group_context.epoch`), and the node is `2 · leaf`. Absent when none is
	/// outstanding; never empty when present.
	struct MembershipArchive: Codable, Sendable, Equatable {
		var treeSecretKeys: MLS.RFC9420.IntegerKeyedMap<SecretField<SecretBytes>>
		var pendingUpdate: MLS.RFC9420.IntegerKeyedMap<PendingUpdateEntryArchive>?

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case treeSecretKeys = 0
			case pendingUpdate = 1
		}
	}

	/// One proposed new leaf key pair in a membership's pending self-Update. The
	/// public key is opaque wire bytes; the secret is the proposed leaf HPKE
	/// private key.
	struct PendingUpdateEntryArchive: Codable, Sendable, Equatable {
		var publicKey: Data
		@SecretField var secret: SecretBytes

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case publicKey = 0
			case secret = 1
		}
	}

	/// Reads just the `format` field so `restore(from archive:)` can dispatch to
	/// the matching decode without first committing to a struct shape. `format`
	/// is key 0, so under spec/snapshot.md §3's strictly-increasing-keys rule it
	/// is always the FIRST entry of the top-level map: the §5 dispatch is "read
	/// the first entry, select the schema, then decode the whole item strictly
	/// under it." This probe is the "read the first entry" step. When §8's
	/// hostile-decode strictness lands (which makes any unknown map key an
	/// error), this becomes a below-struct peek of that first entry rather than a
	/// struct decode — no exemption from the strictness, because it never decodes
	/// the rest of the map.
	struct FormatProbe: Decodable {
		var format: UInt64
		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case format = 0
		}
	}

	/// The flat, single-membership **format 1** schema, retained decode-only
	/// (spec/snapshot.md §4, format 1). `makeSnapshot` no longer emits it; it is
	/// the shape of archives produced before the D18 client-aware split, chiefly
	/// the deployed `export_for_swift()` migration source (#49). A format-1
	/// archive restores to a group with exactly one membership (its `myLeafIndex`
	/// / `treeSecretKeys`) and — having no `pending_updates` field — never one
	/// with an outstanding self-Update.
	struct SnapshotFormat1: Codable, Sendable, Equatable {
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
		var config: SnapshotConfig?
		var exporterTree: SecretTreeStateArchive?

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case format = 0
			case groupContext = 1
			case ratchetTree = 2
			case interimTranscriptHash = 3
			case myLeafIndex = 4
			case epochSecrets = 5
			case treeSecretKeys = 6
			case resumptionPsks = 7
			case messageSecrets = 8
			case retention = 9
			case config = 10
			case exporterTree = 11
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

		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case initSecret = 0
			case exporterSecret = 1
			case epochAuthenticator = 2
			case
				membershipKey = 3
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
	/// Builds the format-2 `Snapshot` of this group's current state (D18): a
	/// client-agnostic `core` plus one entry per local membership, keyed by leaf
	/// index. Unlike format 1, it persists *every* local membership and each
	/// membership's pending self-Update, so neither N > 1 nor an outstanding
	/// self-Update is refused — the format-1 `multipleMembershipsUnsupported` /
	/// `pendingUpdatesUnsupported` guards are gone.
	public func makeSnapshot() throws -> Snapshot {
		var treeWriter = MLS.Writer()
		try treeWriter.encodeVector(try tree.nodes)

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

		// The current epoch's Exporter Tree, persisted as its surviving frontier
		// (never the root) — installed on every epoch-entry path, so present here.
		guard let currentExporterTree = exporterTrees[context.epoch] else {
			throw MLS.RFC9420.GroupError.exporterTreeUnavailable
		}
		let exporterTreeArchive = SecretTreeStateArchive(
			leafCount: MLS.KeySchedule.ExporterTree.leafCount.value,
			nodeSecrets: MLS.RFC9420.IntegerKeyedMap(
				Dictionary(
					uniqueKeysWithValues: currentExporterTree.frontier.map {
						(
							UInt64($0.key),
							SecretField(wrappedValue: $0.value)
						)
					})))

		let core = CoreArchive(
			groupContext: try context.mlsEncoded(),
			ratchetTree: treeWriter.data,
			interimTranscriptHash: interimTranscriptHash,
			epochSecrets: EpochSecretsArchive(
				initSecret: epoch.initSecret, exporterSecret: epoch.exporterSecret,
				epochAuthenticator: epoch.epochAuthenticator,
				membershipKey: epoch.membershipKey),
			resumptionPsks: resumptionPsksMap,
			messageSecrets: messageSecretsMap,
			retention: try Self.makeRetention(retention),
			config: nil,
			exporterTree: exporterTreeArchive)

		// One entry per local membership, keyed by leaf index (membership
		// identity). `uniqueKeysWithValues` would trap on a duplicate leaf, which
		// the composite invariant forbids (a live `Group` never holds two
		// memberships on one leaf).
		let membershipsMap = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: memberships.map {
					(UInt64($0.leafIndex.value), Self.makeMembershipArchive($0))
				}))

		return Snapshot(format: 2, core: core, memberships: membershipsMap)
	}

	/// One membership's per-client archive: its tree-path secret keys and its
	/// pending self-Update (index-keyed entries, absent when none is outstanding).
	private static func makeMembershipArchive(
		_ membership: MLS.RFC9420.Membership
	) -> MembershipArchive {
		let treeSecretKeysMap = MLS.RFC9420.IntegerKeyedMap(
			Dictionary(
				uniqueKeysWithValues: membership.secretKeys.map {
					(UInt64($0.key), SecretField(wrappedValue: $0.value.data))
				}))
		// The proposed key pairs directly, keyed by dense index. epoch and node
		// are not stored (derived at restore). An empty set is emitted as absent,
		// not an empty map (never-empty-when-present); the library never produces
		// one anyway (`proposeUpdate` only appends).
		let pendingArchive = membership.pendingUpdate.flatMap {
			pending -> MLS.RFC9420.IntegerKeyedMap<PendingUpdateEntryArchive>? in
			pending.updates.isEmpty
				? nil
				: MLS.RFC9420.IntegerKeyedMap(
					Dictionary(
						uniqueKeysWithValues: pending.updates.enumerated()
							.map {
								(
									UInt64($0.offset),
									PendingUpdateEntryArchive(
										publicKey: $0
											.element
											.publicKey
											.data,
										secret: $0.element
											.secret.data
									)
								)
							}))
		}
		return MembershipArchive(
			treeSecretKeys: treeSecretKeysMap, pendingUpdate: pendingArchive)
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
		// Dispatch on `format` without first committing to a struct shape — the
		// two formats share only key 0. spec/snapshot.md §5: an unknown format is
		// a decode error, never a silent reinterpretation.
		let format = try archive.decode(FormatProbe.self).format
		switch format {
		case 1:
			return try restoreFormat1(
				try archive.decode(SnapshotFormat1.self), provider)
		case 2:
			return try restore(from: try archive.decode(Snapshot.self), provider)
		default:
			throw MLS.RFC9420.SnapshotError.unsupportedFormat(format)
		}
	}

	/// Restores a group from a decoded **format 2** `Snapshot` (D18): validates
	/// the core section (spec/snapshot.md §4.1/§4.3 cross-consistency MUSTs) and
	/// each membership, then composes them. Every failure is a thrown
	/// `SnapshotError` (or a propagated codec/tree error), never a trap.
	public static func restore(
		from snapshot: Snapshot, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Group {
		guard snapshot.format == 2 else {
			throw MLS.RFC9420.SnapshotError.unsupportedFormat(snapshot.format)
		}
		let (core, tree, context) = try restoreCore(snapshot.core, provider)

		// D18: at least one membership (the format-2 schema is written into
		// spec/snapshot.md by the migration slice). The composite
		// `init(core:memberships:)` has a matching precondition, but that guards a
		// library invariant — a decoded archive is wire-reachable, so an empty
		// map throws rather than trapping.
		guard !snapshot.memberships.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "memberships")
		}
		// Ascending by leaf index: `memberships[0]` (which the sole-membership
		// accessors and `unprotect`'s own-message check read) MUST be
		// deterministic, and `Dictionary` iteration order is not.
		var memberships: [MLS.RFC9420.Membership] = []
		for leafKey in snapshot.memberships.entries.keys.sorted() {
			memberships.append(
				try restoreMembership(
					leafKey: leafKey,
					archive: snapshot.memberships.entries[leafKey]!,
					tree: tree, currentEpoch: context.epoch))
		}
		return MLS.RFC9420.Group(core: core, memberships: memberships)
	}

	/// Restores a group from a decoded **format 1** archive (the flat,
	/// single-membership legacy shape, decode-only). Maps the flat client fields
	/// (`my_leaf_index`, `tree_secret_keys`) to the group's one membership, with
	/// no pending self-Update (format 1 has no such field).
	private static func restoreFormat1(
		_ snapshot: SnapshotFormat1, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Group {
		let (core, tree, context) = try restoreCore(
			CoreArchive(
				groupContext: snapshot.groupContext,
				ratchetTree: snapshot.ratchetTree,
				interimTranscriptHash: snapshot.interimTranscriptHash,
				epochSecrets: snapshot.epochSecrets,
				resumptionPsks: snapshot.resumptionPsks,
				messageSecrets: snapshot.messageSecrets,
				retention: snapshot.retention,
				config: snapshot.config, exporterTree: snapshot.exporterTree),
			provider)
		let membership = try restoreMembership(
			leafKey: UInt64(snapshot.myLeafIndex),
			archive: MembershipArchive(
				treeSecretKeys: snapshot.treeSecretKeys, pendingUpdate: nil),
			tree: tree, currentEpoch: context.epoch)
		return MLS.RFC9420.Group(core: core, memberships: [membership])
	}

	/// The client-agnostic restore shared by both formats: validates the core
	/// section (spec/snapshot.md §4.1/§4.3) and builds the `GroupCore`, returning
	/// the ratchet tree and context the per-membership restore needs (to validate
	/// leaves, and to check a pending Update names the current epoch).
	private static func restoreCore(
		_ core: CoreArchive, _ provider: any MLS.CipherSuiteProvider
	) throws -> (
		core: MLS.RFC9420.GroupCore, tree: MLS.TreeKEM.RatchetTree,
		context: MLS.RFC9420.GroupContext
	) {
		guard core.config == nil else {
			throw MLS.RFC9420.SnapshotError.unexpectedConfig
		}

		let context = try MLS.RFC9420.GroupContext(mlsEncoded: core.groupContext)
		guard provider.cipherSuite == context.cipherSuite else {
			throw MLS.RFC9420.SnapshotError.cipherSuiteMismatch
		}
		let nh = provider.hashSize
		let nk = provider.aeadKeySize
		let nn = provider.aeadNonceSize

		try requireLength(
			core.interimTranscriptHash.count, nh, "interim_transcript_hash")
		try requireLength(core.epochSecrets.initSecret.byteCount, nh, "init_secret")
		try requireLength(
			core.epochSecrets.exporterSecret.byteCount, nh, "exporter_secret")
		try requireLength(
			core.epochSecrets.epochAuthenticator.count, nh, "epoch_authenticator")
		try requireLength(
			core.epochSecrets.membershipKey.byteCount, nh, "membership_key")

		var reader = MLS.Reader(core.ratchetTree)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		try MLS.RFC9420.validateNoTrailingBlank(nodes)
		let tree = try MLS.TreeKEM.RatchetTree(nodes)
		try tree.validateNodeKinds()

		let epoch = MLS.RFC9420.Group.EpochSecrets(
			restoringInitSecret: core.epochSecrets.initSecret,
			exporterSecret: core.epochSecrets.exporterSecret,
			epochAuthenticator: core.epochSecrets.epochAuthenticator,
			membershipKey: core.epochSecrets.membershipKey)

		// spec/snapshot.md §4.1 key 7: resumption_psks within the retention
		// window, never empty, current epoch always retained.
		guard !core.resumptionPsks.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "resumption_psks")
		}
		let resumptionFloor = retentionFloor(
			epoch: context.epoch, depth: UInt64(core.retention.resumptionPskDepth))
		var resumptionPsks: [UInt64: SecretBytes] = [:]
		for (epochKey, secret) in core.resumptionPsks.entries {
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
		guard !core.messageSecrets.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "message_secrets")
		}
		let messageFloor = retentionFloor(
			epoch: context.epoch, depth: UInt64(core.retention.messageSecretsDepth))
		var messageSecrets: [UInt64: MessageSecrets] = [:]
		for (epochKey, storeArchive) in core.messageSecrets.entries {
			guard epochKey <= context.epoch, epochKey >= messageFloor else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"message_secrets epoch \(epochKey) outside window "
						+ "[\(messageFloor), \(context.epoch)]")
			}
			messageSecrets[epochKey] = try restoreStore(
				storeArchive, epoch: epochKey, topLevel: context,
				topLevelContextBytes: core.groupContext, nh: nh, nk: nk, nn: nn)
		}
		guard messageSecrets[context.epoch] != nil else {
			throw MLS.RFC9420.SnapshotError.inconsistentStore(
				"message_secrets missing current epoch \(context.epoch)")
		}

		let retention = RetentionPolicy(
			resumptionPskDepth: Int(core.retention.resumptionPskDepth),
			messageSecretsDepth: Int(core.retention.messageSecretsDepth),
			maxForwardJump: Int(core.retention.maxForwardJump),
			maxSkippedKeysPerSender: Int(core.retention.maxSkippedKeysPerSender))

		var groupCore = MLS.RFC9420.GroupCore(
			context: context, tree: tree,
			interimTranscriptHash: core.interimTranscriptHash,
			epoch: epoch, retention: retention,
			resumptionPsks: resumptionPsks, messageSecrets: messageSecrets)

		// spec/snapshot.md §4.6: rebuild the current epoch's Exporter Tree from its
		// persisted frontier (never a root), so consumed-component deletions
		// survive the round-trip — FS holds across restore, unlike a root rebuild.
		// Absent only in a migration source that predates the exporter tree; then
		// the group has none and `safeExportSecret` throws until it advances an
		// epoch and installs one (FS-safe — nothing is re-derivable meanwhile).
		if let exporterTreeArchive = core.exporterTree {
			guard
				exporterTreeArchive.leafCount
					== MLS.KeySchedule.ExporterTree.leafCount.value
			else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"exporter_tree leaf_count \(exporterTreeArchive.leafCount) is not 2^16"
				)
			}
			let exporterNodeBound = 2 * MLS.KeySchedule.ExporterTree.leafCount.value - 1
			var exporterFrontier: [UInt32: SecretBytes] = [:]
			for (node, secret) in exporterTreeArchive.nodeSecrets.entries {
				try requireLength(
					secret.wrappedValue.byteCount, nh,
					"exporter_tree node_secret")
				guard node < UInt64(exporterNodeBound) else {
					throw MLS.RFC9420.SnapshotError.inconsistentStore(
						"exporter_tree node index \(node) outside a 2^16-leaf tree"
					)
				}
				exporterFrontier[UInt32(node)] = secret.wrappedValue
			}
			groupCore.exporterTrees = [
				context.epoch: MLS.KeySchedule.ExporterTree(
					restoringFrontier: exporterFrontier)
			]
		}
		return (groupCore, tree, context)
	}

	/// Restores one membership from its archive (spec/snapshot.md §4.1 keys 4/6,
	/// plus format 2's per-membership pending self-Update): validates the leaf is
	/// a non-blank member, restores its direct-path secret keys, and rebuilds any
	/// pending self-Update. `leafKey` is the map key (format 2) or `my_leaf_index`
	/// (format 1).
	private static func restoreMembership(
		leafKey: UInt64, archive: MembershipArchive, tree: MLS.TreeKEM.RatchetTree,
		currentEpoch: UInt64
	) throws -> MLS.RFC9420.Membership {
		// A leaf index ≥ leaf_count (or ≥ 2^32) names no leaf. Guard BEFORE
		// `leaf(at:)`, whose `2 * index` is a trapping UInt32 multiply
		// (spec/snapshot.md §3/§8: decode never traps).
		guard leafKey < UInt64(tree.leafCount.value) else {
			throw MLS.RFC9420.SnapshotError.myLeafIndexBlank(UInt32(clamping: leafKey))
		}
		let leafIndex = MLS.LeafIndex(value: UInt32(leafKey))
		guard tree.leaf(at: leafIndex) != nil else {
			throw MLS.RFC9420.SnapshotError.myLeafIndexBlank(leafIndex.value)
		}
		let secretKeys = try restoreTreeSecretKeys(
			archive.treeSecretKeys, myLeafIndex: leafIndex, tree: tree)
		let pendingUpdate = try archive.pendingUpdate.map {
			try restorePendingUpdate(
				$0, leafIndex: leafIndex, currentEpoch: currentEpoch)
		}
		return MLS.RFC9420.Membership(
			leafIndex: leafIndex, secretKeys: secretKeys, pendingUpdate: pendingUpdate)
	}

	/// Rebuilds a membership's pending self-Update from its persisted update set
	/// (format 2). The set MUST be non-empty and its keys dense `0..<count` (the
	/// one-wire-form MUST — index is positional, so a sparse or out-of-range key
	/// is malformed). The epoch and own-leaf node are not stored: they are the
	/// current epoch (a pending Update is cleared on every advance, so it is only
	/// valid for `group_context.epoch`) and `2 · leaf`. The public key is opaque
	/// wire bytes; the secret is validated non-empty by `HpkeSecretKey`.
	private static func restorePendingUpdate(
		_ map: MLS.RFC9420.IntegerKeyedMap<PendingUpdateEntryArchive>,
		leafIndex: MLS.LeafIndex, currentEpoch: UInt64
	) throws -> (
		epoch: UInt64, node: UInt32,
		updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
	) {
		guard !map.entries.isEmpty else {
			throw MLS.RFC9420.SnapshotError.unexpectedlyEmpty(field: "pending_update")
		}
		var updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)] = []
		for index in map.entries.keys.sorted() {
			guard index == UInt64(updates.count) else {
				throw MLS.RFC9420.SnapshotError.inconsistentStore(
					"pending_update keys are not dense 0..<count (index \(index))"
				)
			}
			let entry = map.entries[index]!
			updates.append(
				(
					publicKey: MLS.HpkePublicKey(entry.publicKey),
					secret: try MLS.HpkeSecretKey(entry.secret)
				))
		}
		return (epoch: currentEpoch, node: 2 * leafIndex.value, updates: updates)
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
