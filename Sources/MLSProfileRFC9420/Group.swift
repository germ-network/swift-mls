import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

extension MLS.RFC9420 {
	/// A member's view of one RFC 9420 group: the tree, the current
	/// `GroupContext`, and everything needed to process the next Welcome
	/// or Commit. Value type, no actors or shared mutable state — the app
	/// owns storage, this owns nothing but its own fields.
	public struct Group: Sendable {
		/// The client-agnostic group state (context, tree, transcript, epoch
		/// secrets, PSKs, receive-side message-secret state, exporter tree) —
		/// shared by every local membership (D18).
		public internal(set) var core: GroupCore

		/// The local memberships — one per client this device occupies in the
		/// group, at least one (see `init(core:memberships:)`), ordered ascending
		/// by leaf index on restore. The common case is exactly one. Every path is
		/// N > 1-capable: the client-agnostic `core` and application receive
		/// (`unprotect`, which touches only `core`); the membership-scoped sends
		/// (`protect(as:)` / `proposingUpdate(as:)` / `committing(as:)`, each on its
		/// own membership — slices 3b/4a); commit receive (`validating`, which
		/// decaps the path once per membership and installs each — slice 4a); and
		/// format-2 persistence (which stores every membership). The bare
		/// (non-`as:`) send entries are `ambiguousMembership` at N ≠ 1, since they
		/// cannot pick a membership. N > 1 arises today only from a format-2 restore
		/// (there is no op to add a second local membership to a live group).
		/// **Eviction** is per-membership (slice 4b): a commit removing one local
		/// membership but not others drops just that one and advances the rest;
		/// removing every local membership is a terminal full eviction.
		public internal(set) var memberships: [Membership]

		/// The sole local membership, when there is exactly one (the common
		/// case). `nil` at N != 1 — use the membership-scoped API there.
		public var soleMembership: Membership? {
			memberships.count == 1 ? memberships[0] : nil
		}

		// The pre-D18 flat surface, preserved by delegation so every existing
		// method body, caller, and test is unchanged (D18/1a). Group-agnostic
		// fields read/write `core`; the per-client fields read/write the sole
		// membership — a documented N = 1 precondition, the scoped API being the
		// N > 1 path.
		public internal(set) var context: GroupContext {
			get { core.context }
			set { core.context = newValue }
		}
		public internal(set) var tree: MLS.TreeKEM.RatchetTree {
			get { core.tree }
			set { core.tree = newValue }
		}
		public internal(set) var interimTranscriptHash: Data {
			get { core.interimTranscriptHash }
			set { core.interimTranscriptHash = newValue }
		}
		public internal(set) var epoch: EpochSecrets {
			get { core.epoch }
			set { core.epoch = newValue }
		}
		/// See `RetentionPolicy`. Lowering it prunes immediately (via `core`'s
		/// own `didSet`), not at the next commit.
		public var retention: RetentionPolicy {
			get { core.retention }
			set { core.retention = newValue }
		}
		var resumptionPsks: [UInt64: SecretBytes] {
			get { core.resumptionPsks }
			set { core.resumptionPsks = newValue }
		}
		var messageSecrets: [UInt64: MessageSecrets] {
			get { core.messageSecrets }
			set { core.messageSecrets = newValue }
		}
		var exporterTrees: [UInt64: MLS.KeySchedule.ExporterTree] {
			get { core.exporterTrees }
			set { core.exporterTrees = newValue }
		}

		/// This client's leaf. A sole-membership convenience (N = 1 precondition).
		public internal(set) var myLeafIndex: MLS.LeafIndex {
			get { memberships[0].leafIndex }
			set { memberships[0].leafIndex = newValue }
		}
		var secretKeys: [UInt32: MLS.HpkeSecretKey] {
			get { memberships[0].secretKeys }
			set { memberships[0].secretKeys = newValue }
		}
		var pendingUpdates:
			(
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)?
		{
			get { memberships[0].pendingUpdate }
			set { memberships[0].pendingUpdate = newValue }
		}

		mutating func pruneResumptionPsks(currentEpoch: UInt64) {
			core.pruneResumptionPsks(currentEpoch: currentEpoch)
		}

		init(core: GroupCore, memberships: [Membership]) {
			// A live `Group` always holds at least one local membership (D18): the
			// sole-membership accessors index `memberships[0]`, and the terminal
			// apply of an eviction marks the group ended without shrinking to zero.
			// This is an internal invariant — every caller is in-library — so a
			// violation is a library bug (a trap), not a wire-reachable input;
			// format-2 restore rejects an empty `memberships` map with a thrown
			// `SnapshotError` before it reaches here.
			precondition(
				!memberships.isEmpty, "a Group must hold at least one Membership")
			// Leaf index is a membership's identity (D18): duplicates would make the
			// per-membership key install (slice 4a) last-write-wins into one map
			// entry, stranding a membership. Also a library invariant — format-2
			// restore keys memberships by leaf in an `IntegerKeyedMap`, so it cannot
			// produce a duplicate; only in-library construction could.
			precondition(
				Set(memberships.map(\.leafIndex)).count == memberships.count,
				"a Group's memberships must have distinct leaf indices")
			self.core = core
			self.memberships = memberships
		}

		/// Compatibility memberwise initializer (the pre-D18 shape) — builds a
		/// `core` and a single `Membership`, so `create`/`join`/`restore` need no
		/// change.
		init(
			context: GroupContext, tree: MLS.TreeKEM.RatchetTree,
			interimTranscriptHash: Data, myLeafIndex: MLS.LeafIndex,
			epoch: EpochSecrets, retention: RetentionPolicy = RetentionPolicy(),
			secretKeys: [UInt32: MLS.HpkeSecretKey],
			resumptionPsks: [UInt64: SecretBytes],
			messageSecrets: [UInt64: MessageSecrets] = [:],
			exporterTrees: [UInt64: MLS.KeySchedule.ExporterTree] = [:],
			pendingUpdates: (
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)? = nil
		) {
			self.core = GroupCore(
				context: context, tree: tree,
				interimTranscriptHash: interimTranscriptHash, epoch: epoch,
				retention: retention, resumptionPsks: resumptionPsks,
				messageSecrets: messageSecrets, exporterTrees: exporterTrees)
			self.memberships = [
				Membership(
					leafIndex: myLeafIndex, secretKeys: secretKeys,
					pendingUpdate: pendingUpdates)
			]
		}
	}
}

extension MLS.RFC9420.Group {
	/// The joiner's own key material — never carried on the wire, always
	/// supplied by the caller from wherever it stores its own KeyPackage's
	/// private halves.
	public struct JoinerCredentials: Sendable {
		public var keyPackage: MLS.RFC9420.KeyPackage
		public var initKey: MLS.HpkeSecretKey
		/// The leaf HPKE secret key.
		public var encryptionKey: MLS.HpkeSecretKey

		public init(
			keyPackage: MLS.RFC9420.KeyPackage, initKey: MLS.HpkeSecretKey,
			encryptionKey: MLS.HpkeSecretKey
		) {
			self.keyPackage = keyPackage
			self.initKey = initKey
			self.encryptionKey = encryptionKey
		}
	}

	/// Every non-blank leaf's own signature (RFC 9420 §7.3's authenticity
	/// half), plus §7.3's last bullet: "Verify that the following fields
	/// are unique among the members of the group: signature_key,
	/// encryption_key."
	///
	/// The `encryption_key` half is `validateNoDuplicateEncryptionKeys`,
	/// which is deliberately whole-tree (broader than this bullet, per its
	/// own doc comment). The `signature_key` half can only live here: it is
	/// scoped to *members*, and `MLSTreeKEM`'s `LeafRecord` projection
	/// carries no signature key at all — reading one means decoding a
	/// `LeafNode`, which is this profile's job. Folded into the loop that
	/// already decodes every leaf for its signature, so it costs no extra
	/// decode pass.
	///
	/// Split out of `join` rather than inlined **so it can be tested at
	/// all**. Through `join` this check is unreachable: every leaf mutation
	/// available to a test also perturbs the subtree hashes that parent
	/// nodes' stored `parent_hash` values were computed over, so
	/// `validateParentHashChain` rejects the tree first. Two successive
	/// attempts at a black-box test passed with this check deleted before
	/// that was traced — the check is real, the black-box route to it is
	/// not.
	/// Returns the verified roster — one `RosterEntry` per non-blank leaf,
	/// each's signature and §7.3 policy already checked — so `joining` reports
	/// exactly the leaves this pass validated, in one decode pass (slice 4c). The
	/// `create` caller discards it.
	@discardableResult
	static func validateLeaves(
		_ tree: MLS.TreeKEM.RatchetTree, groupID: Data,
		groupExtensions: [MLS.RFC9420.Extension],
		_ provider: any MLS.CipherSuiteProvider
	) throws -> [MLS.RFC9420.RosterEntry] {
		let groupRequirements = try groupExtensions.requiredCapabilities()

		// Decode every leaf once; the mutual-credential-support check is
		// pairwise over the whole membership, so the collections must be
		// complete before any leaf is judged.
		var leaves: [(MLS.LeafIndex, MLS.RFC9420.LeafNode)] = []
		var memberCapabilities: [MLS.RFC9420.Capabilities] = []
		var memberCredentialTypes: Set<MLS.RFC9420.CredentialType> = []
		for (leafIndex, record) in tree.nonBlankLeaves() {
			let leafNode = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			leaves.append((leafIndex, leafNode))
			memberCapabilities.append(leafNode.capabilities)
			memberCredentialTypes.insert(leafNode.credential.credentialType)
		}

		var seenSignatureKeys: Set<MLS.SignaturePublicKey> = []
		var roster: [MLS.RFC9420.RosterEntry] = []
		for (leafIndex, leafNode) in leaves {
			try leafNode.verifySignature(
				provider,
				placement: .inGroup(groupID: groupID, leafIndex: leafIndex))
			// §7.3's policy half, ending the deferral phase 5 documented.
			// `.treeWalk` because a joiner legitimately meets all three
			// sources; no `currentTime` because the receive-side lifetime
			// check is RECOMMENDED-not-mandatory and hundreds of official
			// vector leaves are already expired.
			try leafNode.validatePolicy(
				.treeWalk,
				groupRequirements: groupRequirements,
				memberCredentialTypes: memberCredentialTypes,
				memberCapabilities: memberCapabilities)
			guard seenSignatureKeys.insert(leafNode.signatureKey).inserted else {
				throw MLS.RFC9420.GroupError.duplicateSignatureKey(leaf: leafIndex)
			}
			// Verified-by-construction: this entry's signature was just checked.
			roster.append(
				MLS.RFC9420.RosterEntry(
					leaf: leafIndex,
					presentation: MLS.RFC9420.CredentialPresentation(
						credential: leafNode.credential,
						signatureKey: leafNode.signatureKey)))
		}
		return roster
	}

	/// RFC 9420 §12.4.3.1, reordered so every structural check on the tree
	/// precedes the first cryptographic judgement that reads from it (the
	/// RFC's own bullet 5, the `GroupInfo` signature check, reads its
	/// verification key out of the tree at leaf `signer` — so the tree
	/// must already be decoded and structurally sane before that
	/// signature can be checked at all). Each step below names the RFC
	/// bullet it corresponds to.
	///
	/// `externalTree` is the out-of-band ratchet tree; preferred over the
	/// `ratchet_tree` extension when both are present, an error when
	/// neither is.
	///
	/// `psk` resolves a `PreSharedKeyID` to its secret. Returning nil is
	/// an error, not a silent skip — RFC 9420: "if a PreSharedKeyID is
	/// part of the GroupSecrets and the client is not in possession of
	/// the corresponding PSK, return an error."
	///
	/// Caller responsibility this function cannot check on its own:
	/// verifying `group_id` is unique among the groups this client is
	/// already participating in (RFC 9420 §12.4.3.1) — the library holds
	/// one `Group` and has no registry of the caller's others. The
	/// `PendingJoin` exposes `context` (hence `groupID`) for exactly this check,
	/// before `apply()`.
	///
	/// D17 step 1 for a join: run the full §12.4.3.1 Welcome validation and build
	/// the group, but hand it back as a `PendingJoin` so the application can
	/// adjudicate the `roster` (the credentials it is about to trust, §5.3.1) and
	/// `signer` before adopting it with `apply()`. The one-time KeyPackage is
	/// consumed whether or not the app applies (`consumedKeyPackage`, D17 §2 L5); a
	/// `joining` that *throws* reports nothing, and the app decides whether to burn
	/// the KeyPackage on a validation failure. The eager `join(...)` does both steps for callers that adopt immediately.
	public static func joining(
		_ provider: any MLS.CipherSuiteProvider,
		welcome: MLS.RFC9420.Welcome,
		credentials: JoinerCredentials,
		externalTree: [MLS.RFC9420.Node?]? = nil,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.PendingJoin {
		// bullet 1
		guard welcome.cipherSuite == credentials.keyPackage.cipherSuite else {
			throw MLS.RFC9420.GroupError.cipherSuiteMismatch
		}
		let keyPackageRef = try credentials.keyPackage.reference(provider)

		// bullet 2
		let groupSecrets = try welcome.decryptGroupSecrets(
			provider, keyPackageRef: keyPackageRef, initKey: credentials.initKey)

		// bullet 3, structural half. RFC 9420 §12.4.3.1: "if a PreSharedKeyID
		// has type resumption with usage reinit or branch, verify that it is
		// the only such PSK." "Such" is anaphoric to "resumption with usage
		// reinit or branch", so this is read as: at most one resumption PSK of
		// usage reinit/branch (external/application PSKs may accompany it).
		// Purely structural, so it precedes both the capability gate below and
		// any resolution or derivation. That gate today rejects every
		// reinit/branch usage regardless; keeping this check independent keeps
		// the MUST enforced for when the gate is relaxed.
		let reinitOrBranchPSKs = groupSecrets.psks.filter {
			if case .resumption(let resumption, _) = $0 {
				return resumption.usage == .reinit || resumption.usage == .branch
			}
			return false
		}.count
		guard reinitOrBranchPSKs <= 1 else {
			throw MLS.RFC9420.GroupError.resumptionPSKNotSole
		}

		// bullet 3, capability + custody half. Resumption PSKs with usage
		// reinit/branch carry semantic rules (the Welcome's epoch being 1, and
		// the §11.2/§11.3 referenced-group checks) meaningless without ReInit/
		// branching support, which this project defers project-wide. Rejected
		// outright rather than silently accepted with those checks unenforced.
		var resolvedPsks: [(encodedID: Data, psk: SecretBytes)] = []
		for id in groupSecrets.psks {
			if case .resumption(let resumption, _) = id,
				resumption.usage != .application
			{
				throw MLS.RFC9420.GroupError.unsupportedResumptionUsage
			}
			guard let secret = try psk(id) else {
				throw MLS.RFC9420.GroupError.unresolvedPreSharedKey
			}
			// Take custody of the app-supplied PSK bytes on the way in.
			// An empty one is malformed, not merely unresolved.
			guard !secret.isEmpty else {
				throw MLS.RFC9420.GroupError.emptyPreSharedKey
			}
			let held = try SecretBytes(bytes: secret)
			resolvedPsks.append((try id.mlsEncoded(), held))
		}
		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: resolvedPsks)

		// bullet 4. A zero-length joiner_secret cannot key the schedule --
		// reject a hostile/malformed Welcome here rather than deriving
		// garbage that only fails later at the confirmation tag.
		guard !groupSecrets.joinerSecret.isEmpty else {
			throw MLS.RFC9420.GroupError.emptyJoinerSecret
		}
		let (groupInfo, epoch) = try welcome.decryptGroupInfo(
			provider, joinerSecret: groupSecrets.joinerSecret, pskSecret: pskSecret)

		// tree decode, ahead of the RFC's own ordering (see doc comment)
		let nodes: [MLS.RFC9420.Node?]
		if let externalTree {
			nodes = externalTree
		} else if let extensionTree = try groupInfo.ratchetTreeExtension() {
			nodes = extensionTree
		} else {
			throw MLS.RFC9420.GroupError.missingRatchetTree
		}
		try MLS.RFC9420.validateNoTrailingBlank(nodes)
		let tree = try MLS.TreeKEM.RatchetTree(nodes)

		// bullet 8 (tree-integrity sub-bullets, plus every non-blank
		// leaf's own signature -- §7.3's authenticity half, plus, since
		// phase 6, the policy half: capability/extension consistency,
		// mutual credential support, `required_capabilities`). Lifetime
		// bounds stay caller opt-ins -- unlike a signature, a lifetime
		// judgement needs a clock,
		// which aren't this function's job to adjudicate.
		try tree.validateNodeKinds()
		try tree.validateParentHashChain(provider)
		try tree.validateUnmergedLeaves()
		try tree.validateNoDuplicateEncryptionKeys()
		guard try tree.treeHash(provider) == groupInfo.groupContext.treeHash else {
			throw MLS.TreeKEM.TreeError.treeHashMismatch
		}
		// The roster the app adjudicates before adopting (slice 4c): every member's
		// leaf and presentation, each a signature-verified binding by construction
		// (this pass checks every leaf's own signature). Whether the app *trusts* a
		// credential is its §5.3.1 judgement, not this library's.
		let roster = try validateLeaves(
			tree, groupID: groupInfo.groupContext.groupID,
			groupExtensions: groupInfo.groupContext.extensions, provider)

		// bullet 7. RFC 9420 §10.1 pairs these two in one sentence --
		// "Verify that the cipher suite and protocol version of the
		// KeyPackage match those in the GroupContext" -- so they are one
		// check, not a cipher-suite check with a version check bolted on.
		// The version half has no bite today (`mls10` is the only value
		// RFC 9420 defines, and this profile's `Message` decoder rejects
		// anything else at its dispatch point), but this library exists to
		// produce protocol variants: the moment a second version is
		// representable, a joiner that never compares versions accepts
		// whatever the inviter claims.
		guard groupInfo.groupContext.cipherSuite == credentials.keyPackage.cipherSuite
		else {
			throw MLS.RFC9420.GroupError.cipherSuiteMismatch
		}
		guard groupInfo.groupContext.version == credentials.keyPackage.version else {
			throw MLS.RFC9420.GroupError.protocolVersionMismatch
		}

		// bullet 5
		guard let signerLeaf = tree.leaf(at: groupInfo.signer) else {
			throw MLS.RFC9420.GroupError.blankSignerLeaf
		}
		let signerLeafNode = try MLS.RFC9420.LeafNode(mlsEncoded: signerLeaf.encoded)
		try groupInfo.verifySignature(provider, signatureKey: signerLeafNode.signatureKey)

		// bullet 9 -- find our own leaf by byte-exact LeafNode equality,
		// not by comparing individual fields (a field-wise match could
		// paper over a signature the tree never actually verified).
		let ownEncoded = try credentials.keyPackage.leafNode.mlsEncoded()
		guard
			let (myLeafIndex, _) = tree.nonBlankLeaves().first(where: {
				$0.record.encoded == ownEncoded
			})
		else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}

		var secretKeys: [UInt32: MLS.HpkeSecretKey] = [
			2 * myLeafIndex.value: credentials.encryptionKey
		]

		// bullet 10
		if let pathSecret = groupSecrets.pathSecret {
			let installed = try tree.installPathSecrets(
				forLeaf: myLeafIndex, from: groupInfo.signer,
				pathSecret: pathSecret,
				provider)
			for (node, secretKey) in installed { secretKeys[node] = secretKey }
		}

		// bullet 13
		let expectedTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: epoch.confirmationKey,
			confirmedTranscriptHash: groupInfo.groupContext.confirmedTranscriptHash)
		guard expectedTag == groupInfo.confirmationTag else {
			throw MLS.RFC9420.GroupError.confirmationTagMismatch
		}

		let interimTranscriptHash = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: groupInfo.groupContext.confirmedTranscriptHash,
			confirmationTag: groupInfo.confirmationTag)

		var group = MLS.RFC9420.Group(
			context: groupInfo.groupContext, tree: tree,
			interimTranscriptHash: interimTranscriptHash, myLeafIndex: myLeafIndex,
			epoch: EpochSecrets(retaining: epoch), secretKeys: secretKeys,
			resumptionPsks: [groupInfo.groupContext.epoch: epoch.resumptionPsk])
		try group.installMessageSecrets(
			context: groupInfo.groupContext,
			senderDataSecret: epoch.senderDataSecret,
			encryptionSecret: epoch.encryptionSecret,
			applicationExportSecret: epoch.applicationExportSecret, tree: tree, provider
		)

		return MLS.RFC9420.PendingJoin(
			roster: roster, signer: groupInfo.signer,
			consumedKeyPackage: keyPackageRef, context: group.context,
			myLeafIndex: group.myLeafIndex, group: group)
	}
}
