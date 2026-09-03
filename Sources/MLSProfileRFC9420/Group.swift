import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath

extension MLS.RFC9420 {
	/// A member's view of one RFC 9420 group: the tree, the current
	/// `GroupContext`, and everything needed to process the next Welcome
	/// or Commit. Value type, no actors or shared mutable state — the app
	/// owns storage, this owns nothing but its own fields.
	public struct Group: Sendable {
		// `internal(set)`, not `private(set)`: Swift scopes `private` to the
		// file, and commit processing lives in `CommitProcessing.swift`.
		// Publicly these stay read-only -- a caller mutates a `Group` only
		// through `join`/`process`.
		public internal(set) var context: GroupContext
		public internal(set) var tree: MLS.TreeKEM.RatchetTree
		public internal(set) var interimTranscriptHash: Data
		public internal(set) var myLeafIndex: MLS.LeafIndex
		public internal(set) var epoch: EpochSecrets

		/// See `RetentionPolicy`. Lowering it prunes immediately, not at
		/// the next commit — a group that never processes another commit
		/// must still be able to shed history.
		public var retention: RetentionPolicy = RetentionPolicy() {
			didSet { pruneResumptionPsks(currentEpoch: context.epoch) }
		}

		/// Every HPKE secret key this member currently holds, keyed by
		/// *node* index — its own leaf (`2 * myLeafIndex`) plus whatever
		/// direct-path ancestors the last Welcome or Commit installed.
		/// `MLSTreeKEM`'s `heldSecretKeys`/`DecapResult` parameters made
		/// stateful.
		var secretKeys: [UInt32: MLS.HpkeSecretKey]

		/// `resumption_psk` for recent epochs, keyed by epoch — bounded by
		/// `retention.resumptionPskDepth`, enforced after every processed
		/// commit and on policy change.
		var resumptionPsks: [UInt64: Data]

		/// Per-epoch application-message state (secret tree, ratchets,
		/// epoch snapshots) — the §9.2 consuming store, bounded by
		/// `retention.messageSecretsDepth`. See `MessageProtection.swift`.
		var messageSecrets: [UInt64: MessageSecrets] = [:]

		mutating func pruneResumptionPsks(currentEpoch: UInt64) {
			// Saturating: at epochs below the depth, everything survives.
			// (An unchecked subtraction here traps -- the fixture epochs
			// are 2-4, below the default depth.)
			let depth = UInt64(retention.resumptionPskDepth)
			let floor = currentEpoch >= depth ? currentEpoch - depth : 0
			resumptionPsks = resumptionPsks.filter { $0.key >= floor }
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
	static func validateLeaves(
		_ tree: MLS.TreeKEM.RatchetTree, groupID: Data,
		groupExtensions: [MLS.RFC9420.Extension],
		_ provider: any MLS.CipherSuiteProvider
	) throws {
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
		}
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
	/// one `Group` and has no registry of the caller's others.
	public static func join(
		_ provider: any MLS.CipherSuiteProvider,
		welcome: MLS.RFC9420.Welcome,
		credentials: JoinerCredentials,
		externalTree: [MLS.RFC9420.Node?]? = nil,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Group {
		// bullet 1
		guard welcome.cipherSuite == credentials.keyPackage.cipherSuite else {
			throw MLS.RFC9420.GroupError.cipherSuiteMismatch
		}
		let keyPackageRef = try credentials.keyPackage.reference(provider)

		// bullet 2
		let groupSecrets = try welcome.decryptGroupSecrets(
			provider, keyPackageRef: keyPackageRef, initKey: credentials.initKey)

		// bullet 3. Resumption PSKs with usage reinit/branch carry their
		// own uniqueness and `GroupInfo.epoch == 1` rules -- meaningless
		// without ReInit/branching support, which this project defers
		// project-wide. Rejected outright rather than silently accepted
		// with those RFC-mandated checks unenforced.
		var resolvedPsks: [(encodedID: Data, psk: Data)] = []
		for id in groupSecrets.psks {
			if case .resumption(let resumption, _) = id,
				resumption.usage != .application
			{
				throw MLS.RFC9420.GroupError.unsupportedResumptionUsage
			}
			guard let secret = try psk(id) else {
				throw MLS.RFC9420.GroupError.unresolvedPreSharedKey
			}
			resolvedPsks.append((try id.mlsEncoded(), secret))
		}
		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: resolvedPsks)

		// bullet 4
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
		let tree = try MLS.TreeKEM.RatchetTree(nodes)

		// bullet 8 (tree-integrity sub-bullets, plus every non-blank
		// leaf's own signature -- §7.3's authenticity half, plus, since
		// phase 6, the policy half: capability/extension consistency,
		// mutual credential support, `required_capabilities`). Lifetime
		// bounds stay caller opt-ins -- unlike a signature, a lifetime
		// judgement needs a clock,
		// which aren't this function's job to adjudicate.
		try tree.validateNodeKinds()
		try tree.validateNoTrailingBlank()
		try tree.validateParentHashChain(provider)
		try tree.validateUnmergedLeaves()
		try tree.validateNoDuplicateEncryptionKeys()
		guard try tree.treeHash(provider) == groupInfo.groupContext.treeHash else {
			throw MLS.TreeKEM.TreeError.treeHashMismatch
		}
		try validateLeaves(
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
			encryptionSecret: epoch.encryptionSecret, tree: tree, provider)
		return group
	}
}
