import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

extension MLS.RFC9420.Group {
	/// The random inputs one commit consumes. A parameter struct rather
	/// than internal generation, following `beginCommitPath`'s precedent:
	/// the caller owns randomness, so construction is deterministic and
	/// testable byte-for-byte; `generate` is the production convenience.
	public struct CommitRandomness: Sendable {
		public var firstPathSecret: Data
		public var leafEncryptionSecretKey: MLS.HpkeSecretKey
		public var leafEncryptionPublicKey: MLS.HpkePublicKey

		public init(
			firstPathSecret: Data, leafEncryptionSecretKey: MLS.HpkeSecretKey,
			leafEncryptionPublicKey: MLS.HpkePublicKey
		) {
			self.firstPathSecret = firstPathSecret
			self.leafEncryptionSecretKey = leafEncryptionSecretKey
			self.leafEncryptionPublicKey = leafEncryptionPublicKey
		}

		public static func generate(_ provider: any MLS.CipherSuiteProvider) throws
			-> CommitRandomness
		{
			let (secretKey, publicKey) = try provider.hpkeGenerateKeyPair()
			return CommitRandomness(
				firstPathSecret: provider.randomBytes(provider.hashSize),
				leafEncryptionSecretKey: secretKey,
				leafEncryptionPublicKey: publicKey)
		}
	}

	/// How `committing` frames the commit it produces. Private by default
	/// (RFC 9420 §6's steer toward `PrivateMessage`); the external interop
	/// harness opts into `.publicMessage` because the mlswg runner drives
	/// public handshakes.
	public enum HandshakeFraming: Sendable {
		case privateMessage
		case publicMessage
	}

	/// RFC 9420 §11: create a one-member group. `epochSecret` is §11's
	/// "fresh random value of size KDF.Nh" — the epoch secret *is* the
	/// random value (its joiner/welcome siblings do not exist at epoch 0,
	/// which is why this takes the `EpochFanOut` path rather than
	/// fabricating them through `advance`). `leafNode` is the creator's
	/// own `key_package`-sourced, already-signed leaf.
	public static func create(
		_ provider: any MLS.CipherSuiteProvider,
		groupID: Data,
		leafNode: MLS.RFC9420.LeafNode,
		leafSecretKey: MLS.HpkeSecretKey,
		extensions: [MLS.RFC9420.Extension] = [],
		epochSecret: Data
	) throws -> MLS.RFC9420.Group {
		let tree = MLS.TreeKEM.RatchetTree(singleLeaf: try leafNode.record)
		let context = MLS.RFC9420.GroupContext(
			version: .mls10, cipherSuite: provider.cipherSuite,
			groupID: groupID, epoch: 0,
			treeHash: try tree.treeHash(provider),
			confirmedTranscriptHash: Data(),
			extensions: extensions)
		// The creator's own leaf still goes through validation — a group
		// born from a leaf that would be rejected at every later join is
		// a group that cannot grow.
		try validateLeaves(
			tree, groupID: groupID, groupExtensions: extensions, provider)

		let fanOut = try MLS.KeySchedule.fromEpochSecret(
			provider, epochSecret: epochSecret)
		let confirmationTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: fanOut.confirmationKey,
			confirmedTranscriptHash: Data())
		let interim = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: Data(), confirmationTag: confirmationTag)

		var group = MLS.RFC9420.Group(
			context: context, tree: tree, interimTranscriptHash: interim,
			myLeafIndex: MLS.LeafIndex(value: 0),
			epoch: EpochSecrets(retaining: fanOut),
			secretKeys: [0: leafSecretKey],
			resumptionPsks: [0: fanOut.resumptionPsk])
		try group.installMessageSecrets(
			context: context, senderDataSecret: fanOut.senderDataSecret,
			encryptionSecret: fanOut.encryptionSecret,
			applicationExportSecret: fanOut.applicationExportSecret, tree: tree,
			provider)
		return group
	}

	/// RFC 9420 §12.4.1, start to finish: validate the list, apply the
	/// proposals, encap, sign, chain the transcript, advance the schedule,
	/// tag, seal — and generate the Welcome for any added members.
	///
	/// `includePath: false` requests §12.4's MAY-omit; it throws
	/// `pathRequired` when the list does not permit omission (empty
	/// commits and path-required proposal types MUST carry one).
	///
	/// Never mutates `self` (D17): it returns a `Transition<SentCommit>` — the
	/// `group` is the OLD epoch with the committer's own handshake generation
	/// consumed (a private commit spends it at seal, §12.4.1), which the caller
	/// **adopts and persists before transmitting** `SentCommit.message`, and the
	/// epoch advance is `SentCommit.pending`, applied once the Delivery Service
	/// affirms the commit. The eager `commit(...)` shim does both steps for
	/// callers that adopt immediately.
	public func committing(
		_ provider: any MLS.CipherSuiteProvider,
		proposals proposalList: [MLS.RFC9420.ProposalOrRef],
		proposalStore: MLS.RFC9420.ProposalStore = MLS.RFC9420.ProposalStore(),
		signingKey: MLS.SignatureSecretKey,
		randomness: CommitRandomness,
		includePath: Bool = true,
		includeRatchetTreeExtension: Bool = true,
		framing: HandshakeFraming = .privateMessage,
		reuseGuard: MLS.Framing.ReuseGuard? = nil,
		paddingLength: Int = 0,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { _ in nil }
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.SentCommit> {
		// The bare entry commits as the sole membership; `committing(as:)` names it.
		try committing(
			committerIndex: try soleMembershipIndex(), provider,
			proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension, framing: framing,
			reuseGuard: reuseGuard, paddingLength: paddingLength, psk: psk)
	}

	/// The committer-scoped core (slice 4a). `committerIndex` names the local
	/// membership that authors this commit; the OTHER local memberships receive
	/// the same commit by decapping its path (`installKeysForMembership`), so the
	/// returned delta installs new-epoch keys for every membership. All must agree
	/// on one `commit_secret` (`divergentCommitSecret` otherwise, a library bug on
	/// the send side — the committer built the path all of them decap).
	func committing(
		committerIndex: Int,
		_ provider: any MLS.CipherSuiteProvider,
		proposals proposalList: [MLS.RFC9420.ProposalOrRef],
		proposalStore: MLS.RFC9420.ProposalStore = MLS.RFC9420.ProposalStore(),
		signingKey: MLS.SignatureSecretKey,
		randomness: CommitRandomness,
		includePath: Bool = true,
		includeRatchetTreeExtension: Bool = true,
		framing: HandshakeFraming = .privateMessage,
		reuseGuard: MLS.Framing.ReuseGuard? = nil,
		paddingLength: Int = 0,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { _ in nil }
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.SentCommit> {
		let committerLeaf = memberships[committerIndex].leafIndex
		// Resolve, exactly as the receive side does.
		var resolved: [MLS.RFC9420.StoredProposal] = []
		for entry in proposalList {
			switch entry {
			case .proposal(let proposal):
				// Inline (by-value): framed in this commit, so this epoch.
				resolved.append(
					.init(
						proposal: proposal, sender: .member(committerLeaf),
						epoch: context.epoch, groupID: context.groupID))
			case .reference(let ref):
				guard let stored = proposalStore[ref] else {
					throw MLS.RFC9420.GroupError.unknownProposalReference
				}
				try requireCurrentContext(stored)
				resolved.append(stored)
			}
		}
		// Constructing what this project cannot process is refused
		// outright — the receive side documents both.
		guard
			!resolved.contains(where: {
				if case .reInit = $0.proposal { true } else { false }
			})
		else { throw MLS.RFC9420.GroupError.unsupportedReInit }
		guard
			!resolved.contains(where: {
				if case .externalInit = $0.proposal { true } else { false }
			})
		else { throw MLS.RFC9420.GroupError.externalInitInRegularCommit }

		var provisionalExtensions = context.extensions
		for stored in resolved {
			if case .groupContextExtensions(let extensions) = stored.proposal {
				provisionalExtensions = extensions
			}
		}
		let updateChanges = try validateProposalList(
			resolved, committer: committerLeaf,
			provisionalExtensions: provisionalExtensions, provider: provider)

		let pskIDs = resolved.compactMap { stored -> MLS.RFC9420.PreSharedKeyIdentifier? in
			guard case .preSharedKey(let id) = stored.proposal else { return nil }
			return id
		}
		let resolvedPsks = try pskIDs.map { id -> (encodedID: Data, psk: SecretBytes) in
			guard let secret = try resolvePsk(id, psk) else {
				throw MLS.RFC9420.GroupError.unresolvedPreSharedKey
			}
			return (try id.mlsEncoded(), secret)
		}

		// §12.4's sender-side rule is the same predicate the receive side
		// checks — the same expression, deliberately.
		let pathRequired =
			resolved.isEmpty
			|| resolved.contains { stored in
				switch stored.proposal {
				case .update, .remove, .externalInit, .groupContextExtensions:
					true
				// §7.2.1 registers app_data_update as Path Required N — it touches
				// no leaf/tree key, so it never forces a path.
				case .add, .preSharedKey, .reInit, .appDataUpdate: false
				}
			}
		if !includePath && pathRequired {
			throw MLS.RFC9420.GroupError.pathRequired
		}

		let applied = try applyProposals(resolved, committer: committerLeaf)
		var newTree = applied.tree

		// Slice 4b eviction, send side: a commit may remove one of THIS device's
		// OTHER local memberships. It is always PARTIAL — the committer cannot
		// remove itself (RFC 9420 §12.2, and `validateProposalList` rejects an
		// inline self-Remove), so the committer always survives. The removed
		// memberships are dropped from the delta's installs and reported as
		// `membershipRemoved`; `apply` removes them from the composite.
		let removedLeaves = resolved.compactMap { stored -> MLS.LeafIndex? in
			if case .remove(let leaf) = stored.proposal { return leaf }
			return nil
		}
		let localLeaves = Set(memberships.map(\.leafIndex))
		let removedLocal = localLeaves.intersection(removedLeaves)

		guard let senderRecord = tree.leaf(at: committerLeaf) else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderRecord.encoded)

		var updatePath: MLS.RFC9420.UpdatePath?
		let commitSecret: Data
		var stage: MLS.TreeKEM.CommitPathStage?
		var unfilteredNodeIndices: [UInt32] = []
		// The context the path secrets are encrypted against — kept for the
		// other local memberships to decap the same path (slice 4a).
		var provisionalContextEncoded: Data?
		// The committer's own path-leaf refresh, for the credential effects (slice
		// 4b). The new leaf keeps the committer's credential and signature key, so
		// this is always an `updated` (encryption-key-only) effect; nil if pathless.
		var committerChange:
			(
				leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
				new: MLS.RFC9420.CredentialPresentation
			)?

		if includePath {
			// The filtered direct path on the post-apply tree — computed
			// before `beginCommitPath` and kept, because `CommitPathStage`
			// deliberately does not expose node indices. (Safe:
			// `beginCommitPath` writes only direct-path parents, which
			// are not in any copath resolution, so the filtering is
			// stable across the call.)
			let directPath = MLS.TreeMath.directPath(
				from: 2 * committerLeaf.value, leafCount: newTree.leafCount)
			let filtered = try newTree.filteredDirectPath(from: committerLeaf)
			unfilteredNodeIndices = zip(directPath, filtered)
				.filter { !$0.1 }.map(\.0.path)

			let pathStage = try newTree.beginCommitPath(
				sender: committerLeaf,
				firstPathSecret: randomness.firstPathSecret, provider)

			var newLeaf = MLS.RFC9420.LeafNode(
				encryptionKey: randomness.leafEncryptionPublicKey,
				signatureKey: senderLeaf.signatureKey,
				credential: senderLeaf.credential,
				capabilities: senderLeaf.capabilities,
				source: .commit(parentHash: pathStage.leafParentHash),
				extensions: senderLeaf.extensions,
				signature: Data())
			newLeaf.signature = try MLS.signWithLabel(
				provider, privateKey: signingKey, label: "LeafNodeTBS",
				content: try newLeaf.toBeSigned(
					placement: .inGroup(
						groupID: context.groupID, leafIndex: committerLeaf))
			)
			// The new leaf carries the committer's OWN signature key, so verifying
			// the signature we just produced fails loudly when `signingKey` is not
			// the committer's private key (at N > 1, `as:` and `signingKey:` are two
			// independent parameters that must agree — a mismatch would otherwise
			// fork the composite locally against a commit every remote member
			// rejects). Harmless at N = 1, where there is only one key to pass.
			try newLeaf.verifySignature(
				provider,
				placement: .inGroup(
					groupID: context.groupID, leafIndex: committerLeaf))
			try newTree.setLeaf(committerLeaf, to: newLeaf.record)
			committerChange = (
				leaf: committerLeaf,
				old: MLS.RFC9420.CredentialPresentation(
					credential: senderLeaf.credential,
					signatureKey: senderLeaf.signatureKey),
				new: MLS.RFC9420.CredentialPresentation(
					credential: newLeaf.credential,
					signatureKey: newLeaf.signatureKey)
			)

			// Provisional context: new epoch, post-merge tree hash, OLD
			// confirmed transcript hash, new extensions (§12.4.1).
			let provisionalContext = MLS.RFC9420.GroupContext(
				version: context.version, cipherSuite: context.cipherSuite,
				groupID: context.groupID, epoch: context.epoch + 1,
				treeHash: try newTree.treeHash(provider),
				confirmedTranscriptHash: context.confirmedTranscriptHash,
				extensions: provisionalExtensions)

			let encodedProvisional = try provisionalContext.mlsEncoded()
			provisionalContextEncoded = encodedProvisional
			let (pathNodes, derivedCommitSecret) = try newTree.finishCommitPath(
				pathStage, groupContext: encodedProvisional,
				excluding: applied.addedLeaves, provider)
			updatePath = MLS.RFC9420.UpdatePath(
				leafNode: newLeaf,
				nodes: pathNodes.map(MLS.RFC9420.UpdatePathNode.init))
			commitSecret = derivedCommitSecret
			stage = pathStage
		} else {
			commitSecret = Data(repeating: 0, count: provider.hashSize)
		}

		// No trailing-blank check on the send side: the tree is serialized
		// via `serializedNodeCount`, which trims trailing blanks by
		// construction, so a built tree can never produce a malformed wire
		// form. (It was a receive-side wire property; that check now lives on
		// the decoded array in `Group.joining`.)

		// Frame, sign under the OLD context, chain the transcript.
		let commit = MLS.RFC9420.Commit(proposals: proposalList, path: updatePath)
		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: context.epoch,
			sender: .member(committerLeaf), authenticatedData: Data(),
			content: .commit(commit))
		let (signedContent, signature) =
			try framing == .publicMessage
			? MLS.RFC9420.signPublic(
				provider, content: framed, groupContext: context,
				signingKey: signingKey)
			: MLS.RFC9420.signPrivate(
				provider, content: framed, groupContext: context,
				signingKey: signingKey)
		var signatureWriter = MLS.Writer()
		try signatureWriter.encode(signature)
		let confirmedTranscriptHash = try MLS.Framing.confirmedTranscriptHash(
			provider, interimBefore: interimTranscriptHash,
			input: try signedContent.confirmedTranscriptHashInput(
				encodedSignature: Data(signatureWriter.bytes)))

		let newContext = MLS.RFC9420.GroupContext(
			version: context.version, cipherSuite: context.cipherSuite,
			groupID: context.groupID, epoch: context.epoch + 1,
			treeHash: try newTree.treeHash(provider),
			confirmedTranscriptHash: confirmedTranscriptHash,
			extensions: provisionalExtensions)

		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: resolvedPsks)
		let newEpoch = try MLS.KeySchedule.advance(
			provider, initSecret: epoch.initSecret, commitSecret: commitSecret,
			pskSecret: pskSecret, groupContext: try newContext.mlsEncoded())
		let confirmationTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: newEpoch.confirmationKey,
			confirmedTranscriptHash: confirmedTranscriptHash)

		// The committer's own post-commit private state.
		// `senderIndex` only when a path re-keyed the direct path -- the
		// receive side splits exactly this way. Passing it for a pathless
		// commit pruned the committer's own parent keys with nothing
		// re-adding them: the next far-subtree commit encrypts to a node
		// key the committer threw away, and the committer is locked out of
		// its own group permanently (`notAMember` at decap). The
		// self-interop gate missed it because no *other* member ever
		// committed a path after a pathless commit -- the stage-5 review's
		// three-member repro is now the regression test.
		var newSecretKeys = prunedSecretKeys(
			heldSecretKeys: memberships[committerIndex].secretKeys,
			ownLeaf: committerLeaf, blankedNodes: applied.blankedNodes,
			senderIndex: includePath ? committerLeaf : nil,
			leafCount: newTree.leafCount)
		if let stage {
			newSecretKeys[2 * committerLeaf.value] = randomness.leafEncryptionSecretKey
			for (node, key) in zip(unfilteredNodeIndices, stage.nodeSecretKeys) {
				newSecretKeys[node] = key
			}
		}

		// The committer built the path; every OTHER local membership receives the
		// same commit by decapping it (slice 4a) — exactly as a remote member
		// would in `validatedDelta`. Each must recover the committer's own
		// `commit_secret`; a mismatch is a construction bug (the committer built
		// what they decap), surfaced as `divergentCommitSecret` rather than
		// shipping disagreeing key material.
		var newSecretKeysByLeaf: [MLS.LeafIndex: [UInt32: MLS.HpkeSecretKey]] = [
			committerLeaf: newSecretKeys
		]
		for (index, membership) in memberships.enumerated()
		where index != committerIndex && !removedLocal.contains(membership.leafIndex) {
			if let path = updatePath, let contextEncoded = provisionalContextEncoded {
				let (keys, derived) = try installKeysForMembership(
					membership, path: path, provisionalTree: newTree,
					senderIndex: committerLeaf,
					provisionalContextEncoded: contextEncoded,
					blankedNodes: applied.blankedNodes,
					addedLeaves: applied.addedLeaves, provider)
				guard derived == commitSecret else {
					throw MLS.RFC9420.GroupError.divergentCommitSecret
				}
				newSecretKeysByLeaf[membership.leafIndex] = keys
			} else {
				// Pathless: the other memberships only shed keys for blanked nodes.
				newSecretKeysByLeaf[membership.leafIndex] = prunedSecretKeys(
					heldSecretKeys: membership.secretKeys,
					ownLeaf: membership.leafIndex,
					blankedNodes: applied.blankedNodes,
					senderIndex: nil, leafCount: newTree.leafCount)
			}
		}

		// Build the epoch DELTA (D17 §2/§4) — the send-side twin of
		// `validatedDelta`, never a successor group. The new-epoch message store
		// and exporter are built standalone; the old-epoch stores are NOT captured
		// (they come from the group at `apply`, which is what preserves any
		// consumption made while the commit is pending).
		let newInterim = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmedTranscriptHash,
			confirmationTag: confirmationTag)
		let (newStore, newExporter) = try Self.makeEpochMessageState(
			context: newContext, senderDataSecret: newEpoch.senderDataSecret,
			encryptionSecret: newEpoch.encryptionSecret,
			applicationExportSecret: newEpoch.applicationExportSecret,
			tree: newTree, provider)
		let effects = commitMembershipEffects(
			epochAdvanced: .epochAdvanced(
				from: context.epoch, to: newContext.epoch, committer: committerLeaf),
			added: applied.added, updateChanges: updateChanges,
			committerChange: committerChange, removedLeaves: removedLeaves,
			localMembershipLeaves: localLeaves,
			appDataUpdates: resolved.compactMap {
				if case .appDataUpdate(let update) = $0.proposal {
					update
				} else {
					nil
				}
			})
		let pending = MLS.RFC9420.PendingCommit(
			effects: effects, base: context, baseMemberships: localLeaves,
			newContext: newContext, newTree: newTree,
			newEpoch: EpochSecrets(retaining: newEpoch),
			newSecretKeysByLeaf: newSecretKeysByLeaf,
			newInterimTranscriptHash: newInterim,
			newMessageStore: newStore, newExporterTree: newExporter,
			newResumptionPsk: newEpoch.resumptionPsk,
			removedMemberships: removedLocal)

		let welcome = try makeWelcome(
			provider, committer: committerLeaf, resolved: resolved, applied: applied,
			stage: stage, newTree: newTree, newContext: newContext,
			confirmationTag: confirmationTag, newEpoch: newEpoch,
			pskIDs: pskIDs, signingKey: signingKey,
			includeRatchetTreeExtension: includeRatchetTreeExtension)

		// Seal in the OLD epoch. A private commit spends the committer's own next
		// handshake generation there (§12.4.1); that consumption is recorded on
		// `sealed` — a copy of the pre-commit group — which is the state the
		// caller adopts and persists BEFORE transmitting, so a crash-and-resend
		// cannot reuse the generation. A public commit consumes nothing
		// (OLD membership key, §12.4.1), so `sealed` is unchanged.
		var sealed = self
		let message: MLS.RFC9420.Message
		switch framing {
		case .publicMessage:
			message = .publicMessage(
				try MLS.RFC9420.sealPublic(
					provider, content: framed, signedContent: signedContent,
					signature: signature, confirmationTag: confirmationTag,
					membershipKey: epoch.membershipKey))
		case .privateMessage:
			// Sealed on the committing membership's own handshake ratchet (§12.4.1).
			message = .privateMessage(
				try sealed.sealHandshakeCommit(
					membershipIndex: committerIndex, provider,
					epoch: context.epoch,
					framed: framed,
					signature: signature, confirmationTag: confirmationTag,
					reuseGuard: reuseGuard
						?? MLS.Framing.ReuseGuard(provider.randomBytes(4)),
					paddingLength: paddingLength))
		}

		return MLS.RFC9420.Transition(
			group: sealed,
			output: MLS.RFC9420.SentCommit(
				message: message, welcome: welcome, pending: pending))
	}

	/// §12.4.1's Welcome tail: GroupInfo (signed, then sealed under the
	/// welcome key/nonce), and per added member a `GroupSecrets` carrying
	/// the joiner secret, the path secret at the least common ancestor
	/// with the committer, and the commit's PSK ids in proposal order —
	/// HPKE-sealed to the member's `init_key` with the *encrypted*
	/// GroupInfo as context (the splice-prevention binding `joining`'s
	/// decrypt side documents), which is why the GroupInfo must be sealed
	/// first.
	private func makeWelcome(
		_ provider: any MLS.CipherSuiteProvider,
		committer: MLS.LeafIndex,
		resolved: [MLS.RFC9420.StoredProposal],
		applied: AppliedProposals,
		stage: MLS.TreeKEM.CommitPathStage?,
		newTree: MLS.TreeKEM.RatchetTree,
		newContext: MLS.RFC9420.GroupContext,
		confirmationTag: MLS.ConfirmationTag,
		newEpoch: MLS.KeySchedule.Epoch,
		pskIDs: [MLS.RFC9420.PreSharedKeyIdentifier],
		signingKey: MLS.SignatureSecretKey,
		includeRatchetTreeExtension: Bool
	) throws -> MLS.RFC9420.Welcome? {
		guard !applied.addedLeaves.isEmpty else { return nil }

		var groupInfoExtensions: [MLS.RFC9420.Extension] = []
		if includeRatchetTreeExtension {
			var writer = MLS.Writer()
			try writer.encodeVector(newTree.nodes)
			groupInfoExtensions.append(
				.init(type: .init(.ratchetTree), data: Data(writer.bytes)))
		}
		var groupInfo = MLS.RFC9420.GroupInfo(
			groupContext: newContext, extensions: groupInfoExtensions,
			confirmationTag: confirmationTag, signer: committer,
			signature: Data())
		groupInfo.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "GroupInfoTBS",
			content: try groupInfo.toBeSigned())

		let (welcomeKey, welcomeNonce) = try MLS.KeySchedule.welcomeKeyNonce(
			provider, welcomeSecret: newEpoch.welcomeSecret)
		let encryptedGroupInfo = try provider.aeadSeal(
			key: welcomeKey, nonce: welcomeNonce, aad: nil,
			plaintext: try groupInfo.mlsEncoded())

		let myPath = MLS.TreeMath.directPath(
			from: 2 * committer.value, leafCount: newTree.leafCount
		).map(\.path)

		var secrets: [MLS.RFC9420.EncryptedGroupSecrets] = []
		for stored in resolved {
			guard case .add(let keyPackage) = stored.proposal else { continue }
			// §12.4.3.1: "the set of Welcome messages produced in this
			// step MUST cover every new member added in the Commit" -- an
			// unmatched member is a thrown invariant violation, never a
			// silent skip.
			guard
				let addedIndex = applied.addedLeaves.first(where: { index in
					(try? newTree.leaf(at: index)?.encoded
						== keyPackage.leafNode.mlsEncoded()) ?? false
				})
			else { throw MLS.RFC9420.GroupError.welcomeCoverageIncomplete }

			// The path secret at the LCA of the committer and this new
			// member — nil for pathless commits, and nil when the LCA is
			// a filtered position (no secret was derived there).
			var pathSecret: Data?
			if let stage {
				let addedPath = Set(
					MLS.TreeMath.directPath(
						from: 2 * addedIndex.value,
						leafCount: newTree.leafCount
					).map(\.path))
				if let lca = myPath.first(where: addedPath.contains) {
					pathSecret = stage.pathSecret(atNode: lca)
				}
			}

			// Custody exit at the wire boundary: `joiner_secret` is carried
			// in the Welcome's `GroupSecrets`, so it is copied out of
			// zeroizing storage into the plaintext that is then HPKE-sealed
			// (the encoded, encrypted `GroupSecrets` is what leaves).
			let groupSecrets = MLS.RFC9420.GroupSecrets(
				joinerSecret: newEpoch.joinerSecret.withUnsafeBytes { Data($0) },
				pathSecret: pathSecret,
				psks: pskIDs)
			let (enc, ciphertext) = try MLS.encryptWithLabel(
				provider, publicKey: keyPackage.initKey, label: "Welcome",
				context: encryptedGroupInfo,
				plaintext: try groupSecrets.mlsEncoded())
			secrets.append(
				.init(
					newMember: try keyPackage.reference(provider),
					encryptedGroupSecrets: .init(
						kemOutput: enc, ciphertext: ciphertext)))
		}

		return MLS.RFC9420.Welcome(
			cipherSuite: context.cipherSuite, secrets: secrets,
			encryptedGroupInfo: encryptedGroupInfo)
	}
}
