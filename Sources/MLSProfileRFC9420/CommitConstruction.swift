import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath

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

	public struct CommitOutput: Sendable {
		/// The committer's own post-commit state.
		public let group: MLS.RFC9420.Group
		public let commit: MLS.RFC9420.PublicMessage
		/// Present iff the commit added members. **At commit time or
		/// never**: the retained epoch state deliberately keeps neither
		/// the confirmation tag nor the welcome secret (§9.2 retention),
		/// so there is no later route to a second Welcome for this epoch.
		public let welcome: MLS.RFC9420.Welcome?
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
			encryptionSecret: fanOut.encryptionSecret, tree: tree, provider)
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
	/// Never mutates `self` — same contract as `processing`, and for the
	/// same reason.
	public func committing(
		_ provider: any MLS.CipherSuiteProvider,
		proposals proposalList: [MLS.RFC9420.ProposalOrRef],
		proposalStore: MLS.RFC9420.ProposalStore = [:],
		signingKey: MLS.SignatureSecretKey,
		randomness: CommitRandomness,
		includePath: Bool = true,
		includeRatchetTreeExtension: Bool = true,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { _ in nil }
	) throws -> CommitOutput {
		// Resolve, exactly as the receive side does.
		var resolved: [MLS.RFC9420.StoredProposal] = []
		for entry in proposalList {
			switch entry {
			case .proposal(let proposal):
				resolved.append(
					.init(proposal: proposal, sender: .member(myLeafIndex)))
			case .reference(let ref):
				guard let stored = proposalStore[ref] else {
					throw MLS.RFC9420.GroupError.unknownProposalReference
				}
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
		else { throw MLS.RFC9420.GroupError.unsupportedSender }

		var provisionalExtensions = context.extensions
		for stored in resolved {
			if case .groupContextExtensions(let extensions) = stored.proposal {
				provisionalExtensions = extensions
			}
		}
		try validateProposalList(
			resolved, committer: myLeafIndex,
			provisionalExtensions: provisionalExtensions, provider: provider)

		let pskIDs = resolved.compactMap { stored -> MLS.RFC9420.PreSharedKeyIdentifier? in
			guard case .preSharedKey(let id) = stored.proposal else { return nil }
			return id
		}
		let resolvedPsks = try pskIDs.map { id -> (encodedID: Data, psk: Data) in
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
				case .add, .preSharedKey, .reInit: false
				}
			}
		if !includePath && pathRequired {
			throw MLS.RFC9420.GroupError.pathRequired
		}

		let applied = try applyProposals(resolved, committer: myLeafIndex)
		var newTree = applied.tree

		guard let senderRecord = tree.leaf(at: myLeafIndex) else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderRecord.encoded)

		var updatePath: MLS.RFC9420.UpdatePath?
		let commitSecret: Data
		var stage: MLS.TreeKEM.CommitPathStage?
		var unfilteredNodeIndices: [UInt32] = []

		if includePath {
			// The filtered direct path on the post-apply tree — computed
			// before `beginCommitPath` and kept, because `CommitPathStage`
			// deliberately does not expose node indices. (Safe:
			// `beginCommitPath` writes only direct-path parents, which
			// are not in any copath resolution, so the filtering is
			// stable across the call.)
			let directPath = MLS.TreeMath.directPath(
				from: 2 * myLeafIndex.value, leafCount: newTree.leafCount)
			let filtered = try newTree.filteredDirectPath(from: myLeafIndex)
			unfilteredNodeIndices = zip(directPath, filtered)
				.filter { !$0.1 }.map(\.0.path)

			let pathStage = try newTree.beginCommitPath(
				sender: myLeafIndex,
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
						groupID: context.groupID, leafIndex: myLeafIndex)))
			try newTree.setLeaf(myLeafIndex, to: newLeaf.record)

			// Provisional context: new epoch, post-merge tree hash, OLD
			// confirmed transcript hash, new extensions (§12.4.1).
			let provisionalContext = MLS.RFC9420.GroupContext(
				version: context.version, cipherSuite: context.cipherSuite,
				groupID: context.groupID, epoch: context.epoch + 1,
				treeHash: try newTree.treeHash(provider),
				confirmedTranscriptHash: context.confirmedTranscriptHash,
				extensions: provisionalExtensions)

			let (pathNodes, derivedCommitSecret) = try newTree.finishCommitPath(
				pathStage,
				groupContext: try provisionalContext.mlsEncoded(),
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
		// the decoded array in `Group.join`.)

		// Frame, sign under the OLD context, chain the transcript.
		let commit = MLS.RFC9420.Commit(proposals: proposalList, path: updatePath)
		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: context.epoch,
			sender: .member(myLeafIndex), authenticatedData: Data(),
			content: .commit(commit))
		let (signedContent, signature) = try MLS.RFC9420.signPublic(
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

		// Seal with OLD-epoch keys (§12.4.1: membership_tag uses the old
		// membership_key).
		let message = try MLS.RFC9420.sealPublic(
			provider, content: framed, signedContent: signedContent,
			signature: signature, confirmationTag: confirmationTag,
			membershipKey: epoch.membershipKey)

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
			blankedNodes: applied.blankedNodes,
			senderIndex: includePath ? myLeafIndex : nil,
			leafCount: newTree.leafCount)
		if let stage {
			newSecretKeys[2 * myLeafIndex.value] = randomness.leafEncryptionSecretKey
			for (node, key) in zip(unfilteredNodeIndices, stage.nodeSecretKeys) {
				newSecretKeys[node] = key
			}
		}

		var updated = self
		updated.context = newContext
		updated.tree = newTree
		updated.epoch = EpochSecrets(retaining: newEpoch)
		updated.secretKeys = newSecretKeys
		updated.interimTranscriptHash = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmedTranscriptHash,
			confirmationTag: confirmationTag)
		updated.resumptionPsks[newContext.epoch] = newEpoch.resumptionPsk
		updated.pruneResumptionPsks(currentEpoch: newContext.epoch)
		try updated.installMessageSecrets(
			context: newContext, senderDataSecret: newEpoch.senderDataSecret,
			encryptionSecret: newEpoch.encryptionSecret, tree: newTree, provider)

		let welcome = try makeWelcome(
			provider, resolved: resolved, applied: applied, stage: stage,
			newTree: newTree, newContext: newContext,
			confirmationTag: confirmationTag, newEpoch: newEpoch,
			pskIDs: pskIDs, signingKey: signingKey,
			includeRatchetTreeExtension: includeRatchetTreeExtension)

		return CommitOutput(group: updated, commit: message, welcome: welcome)
	}

	/// §12.4.1's Welcome tail: GroupInfo (signed, then sealed under the
	/// welcome key/nonce), and per added member a `GroupSecrets` carrying
	/// the joiner secret, the path secret at the least common ancestor
	/// with the committer, and the commit's PSK ids in proposal order —
	/// HPKE-sealed to the member's `init_key` with the *encrypted*
	/// GroupInfo as context (the splice-prevention binding `join`'s
	/// decrypt side documents), which is why the GroupInfo must be sealed
	/// first.
	private func makeWelcome(
		_ provider: any MLS.CipherSuiteProvider,
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
			confirmationTag: confirmationTag, signer: myLeafIndex,
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
			from: 2 * myLeafIndex.value, leafCount: newTree.leafCount
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

			let groupSecrets = MLS.RFC9420.GroupSecrets(
				joinerSecret: newEpoch.joinerSecret, pathSecret: pathSecret,
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
