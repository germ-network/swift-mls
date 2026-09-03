import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeMath

extension MLS.RFC9420.Group {
	/// The §9.2-conforming secret-tree state: a map of *live* node
	/// secrets, seeded with `[root: encryption_secret]`, that consumes as
	/// it descends. Deriving a leaf deletes every path node it passes and
	/// caches every copath sibling — so after the first derivation the
	/// root (the epoch's `encryption_secret` itself, per §9.2's worked
	/// example) no longer exists in any representation, and later leaves
	/// are reached from retained siblings. The stateless
	/// `MLS.KeySchedule.leafSecret` walks from the root every time and
	/// therefore cannot be the store; it remains the vector-pinned oracle
	/// this walker is differentially tested against.
	struct ConsumingSecretTree: Sendable {
		var nodeSecrets: [UInt32: Data]
		let leafCount: MLS.LeafCount

		init(encryptionSecret: Data, leafCount: MLS.LeafCount) {
			self.leafCount = leafCount
			self.nodeSecrets = [
				MLS.TreeMath.root(leafCount: leafCount): encryptionSecret
			]
		}

		/// Derives (and consumes toward) the leaf's secret. Throws when
		/// the subtree covering this leaf has already been fully consumed
		/// — that is a replay/reuse signal, not a derivation failure.
		mutating func consumeLeafSecret(
			for leafIndex: MLS.LeafIndex,
			_ provider: any MLS.CipherSuiteProvider
		) throws -> Data {
			let leafNode = 2 * leafIndex.value
			guard leafIndex.value < leafCount.value else {
				throw MLS.CryptoError.invalidKey
			}
			if let ready = nodeSecrets.removeValue(forKey: leafNode) {
				return ready
			}
			// Climb until a held ancestor, then split back down.
			let path =
				[leafNode]
				+ MLS.TreeMath.directPath(from: leafNode, leafCount: leafCount)
				.map(\.path)
			guard
				let heldLevel = path.firstIndex(where: {
					nodeSecrets[$0] != nil
				}), heldLevel > 0
			else {
				throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
					generation: 0)
			}
			var nodeIndex = path[heldLevel]
			var secret = nodeSecrets.removeValue(forKey: nodeIndex)!
			for level in stride(from: heldLevel - 1, through: 0, by: -1) {
				let child = path[level]
				let (left, right) = try MLS.KeySchedule.splitTreeNode(
					provider, secret: secret)
				let goingLeft = MLS.TreeMath.left(nodeIndex) == child
				// Cache the sibling we are not taking; the taken side is
				// consumed by the descent itself.
				let sibling =
					goingLeft
					? MLS.TreeMath.right(nodeIndex)
					: MLS.TreeMath.left(nodeIndex)
				nodeSecrets[sibling] = goingLeft ? right : left
				secret = goingLeft ? left : right
				nodeIndex = child
			}
			return secret
		}
	}

	/// One sender's ratchet (handshake or application): the head secret,
	/// its generation, and the bounded cache of skipped-but-unconsumed
	/// (key, nonce) pairs — §15.3's three policies live in
	/// `RetentionPolicy`, and the *ratchet secrets* skipped over are
	/// consumed and deleted per §9.2 even though their derived keys are
	/// kept.
	struct RatchetChain: Sendable {
		var headGeneration: UInt32
		/// nil once the chain is retired (head consumed with nothing
		/// ahead retainable).
		var headSecret: Data?
		var skipped: [UInt32: (key: Data, nonce: Data)] = [:]
	}

	/// Everything unprotecting a *retained* epoch's `PrivateMessage` needs
	/// — frozen, because the live group has moved on: the group context
	/// this epoch's signatures bind, each member's signature key as of
	/// this epoch, and the consuming message-secret state. Deliberately
	/// NOT the epoch's `init_secret` or key-schedule tail (§9.2 requires
	/// those gone once the next epoch exists), and not its `membership_key`
	/// either — so a retained epoch's `PublicMessage` cannot be verified.
	///
	/// "Frozen" rather than "snapshot": `Snapshot` is the glossary term for
	/// a whole group's persisted state (`spec/snapshot.md`), which this is
	/// one section of.
	struct MessageSecrets: Sendable {
		let groupContext: MLS.RFC9420.GroupContext
		let senderDataSecret: Data
		let signatureKeys: [MLS.LeafIndex: MLS.SignaturePublicKey]
		var tree: ConsumingSecretTree
		var chains: [ChainKey: RatchetChain] = [:]
		var ownNextGeneration: (handshake: UInt32, application: UInt32) = (0, 0)

		struct ChainKey: Hashable, Sendable {
			let leaf: MLS.LeafIndex
			let isHandshake: Bool
		}
	}

	/// What a derivation wants to change, applied only after the content
	/// AEAD actually opens. §9.2's consumption trigger is "(successfully)
	/// decrypt" — and the parenthetical is a security boundary, not
	/// pedantry: sender data is sealed under a secret every member holds,
	/// so a malicious member can forge sender data naming any (victim,
	/// generation) over garbage ciphertext. Consuming on derivation would
	/// let that forgery permanently destroy the victim's real message.
	struct PendingConsumption {
		let epoch: UInt64
		let chain: MessageSecrets.ChainKey
		/// nil: the key came from the skipped cache (remove it);
		/// non-nil: the chain advances to this state.
		let advanced: RatchetChain?
		let consumedGeneration: UInt32
	}

	/// A `MessageKeySource` that hands back one already-derived (key,
	/// nonce) regardless of what is asked for — the send side has already
	/// picked its own generation via `deriveMessageKey`, so `sealPrivate`'s
	/// key-lookup callback is a formality here, not a second derivation.
	struct OneShotKey: MLS.RFC9420.MessageKeySource {
		let key: Data
		let nonce: Data
		func key(
			for leafIndex: MLS.LeafIndex, generation: UInt32,
			contentType: MLS.ContentType
		) throws -> (key: Data, nonce: Data) { (key, nonce) }
	}
}

extension MLS.RFC9420.Group {
	/// Builds and installs the message-secret state for a newly entered
	/// epoch, and prunes retired epochs to
	/// `retention.messageSecretsDepth`. Called by every epoch-entering
	/// path (`create`, `join`, `processing`, `committing`).
	mutating func installMessageSecrets(
		context: MLS.RFC9420.GroupContext,
		senderDataSecret: Data, encryptionSecret: Data,
		tree: MLS.TreeKEM.RatchetTree,
		_ provider: any MLS.CipherSuiteProvider
	) throws {
		var signatureKeys: [MLS.LeafIndex: MLS.SignaturePublicKey] = [:]
		// Two decodes per touched leaf: commit processing already decoded the
		// added/updated/committer LeafNodes for validation, and this decodes
		// every non-blank leaf again purely for `signatureKey` -- plus unchanged
		// leaves are re-decoded each epoch though their key is stable. Kept eager
		// because the snapshot persists decoded keys (spec/snapshot.md 4.3
		// `signature_keys`), not leaf bytes, so a future incremental build (carry
		// the prior epoch's map forward, patch only the commit's changed leaves)
		// is a pure in-memory change needing no snapshot-format change.
		for (leafIndex, record) in tree.nonBlankLeaves() {
			signatureKeys[leafIndex] =
				try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded).signatureKey
		}
		messageSecrets[context.epoch] = MessageSecrets(
			groupContext: context,
			senderDataSecret: senderDataSecret,
			signatureKeys: signatureKeys,
			tree: ConsumingSecretTree(
				encryptionSecret: encryptionSecret, leafCount: tree.leafCount))
		let depth = UInt64(retention.messageSecretsDepth)
		let floor = context.epoch >= depth ? context.epoch - depth : 0
		messageSecrets = messageSecrets.filter { $0.key >= floor }
	}

	/// Key/nonce for `(leaf, generation, kind)` in `epoch`, plus the
	/// consumption to apply on success. The §15.3 bounds run here, before
	/// any derivation loop — the RFC's own DoS is a forged
	/// `generation = 0xffffffff` forcing billions of derivations.
	mutating func deriveMessageKey(
		epoch: UInt64, leaf: MLS.LeafIndex, generation: UInt32,
		isHandshake: Bool, _ provider: any MLS.CipherSuiteProvider
	) throws -> (key: Data, nonce: Data, pending: PendingConsumption) {
		guard var secrets = messageSecrets[epoch] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(epoch: epoch)
		}
		let chainKey = MessageSecrets.ChainKey(leaf: leaf, isHandshake: isHandshake)
		var chain: RatchetChain
		if let existing = secrets.chains[chainKey] {
			chain = existing
		} else {
			// §9.1: one leaf_secret forks into BOTH the handshake and
			// application ratchets (`SecretTree.swift`'s own doc comment:
			// "two independent ratchets ... hang off each leaf"). Bootstrap
			// both chains together on whichever is touched first --
			// `consumeLeafSecret` derives and deletes the tree's leaf_secret
			// in one shot, so calling it a second time for this leaf, from
			// the other ratchet's own first touch, would find nothing left
			// to derive from.
			let leafSecret = try secrets.tree.consumeLeafSecret(for: leaf, provider)
			let handshakeChain = RatchetChain(
				headGeneration: 0,
				headSecret: try MLS.KeySchedule.handshakeRatchetSecret(
					provider, leafSecret: leafSecret))
			let applicationChain = RatchetChain(
				headGeneration: 0,
				headSecret: try MLS.KeySchedule.applicationRatchetSecret(
					provider, leafSecret: leafSecret))
			secrets.chains[MessageSecrets.ChainKey(leaf: leaf, isHandshake: true)] =
				handshakeChain
			secrets.chains[MessageSecrets.ChainKey(leaf: leaf, isHandshake: false)] =
				applicationChain
			chain = isHandshake ? handshakeChain : applicationChain
			messageSecrets[epoch] = secrets
		}

		// Below the head: either a retained skipped key, or consumed.
		if generation < chain.headGeneration {
			guard let cached = chain.skipped[generation] else {
				throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
					generation: generation)
			}
			return (
				cached.key, cached.nonce,
				PendingConsumption(
					epoch: epoch, chain: chainKey, advanced: nil,
					consumedGeneration: generation)
			)
		}

		guard let headSecret = chain.headSecret else {
			throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
				generation: generation)
		}
		let jump = generation - chain.headGeneration
		guard jump <= UInt32(retention.maxForwardJump) else {
			throw MLS.RFC9420.GroupError.generationJumpTooLarge(
				requested: generation, head: chain.headGeneration)
		}

		// Walk forward, caching skipped keys (bounded) and deleting the
		// skipped ratchet secrets by construction — each loop iteration's
		// secret exists only in this frame.
		var advanced = chain
		var secret = headSecret
		var stepped: (key: Data, nonce: Data)?
		for g in chain.headGeneration...generation {
			let step = try MLS.KeySchedule.ratchetStep(
				provider, secret: secret, generation: g)
			if g == generation {
				stepped = (step.key, step.nonce)
			} else {
				advanced.skipped[g] = (step.key, step.nonce)
			}
			secret = step.nextSecret
		}
		guard advanced.skipped.count <= retention.maxSkippedKeysPerSender else {
			throw MLS.RFC9420.GroupError.tooManySkippedKeys(leaf: leaf)
		}
		advanced.headGeneration = generation &+ 1
		advanced.headSecret = generation == .max ? nil : secret
		guard let result = stepped else {
			// Unreachable: the loop always executes its final iteration.
			throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
				generation: generation)
		}
		return (
			result.key, result.nonce,
			PendingConsumption(
				epoch: epoch, chain: chainKey, advanced: advanced,
				consumedGeneration: generation)
		)
	}

	mutating func commitConsumption(_ pending: PendingConsumption) {
		guard var secrets = messageSecrets[pending.epoch] else { return }
		if let advanced = pending.advanced {
			secrets.chains[pending.chain] = advanced
		} else {
			secrets.chains[pending.chain]?.skipped[pending.consumedGeneration] = nil
		}
		messageSecrets[pending.epoch] = secrets
	}
}

extension MLS.RFC9420.Group {
	public enum UnprotectedContent: Sendable {
		case application(Data)
		/// The framed proposal, ready for `ProposalStore.insert` — the
		/// ref binds the framed `AuthenticatedContent`, which unprotecting
		/// is the last moment anyone holds it, so `insert` is what derives
		/// it now rather than this call computing it up front.
		case proposal(MLS.RFC9420.AuthenticatedContent)
		/// A commit needs the full processing pipeline; hand back the
		/// authenticated frame for `processing` to take over.
		case commit(MLS.RFC9420.AuthenticatedContent)
	}

	public struct Unprotected: Sendable {
		public let sender: MLS.LeafIndex
		public let authenticatedData: Data
		public let content: UnprotectedContent
	}

	/// Send an application message in the current epoch. Mutating: the
	/// own application ratchet advances (RFC 9420 §9's "senders MUST NOT
	/// reuse a generation"), which is also why callers must treat a
	/// `Group` value as the single sending authority — copies of a value
	/// type fork the ratchet, and the 4-byte reuse guard is the RFC's own
	/// mitigation for exactly that, not a license for it.
	public mutating func protect(
		_ provider: any MLS.CipherSuiteProvider,
		applicationData: Data,
		authenticatedData: Data = Data(),
		signingKey: MLS.SignatureSecretKey,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int = 0
	) throws -> MLS.RFC9420.PrivateMessage {
		try protectContent(
			provider, content: .application(applicationData),
			authenticatedData: authenticatedData, signingKey: signingKey,
			reuseGuard: reuseGuard, paddingLength: max(0, paddingLength))
	}

	/// Convenience: fresh reuse-guard bytes from the provider.
	public mutating func protect(
		_ provider: any MLS.CipherSuiteProvider,
		applicationData: Data,
		authenticatedData: Data = Data(),
		signingKey: MLS.SignatureSecretKey,
		paddingLength: Int = 0
	) throws -> MLS.RFC9420.PrivateMessage {
		try protect(
			provider, applicationData: applicationData,
			authenticatedData: authenticatedData, signingKey: signingKey,
			reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)),
			paddingLength: paddingLength)
	}

	mutating func protectContent(
		_ provider: any MLS.CipherSuiteProvider,
		content: MLS.RFC9420.Content,
		authenticatedData: Data,
		signingKey: MLS.SignatureSecretKey,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> MLS.RFC9420.PrivateMessage {
		let epochNumber = context.epoch
		guard var secrets = messageSecrets[epochNumber] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
				epoch: epochNumber)
		}
		let isHandshake = content.contentType != .application
		let generation =
			isHandshake
			? secrets.ownNextGeneration.handshake
			: secrets.ownNextGeneration.application
		guard generation != .max else {
			throw MLS.RFC9420.GroupError.sendGenerationExhausted
		}

		// The send side derives through the same consuming store the
		// receive side uses -- one authority, no drift -- but commits its
		// consumption immediately: our own send cannot "fail to decrypt".
		let (key, nonce, pending) = try deriveMessageKey(
			epoch: epochNumber, leaf: myLeafIndex, generation: generation,
			isHandshake: isHandshake, provider)
		commitConsumption(pending)

		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: epochNumber,
			sender: .member(myLeafIndex), authenticatedData: authenticatedData,
			content: content)
		let message = try MLS.RFC9420.protectPrivate(
			provider, keySource: OneShotKey(key: key, nonce: nonce),
			content: framed, groupContext: secrets.groupContext,
			generation: generation, confirmationTag: nil,
			signingKey: signingKey, senderDataSecret: secrets.senderDataSecret,
			reuseGuard: reuseGuard, paddingLength: paddingLength)

		secrets = messageSecrets[epochNumber]!
		if isHandshake {
			secrets.ownNextGeneration.handshake = generation + 1
		} else {
			secrets.ownNextGeneration.application = generation + 1
		}
		messageSecrets[epochNumber] = secrets
		return message
	}

	/// The commit-authoring counterpart to `protectContent`: seals a
	/// commit's `FramedContent` — already framed, signed, and
	/// transcript-chained by `committing` under the OLD epoch's
	/// `wireFormat: .privateMessage` (see `signPrivate`) — as a
	/// `PrivateMessage`, advancing the committer's own handshake ratchet
	/// exactly as `protectContent` advances it for a proposal. Takes
	/// `oldEpoch` explicitly: a commit is sent in the epoch it closes, not
	/// the one `committing` has already installed into `self` by the time
	/// this runs.
	mutating func sealHandshakeCommit(
		_ provider: any MLS.CipherSuiteProvider,
		epoch oldEpoch: UInt64,
		framed: MLS.RFC9420.FramedContent,
		signature: MLS.Signature,
		confirmationTag: MLS.ConfirmationTag,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> MLS.RFC9420.PrivateMessage {
		guard var secrets = messageSecrets[oldEpoch] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(epoch: oldEpoch)
		}
		let generation = secrets.ownNextGeneration.handshake
		guard generation != .max else {
			throw MLS.RFC9420.GroupError.sendGenerationExhausted
		}

		// Same derive-then-immediately-consume rule as `protectContent`:
		// our own send cannot "fail to decrypt".
		let (key, nonce, pending) = try deriveMessageKey(
			epoch: oldEpoch, leaf: myLeafIndex, generation: generation,
			isHandshake: true, provider)
		commitConsumption(pending)

		let message = try MLS.RFC9420.sealPrivate(
			provider, keySource: OneShotKey(key: key, nonce: nonce),
			content: framed, signature: signature, generation: generation,
			confirmationTag: confirmationTag,
			senderDataSecret: secrets.senderDataSecret,
			reuseGuard: reuseGuard, paddingLength: paddingLength)

		secrets = messageSecrets[oldEpoch]!
		secrets.ownNextGeneration.handshake = generation + 1
		messageSecrets[oldEpoch] = secrets
		return message
	}

	/// Receive a `PrivateMessage` — the §9.2-ordered pipeline: route by
	/// group/epoch/content-type before any ratchet is touched, open the
	/// sender data, refuse our own leaf, bound the jump, derive, open the
	/// content AEAD, and only then consume. A failed decrypt leaves every
	/// ratchet exactly where it was.
	public mutating func unprotect(
		_ provider: any MLS.CipherSuiteProvider,
		message: MLS.RFC9420.PrivateMessage
	) throws -> Unprotected {
		guard message.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		guard [.application, .proposal, .commit].contains(message.contentType)
		else {
			throw MLS.RFC9420.GroupError.wrongContentType(message.contentType)
		}
		guard let secrets = messageSecrets[message.epoch] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
				epoch: message.epoch)
		}

		let senderData = try MLS.RFC9420.openSenderData(
			provider, message: message,
			senderDataSecret: secrets.senderDataSecret)
		guard senderData.leafIndex != myLeafIndex else {
			throw MLS.RFC9420.GroupError.cannotDecryptOwnMessage
		}
		let (key, nonce, pending) = try deriveMessageKey(
			epoch: message.epoch, leaf: senderData.leafIndex,
			generation: senderData.generation,
			isHandshake: message.contentType != .application, provider)

		let signatureKeys = secrets.signatureKeys
		let authenticated = try MLS.RFC9420.openPrivateContent(
			provider, message: message, senderData: senderData, key: key,
			nonce: nonce, groupContext: secrets.groupContext,
			verificationKey: { leaf in
				guard let key = signatureKeys[leaf] else {
					throw MLS.RFC9420.GroupError.blankSenderLeaf
				}
				return key
			})
		commitConsumption(pending)

		let content: UnprotectedContent
		switch authenticated.content.content {
		case .application(let data):
			content = .application(data)
		case .proposal:
			content = .proposal(authenticated)
		case .commit:
			content = .commit(authenticated)
		}
		return Unprotected(
			sender: senderData.leafIndex,
			authenticatedData: message.authenticatedData,
			content: content)
	}
}
