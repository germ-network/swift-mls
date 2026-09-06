import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeMath
import SecretBytes

extension MLS.RFC9420.Group {

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
		let senderDataSecret: SecretBytes
		let signatureKeys: [MLS.LeafIndex: MLS.SignaturePublicKey]
		var tree: MLS.KeySchedule.ConsumingSecretTree
		/// **Remote** senders' ratchet chains only (slice 3b). A local
		/// membership's own send ratchet lives on its `Membership.ownSend`, seeded
		/// from `tree` but never cached back here — so this map never keys a local
		/// leaf, and two local memberships never share a send position.
		var chains: [ChainKey: MLS.KeySchedule.RatchetChain] = [:]

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
		let advanced: MLS.KeySchedule.RatchetChain?
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
	/// Build — without installing — the new epoch's message-secret store and
	/// Exporter Tree from the new epoch's secrets and the new tree. `static` by
	/// design (D17 §4, L-4): it derives the delta's retained message state from
	/// the new epoch's inputs alone and *cannot* read the live group's
	/// (more-consumed) message-secret state, which is exactly the §4 invariant
	/// that lets a `PendingCommit` hold these standalone and `apply(onto:)`
	/// compose them onto a live group. Callers that install directly
	/// (`installMessageSecrets`) prune afterwards; the delta path prunes at
	/// `apply(onto:)` instead.
	static func makeEpochMessageState(
		context: MLS.RFC9420.GroupContext,
		senderDataSecret: some ContiguousBytes, encryptionSecret: some ContiguousBytes,
		applicationExportSecret: some ContiguousBytes,
		tree: MLS.TreeKEM.RatchetTree,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> (store: MessageSecrets, exporter: MLS.KeySchedule.ExporterTree) {
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
		let store = try MessageSecrets(
			groupContext: context,
			// Held zeroizing for the epoch's life: `senderDataSecret` seeds
			// every message's sender-data key, so it is retained the whole
			// epoch, not consumed in-flight.
			senderDataSecret: SecretBytes(bytes: senderDataSecret),
			signatureKeys: signatureKeys,
			tree: MLS.KeySchedule.ConsumingSecretTree(
				encryptionSecret: encryptionSecret, leafCount: tree.leafCount))
		// draft-ietf-mls-extensions-08 §4.4: build this epoch's Exporter Tree from
		// application_export_secret and hold the *consuming tree* — never the raw
		// root. The first export splits and deletes the root, and each export
		// deletes its component's root-to-leaf path (RFC 9420 §9.2, which §4.4
		// invokes); retaining the root would re-derive consumed components and
		// defeat forward secrecy. Matches the deployed fork, which holds
		// `ExporterTree(SecretTree)`, not the root.
		let exporter = try MLS.KeySchedule.ExporterTree(
			applicationExportSecret: applicationExportSecret)
		return (store, exporter)
	}

	/// Install the new epoch's message state into `self` and prune to the
	/// retention window. Only `create` and `join` install directly (they build a
	/// group, not a delta); every commit — receive and send alike — composes the
	/// new epoch via the D17 delta's `apply(onto:)` instead.
	mutating func installMessageSecrets(
		context: MLS.RFC9420.GroupContext,
		senderDataSecret: some ContiguousBytes, encryptionSecret: some ContiguousBytes,
		applicationExportSecret: some ContiguousBytes,
		tree: MLS.TreeKEM.RatchetTree,
		_ provider: any MLS.CipherSuiteProvider
	) throws {
		let (store, exporter) = try Self.makeEpochMessageState(
			context: context, senderDataSecret: senderDataSecret,
			encryptionSecret: encryptionSecret,
			applicationExportSecret: applicationExportSecret, tree: tree, provider)
		messageSecrets[context.epoch] = store
		let depth = UInt64(retention.messageSecretsDepth)
		let floor = context.epoch >= depth ? context.epoch - depth : 0
		messageSecrets = messageSecrets.filter { $0.key >= floor }
		// Single-epoch (past epochs' seeds aren't retained), so this drops any
		// prior epoch's tree.
		exporterTrees = [context.epoch: exporter]
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
		var chain: MLS.KeySchedule.RatchetChain
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
			// Surface the mechanism's tree-exhaustion as this layer's public
			// replay error, preserving the pre-relocation contract: a §9.2
			// replay of a fully-consumed subtree is `generationAlreadyConsumed`,
			// matchable by callers, not the `package` `SecretTreeError` leaking
			// out of `unprotect` as an opaque error.
			let leafSecret: SecretBytes
			do {
				leafSecret = try secrets.tree.consumeLeafSecret(for: leaf, provider)
			} catch MLS.KeySchedule.SecretTreeError.subtreeExhausted {
				throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
					generation: 0)
			}
			let handshakeChain = MLS.KeySchedule.RatchetChain(
				headGeneration: 0,
				headSecret: try MLS.KeySchedule.handshakeRatchetSecret(
					provider, leafSecret: leafSecret))
			let applicationChain = MLS.KeySchedule.RatchetChain(
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
				cached.key.withUnsafeBytes { Data($0) }, cached.nonce,
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
				advanced.skipped[g] = (try SecretBytes(bytes: step.key), step.nonce)
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

	/// Key/nonce for the membership at `membershipIndex`'s next own send in
	/// `epoch`, advancing that membership's own ratchet (slice 3b). The send side
	/// derives through the same §9.2 secret tree the receive side uses — one
	/// authority, no drift — but the own leaf's chain lives on the `Membership`,
	/// not in the shared `GroupCore` store, so two local memberships never share a
	/// send position and each spends its own generation.
	///
	/// Consumption is immediate (our own send cannot "fail to decrypt"), and the
	/// generation returned is the one that was spent. Send is strictly sequential
	/// — the requested generation is always the chain head — so this walks exactly
	/// one step and never caches a skipped key.
	mutating func deriveOwnSendKey(
		membershipIndex: Int, epoch: UInt64, isHandshake: Bool,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> (key: Data, nonce: Data, generation: UInt32) {
		// A member frames only in its current epoch; a tag from any other epoch
		// is stale state to discard, never a ratchet to resume — this is the
		// structural bar against carrying a generation across an epoch (§9.1).
		if memberships[membershipIndex].ownSend.epoch != epoch {
			memberships[membershipIndex].ownSend = MLS.RFC9420.Membership.OwnSendState(
				epoch: epoch)
		}
		let generation = memberships[membershipIndex].ownSend.nextGeneration(
			isHandshake: isHandshake)
		guard generation != .max else {
			throw MLS.RFC9420.GroupError.sendGenerationExhausted
		}

		// Seed both own ratchets together from a single consumed leaf secret on
		// the first send this epoch (§9.1: one leaf_secret forks into both). The
		// leaf secret is consumed from — and deleted in — the shared `GroupCore`
		// tree; the resulting chains are held on the membership.
		if memberships[membershipIndex].ownSend.handshakeChain == nil {
			guard var store = core.messageSecrets[epoch] else {
				throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
					epoch: epoch)
			}
			let leaf = memberships[membershipIndex].leafIndex
			let leafSecret: SecretBytes
			do {
				leafSecret = try store.tree.consumeLeafSecret(for: leaf, provider)
			} catch MLS.KeySchedule.SecretTreeError.subtreeExhausted {
				throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
					generation: 0)
			}
			core.messageSecrets[epoch] = store
			memberships[membershipIndex].ownSend.handshakeChain =
				MLS.KeySchedule.RatchetChain(
					headGeneration: 0,
					headSecret: try MLS.KeySchedule.handshakeRatchetSecret(
						provider, leafSecret: leafSecret))
			memberships[membershipIndex].ownSend.applicationChain =
				MLS.KeySchedule.RatchetChain(
					headGeneration: 0,
					headSecret: try MLS.KeySchedule.applicationRatchetSecret(
						provider, leafSecret: leafSecret))
		}

		var chain =
			isHandshake
			? memberships[membershipIndex].ownSend.handshakeChain!
			: memberships[membershipIndex].ownSend.applicationChain!
		// generation == chain.headGeneration by construction (sequential send).
		guard let headSecret = chain.headSecret else {
			throw MLS.RFC9420.GroupError.generationAlreadyConsumed(
				generation: generation)
		}
		let step = try MLS.KeySchedule.ratchetStep(
			provider, secret: headSecret, generation: generation)
		// Advance the chain (the sole send position): its new head IS the next
		// generation. `generation != .max` was guarded above, so the head never
		// wraps and the chain never retires.
		chain.headGeneration = generation + 1
		chain.headSecret = step.nextSecret
		if isHandshake {
			memberships[membershipIndex].ownSend.handshakeChain = chain
		} else {
			memberships[membershipIndex].ownSend.applicationChain = chain
		}
		return (step.key, step.nonce, generation)
	}
}

extension MLS.RFC9420.Group {
	public enum UnprotectedContent: Sendable {
		case application(Data)
		/// The authenticated proposal, ready for `ProposalStore.insert`.
		/// `unprotect` has already checked its AEAD and signature, so it is a
		/// `VerifiedProposal` — the store's non-fabricable capability — and the
		/// ref binds the framed content, which `insert` derives now rather than
		/// this call computing it up front.
		case proposal(MLS.RFC9420.VerifiedProposal)
		/// A commit needs the full processing pipeline. This hands back the
		/// authenticated frame for inspection only: the processing core is gated
		/// on a `VerifiedCommit` minted internally (D17 §2.1, M-1), so a raw
		/// `AuthenticatedContent` cannot be re-applied through the public API, and
		/// a bare `unprotect` has already consumed the ratchet. To *apply* a
		/// private-framed commit, route by `wireFormat`/`contentType` and call
		/// `validating(commit:)` on the `PrivateMessage` (then `apply(onto:)`)
		/// instead of `unprotect`.
		case commit(MLS.RFC9420.AuthenticatedContent)
	}

	public struct Unprotected: Sendable {
		/// The leaf that framed this message — **a leaf in `epoch`'s roster, not
		/// necessarily the current one.** A `PrivateMessage` may come from any
		/// epoch still within the retention window, and a leaf index is not stable
		/// across epochs: removing a member blanks its leaf, and the next Add fills
		/// the leftmost empty leaf (RFC 9420 §12.1.1), so a later member can come to
		/// occupy the same index. Resolving `sender` against the *current* `tree`
		/// would then bind a retained-epoch message to whoever holds that leaf now,
		/// not the member who framed it.
		///
		/// **MUST**: resolve `sender` to an identity only within `epoch`'s roster.
		/// `senderSignatureKey` is that epoch's verified signing key for this leaf —
		/// the key the framing signature was actually checked against — so key
		/// identity off it directly, or compare it to the identity you expect,
		/// rather than reading the current tree. The library does not retain
		/// past-epoch credentials, so an application that needs the credential (not
		/// just the key) must keep its own epoch → roster history.
		public let sender: MLS.LeafIndex
		/// The epoch this message was framed in and decrypted against — the epoch
		/// whose roster `sender` indexes. Also readable before `unprotect` as
		/// `PrivateMessage.epoch`; surfaced here so attribution is epoch-bound
		/// without a second lookup.
		public let epoch: UInt64
		/// The signing key the framing signature was verified against: `epoch`'s
		/// frozen `signature_key` for `sender`'s leaf. Epoch-bound identity — two
		/// members occupying one leaf index in different epochs have different keys
		/// here, so this distinguishes them where the bare leaf index cannot.
		public let senderSignatureKey: MLS.SignaturePublicKey
		public let authenticatedData: Data
		public let content: UnprotectedContent
	}

	/// Send an application message in the current epoch. Mutating: the
	/// own application ratchet advances (RFC 9420 §9's "senders MUST NOT
	/// reuse a generation"), which is also why callers must treat a
	/// `Group` value as the single sending authority — copies of a value
	/// type fork the ratchet, and the 4-byte reuse guard is the RFC's own
	/// mitigation for exactly that, not a license for it.
	///
	/// Sends as the sole local membership; `ambiguousMembership` at N ≠ 1, where
	/// `protect(as:)` names the sending membership.
	public mutating func protect(
		_ provider: any MLS.CipherSuiteProvider,
		applicationData: Data,
		authenticatedData: Data = Data(),
		signingKey: MLS.SignatureSecretKey,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int = 0
	) throws -> MLS.RFC9420.PrivateMessage {
		try protectContent(
			membershipIndex: try soleMembershipIndex(), provider,
			content: .application(applicationData),
			authenticatedData: authenticatedData, signingKey: signingKey,
			reuseGuard: reuseGuard, paddingLength: max(0, paddingLength)
		).message
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

	/// Returns the signature alongside the sealed message — not needed by
	/// `protect`'s own callers, but `proposeUpdate` computes a `ProposalRef`
	/// over exactly this framing, and the ref must be built from the SAME
	/// signature that sealed the message, not a second one: three of the
	/// five supported suites randomize ECDSA, so signing the same content
	/// twice produces two different signatures, and a ref built from the
	/// wrong one would never match what a receiver's own `unprotect` +
	/// `ProposalStore.insert` computes.
	mutating func protectContent(
		membershipIndex: Int,
		_ provider: any MLS.CipherSuiteProvider,
		content: MLS.RFC9420.Content,
		authenticatedData: Data,
		signingKey: MLS.SignatureSecretKey,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> (message: MLS.RFC9420.PrivateMessage, signature: MLS.Signature) {
		let epochNumber = context.epoch
		let leaf = memberships[membershipIndex].leafIndex
		guard let secrets = core.messageSecrets[epochNumber] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
				epoch: epochNumber)
		}
		let isHandshake = content.contentType != .application

		// Spend this membership's own generation (slice 3b) — seeded from and
		// consuming the shared secret tree, advanced on the membership.
		let (key, nonce, generation) = try deriveOwnSendKey(
			membershipIndex: membershipIndex, epoch: epochNumber,
			isHandshake: isHandshake, provider)

		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: epochNumber,
			sender: .member(leaf), authenticatedData: authenticatedData,
			content: content)
		// Split, rather than the one-shot `protectPrivate`, purely to keep
		// the signature: behaviorally identical to `protectPrivate`, which
		// does exactly these two calls internally.
		let (_, signature) = try MLS.RFC9420.signPrivate(
			provider, content: framed, groupContext: secrets.groupContext,
			signingKey: signingKey)
		let message = try MLS.RFC9420.sealPrivate(
			provider, keySource: OneShotKey(key: key, nonce: nonce),
			content: framed, signature: signature, generation: generation,
			confirmationTag: nil, senderDataSecret: secrets.senderDataSecret,
			reuseGuard: reuseGuard, paddingLength: paddingLength)
		return (message, signature)
	}

	/// The commit-authoring counterpart to `protectContent`: seals a
	/// commit's `FramedContent` — already framed, signed, and
	/// transcript-chained by `committing` under the OLD epoch's
	/// `wireFormat: .privateMessage` (see `signPrivate`) — as a
	/// `PrivateMessage`, advancing the committer's own handshake ratchet
	/// exactly as `protectContent` advances it for a proposal. Takes
	/// `oldEpoch` explicitly: a commit is sent in the epoch it closes, and
	/// `committing` seals on a copy of the pre-commit group whose current epoch
	/// IS `oldEpoch` (the successor is a not-yet-applied delta).
	mutating func sealHandshakeCommit(
		membershipIndex: Int,
		_ provider: any MLS.CipherSuiteProvider,
		epoch oldEpoch: UInt64,
		framed: MLS.RFC9420.FramedContent,
		signature: MLS.Signature,
		confirmationTag: MLS.ConfirmationTag,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> MLS.RFC9420.PrivateMessage {
		guard let secrets = core.messageSecrets[oldEpoch] else {
			throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(epoch: oldEpoch)
		}
		// Spend the committer membership's own handshake generation in the old
		// epoch (slice 3b) — exactly as `protectContent` spends it for a proposal.
		let (key, nonce, generation) = try deriveOwnSendKey(
			membershipIndex: membershipIndex, epoch: oldEpoch, isHandshake: true,
			provider)

		return try MLS.RFC9420.sealPrivate(
			provider, keySource: OneShotKey(key: key, nonce: nonce),
			content: framed, signature: signature, generation: generation,
			confirmationTag: confirmationTag,
			senderDataSecret: secrets.senderDataSecret,
			reuseGuard: reuseGuard, paddingLength: paddingLength)
	}

	/// What `openPrivate` recovers from a `PrivateMessage`: the authenticated
	/// frame, the sender's leaf and `epoch`-bound verified key, and the ratchet
	/// consumption to commit — or discard, for a read-only peek.
	struct OpenedPrivate {
		let authenticated: MLS.RFC9420.AuthenticatedContent
		let senderLeaf: MLS.LeafIndex
		let epoch: UInt64
		let senderSignatureKey: MLS.SignaturePublicKey
		let pending: PendingConsumption
	}

	/// The shared private-receive core (D17 §1.1): route by
	/// group/epoch/content-type, open the sender data, refuse our own leaf,
	/// derive the message key, and open the content AEAD + framing signature —
	/// **without committing the ratchet consumption**. `mutating` only for the
	/// one-time per-leaf chain bootstrap (§9's leaf-secret fork into the handshake
	/// and application ratchets); the generation consumption is
	/// returned as `pending` for the caller to `commitConsumption` (the
	/// consuming entries) or discard (`peeking`). A failed decrypt leaves every
	/// ratchet exactly where it was.
	mutating func openPrivate(
		_ provider: any MLS.CipherSuiteProvider,
		_ message: MLS.RFC9420.PrivateMessage
	) throws -> OpenedPrivate {
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
		// Own-message guard = sender ∈ any local membership's leaf (D18 §3), not
		// just `memberships[0]`: at N > 1 a message framed by a non-sole local leaf
		// is still this device's own, and receiving it must fail the same clean way
		// as the sole-membership case rather than falling through to a ratchet
		// derivation that only fails later (its leaf secret was spent by that
		// membership's own send).
		guard !memberships.contains(where: { $0.leafIndex == senderData.leafIndex })
		else {
			throw MLS.RFC9420.GroupError.cannotDecryptOwnMessage
		}
		// `epoch`'s frozen signing key for the sender's leaf: the key the framing
		// signature is verified against below, and the epoch-bound identity
		// surfaced on `Unprotected`. Checked BEFORE deriving any message key — a
		// leaf blank in the framing epoch can never authenticate, so a forged
		// `sender_data` naming a blank leaf must not make the receiver bootstrap
		// and walk that leaf's ratchet.
		guard let senderSignatureKey = secrets.signatureKeys[senderData.leafIndex]
		else {
			throw MLS.RFC9420.GroupError.blankSenderLeaf
		}
		let (key, nonce, pending) = try deriveMessageKey(
			epoch: message.epoch, leaf: senderData.leafIndex,
			generation: senderData.generation,
			isHandshake: message.contentType != .application, provider)

		let authenticated = try MLS.RFC9420.openPrivateContent(
			provider, message: message, senderData: senderData, key: key,
			nonce: nonce, groupContext: secrets.groupContext,
			// The verified key IS the returned key, by construction: verification
			// uses the exact key surfaced on `Unprotected`, so the vouched-for key
			// and the one that authenticated the frame cannot decouple.
			verificationKey: { _ in senderSignatureKey })
		return OpenedPrivate(
			authenticated: authenticated, senderLeaf: senderData.leafIndex,
			epoch: message.epoch, senderSignatureKey: senderSignatureKey,
			pending: pending)
	}

	/// Build the `Unprotected` view of an opened frame (D17). `authenticatedData`
	/// comes from the wire message; the epoch-bound `sender`/`senderSignatureKey`
	/// come from `opened`.
	static func makeUnprotected(
		_ opened: OpenedPrivate, authenticatedData: Data
	) -> Unprotected {
		let content: UnprotectedContent
		switch opened.authenticated.content.content {
		case .application(let data):
			content = .application(data)
		case .proposal:
			content = .proposal(
				MLS.RFC9420.VerifiedProposal(verified: opened.authenticated))
		case .commit:
			content = .commit(opened.authenticated)
		}
		return Unprotected(
			sender: opened.senderLeaf, epoch: opened.epoch,
			senderSignatureKey: opened.senderSignatureKey,
			authenticatedData: authenticatedData, content: content)
	}

	/// Receive a `PrivateMessage` as a transition (D17 §1.1). Decrypting a
	/// private message advances a ratchet — a consumption §9.2 requires be
	/// deleted — so this is a `Transition`: the `group` is the post-consumption
	/// live state to adopt (and persist), the `output` is the decrypted
	/// `Unprotected`. For a commit or proposal, route to `validating(commit:)` /
	/// `verifying(proposal:)` to also get the delta / `VerifiedProposal`; this
	/// entry decrypts every content type but hands the commit back as inspection
	/// data (M5 — `.commit` is not applicable). A failed decrypt returns nothing
	/// and consumes nothing.
	public func unprotecting(
		_ provider: any MLS.CipherSuiteProvider,
		_ message: MLS.RFC9420.PrivateMessage
	) throws -> MLS.RFC9420.Transition<Unprotected> {
		var group = self
		let opened = try group.openPrivate(provider, message)
		group.commitConsumption(opened.pending)
		return MLS.RFC9420.Transition(
			group: group,
			output: Self.makeUnprotected(
				opened, authenticatedData: message.authenticatedData))
	}

	/// Read-only decrypt (#31): recover a `PrivateMessage`'s content **without**
	/// advancing any ratchet — nothing to adopt, so it returns a plain
	/// `Unprotected`, never a `Transition`. Application content only: a handshake
	/// is refused (`wrongContentType`), so a peek can never yield an applicable
	/// commit (M5). The consumption the decrypt would make is discarded, so the
	/// same generation still opens for real via `unprotecting` afterward.
	public func peeking(
		_ provider: any MLS.CipherSuiteProvider,
		_ message: MLS.RFC9420.PrivateMessage
	) throws -> Unprotected {
		guard message.contentType == .application else {
			throw MLS.RFC9420.GroupError.wrongContentType(message.contentType)
		}
		var group = self  // consumption + bootstrap land here and are discarded
		let opened = try group.openPrivate(provider, message)
		return Self.makeUnprotected(
			opened, authenticatedData: message.authenticatedData)
	}

	/// Mutating convenience over `unprotecting` for the application-message receive
	/// hot path: it adopts the transition's post-consumption `group` into `self`
	/// and returns the decrypted content in one step. It has none of the
	/// deferred-apply / pending shape a handshake receive carries — the ratchet
	/// consumption is applied in place — so its only obligation is the one every
	/// mutating operation carries: persist the mutated group before acting on the
	/// plaintext (spec/snapshot.md §6), exactly as `protect` does on the send side.
	/// `unprotecting` is the two-step form for a caller that must interpose that
	/// persist explicitly.
	@discardableResult
	public mutating func unprotect(
		_ provider: any MLS.CipherSuiteProvider,
		message: MLS.RFC9420.PrivateMessage
	) throws -> Unprotected {
		let transition = try unprotecting(provider, message)
		self = transition.group
		return transition.output
	}
}
