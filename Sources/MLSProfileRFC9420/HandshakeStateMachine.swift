import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

// D17 — the handshake state machine expressed in types. Slice 1: the
// `Transition`/`PendingCommit` foundation (the interleaved-consumption fix). The public
// two-step entry point for a public-framed commit is `validating(commit:)`
// (see `CommitProcessing.swift`); private framing, proposals, the send side,
// eviction, and the credential effects arrive in later slices.

extension MLS.RFC9420 {
	/// D12b made structural, with a **lazy** snapshot (D17 §2/H2): a state
	/// advance hands back the live `group` to adopt and the `output` to act on,
	/// and `snapshot()` computes the persisted form on demand — so a receive
	/// path that produces many transitions does not pay the snapshot encoding
	/// for each. The three are obtainable only together, which is what keeps
	/// outputs from separating from the state that must be persisted with them.
	///
	/// `~Copyable` when `Output` is (a `PendingCommit` output makes the whole
	/// transition linear); an ordinary value when `Output` is copyable.
	///
	/// Read `group` first (it is `Copyable`); `takeOutput()` then consumes the
	/// transition to hand back the `output` — a transition is consumed exactly
	/// once. That accessor, not `@frozen`, is how a `~Copyable` `output` (e.g. a
	/// `PendingCommit`) crosses a module boundary: a non-frozen public type's
	/// stored property cannot be partially consumed by another module, and this
	/// type deliberately makes no `@frozen` layout promise.
	public struct Transition<Output: ~Copyable & Sendable>: ~Copyable, Sendable {
		/// The state to adopt. Adopting it and persisting `snapshot()` together
		/// is a MUST-level contract (D17 §3) — the type cannot force it.
		public let group: Group
		public let output: Output

		init(group: Group, output: consuming Output) {
			self.group = group
			self.output = output
		}

		/// The persisted form, computed on demand. Persist it atomically with
		/// adopting `group`.
		public func snapshot() throws -> Group.Snapshot {
			try group.makeSnapshot()
		}

		/// Consume the transition and hand back its `output` — the supported way
		/// to move a `~Copyable` `Output` (e.g. `PendingCommit` / `CommitValidation`)
		/// out to act on it, since a non-frozen public type's stored property
		/// cannot be partially consumed across a module boundary. Read `group`
		/// first; this consumes the transition, so it is called exactly once. For
		/// a `Copyable` `Output`, reading `.output` directly is equivalent.
		public consuming func takeOutput() -> Output {
			output
		}
	}

	/// One effect a commit had, for the application to adjudicate at the seam
	/// between validation and apply. Slice 1 emits only `epochAdvanced`; the
	/// membership and §5.3.1 credential effects (`added`, `credentialReplaced`,
	/// `updated`, `removed`, `selfRemoved`, …) arrive in a later
	/// slice.
	public enum CommitEffect: Sendable, Equatable {
		/// The epoch advanced from `from` to `to`, committed by `committer`.
		case epochAdvanced(from: UInt64, to: UInt64, committer: MLS.LeafIndex)
	}

	/// The effects of one commit, in application order.
	public struct CommitEffects: Sendable, Equatable {
		public let events: [CommitEffect]
		init(_ events: [CommitEffect]) { self.events = events }
	}

	/// The outcome of `validating(commit: PrivateMessage)` (D17 §1.1). Decrypting
	/// the frame spends the sender's handshake generation the moment its AEAD
	/// opens (RFC 9420 §9.2), so **both** arms carry that consumption in the
	/// enclosing `Transition.group` — the entry never throws after a successful
	/// open, and adopting `group` keeps the generation spent whichever arm
	/// results. `~Copyable` because `.pending` is.
	public enum CommitValidation: ~Copyable, Sendable {
		/// Authentic **and** valid: adjudicate `effects`, then `apply(onto:)` the
		/// group you adopted.
		case pending(PendingCommit)
		/// Authentic (framing AEAD + signature) but **not** a valid commit — bad
		/// confirmation tag, an invalid proposal list, and so on. There is nothing
		/// to apply, but the consumption is kept (a replay is rejected). Unlike a
		/// commit the app *declines* to apply, a rejection is not the app's choice;
		/// it is committer misbehaviour the application (RFC 9420 §5.3.1's
		/// Authentication Service) may act on.
		case rejected(CommitRejection)
	}

	/// An authentically framed but invalid private commit (D17 §1.1). `sender` is
	/// a leaf in `epoch`'s roster (not the current tree — the same epoch-bound
	/// attribution `Unprotected` carries); `reason` is the validation error that
	/// rejected it — the thrown error itself (a `GroupError`, `FramingError`, …),
	/// so an app can pattern-match known cases (`Error` refines `Sendable`).
	public struct CommitRejection: Sendable {
		public let sender: MLS.LeafIndex
		public let epoch: UInt64
		public let reason: any Error
	}

	/// Sending a commit (D17 §1.1, table row 33). The committer seals the commit
	/// in the OLD epoch — a private commit spends the next generation of its own
	/// handshake ratchet there (RFC 9420 §12.4.1 + §9.1) — so this is the output
	/// of a `Transition` whose `group` is the old epoch with that generation
	/// consumed: **adopt and persist it before transmitting `message`**, so a
	/// crash-and-resend cannot reuse the generation. The epoch advance is
	/// `pending`, applied only once the Delivery Service affirms this commit over
	/// any competitor — exactly as a receiver applies one (`staleBase` if a
	/// competing commit landed first). `welcome` is transmitted to the added
	/// members at that same moment.
	///
	/// Scope: `pending` is held in memory, not persisted with `group` (a
	/// persisted pending slot is a later change — the interop server carries the
	/// only such slot today). So adopting `group` makes the spent generation
	/// reuse-safe across a crash, but recovering the *epoch advance* across a
	/// crash between transmit and affirmation still needs that slot — a crash
	/// there leaves the committer at the old epoch with no in-hand `pending`.
	public struct SentCommit: ~Copyable, Sendable {
		public let message: MLS.RFC9420.Message
		/// Present iff the commit added members — sent to them once the commit is
		/// affirmed and `pending` is applied.
		public let welcome: MLS.RFC9420.Welcome?
		public let pending: PendingCommit

		/// Consume the `SentCommit` and hand back its `pending` epoch advance —
		/// the supported way to move the `~Copyable` `PendingCommit` out to
		/// `apply` it across a module boundary. Read `message` / `welcome` (both
		/// `Copyable`) first; this consumes the value.
		public consuming func takePending() -> PendingCommit {
			pending
		}
	}

	/// Step 2 of a handshake: a validated epoch **delta**, never a successor
	/// `Group`. `apply(onto:)` composes it onto the *live* group the
	/// application has kept operating on, taking that group's (more-consumed)
	/// retained message-secret stores — so consumption made while the commit
	/// was pending is never rolled back (D17 §4). Non-copyable, and
	/// `apply` is `consuming`: a pending applies at most once, and applying it
	/// onto a group that has moved past its base throws `staleBase` rather than
	/// forking.
	///
	/// The delta fields are `internal`: a `PendingCommit` is produced only by
	/// the library's receive (`validating`/`processing`) and send (`committing`)
	/// paths, never constructed by a caller.
	public struct PendingCommit: ~Copyable, Sendable {
		public let effects: CommitEffects
		/// The **entire** `GroupContext` this delta was validated against;
		/// `apply(onto:)` requires `live.context == base` (D17 §4).
		public let base: GroupContext
		/// The local `Membership` leaf indices this delta was validated against.
		/// `apply(onto:)` requires `live`'s local-membership set to still equal
		/// this (D17 §4 L-2): the delta installs per-membership key material keyed
		/// by leaf index, so composing it onto a changed membership set would
		/// misplace or drop that material. Together with `base`, this is the whole
		/// of what the pending assumes about the group it applies onto.
		let baseMemberships: Set<MLS.LeafIndex>

		// The epoch advance, derivable from the commit and `base` alone —
		// nothing here is read from `base`'s message-secret state (D17 §4's
		// invariant), so composing onto a more-consumed `live` is sound.
		let newContext: GroupContext
		let newTree: MLS.TreeKEM.RatchetTree
		let newEpoch: Group.EpochSecrets
		/// The new-epoch HPKE secret keys **per local membership**, keyed by that
		/// membership's leaf index (slice 4a). Each membership decaps the commit's
		/// path against its own held keys, so the map has one entry per member of
		/// `baseMemberships`; `apply` installs each onto its membership. The keys
		/// were validated to agree on a single `commit_secret` across memberships
		/// before this delta was built.
		let newSecretKeysByLeaf: [MLS.LeafIndex: [UInt32: MLS.HpkeSecretKey]]
		let newInterimTranscriptHash: Data
		let newMessageStore: Group.MessageSecrets
		let newExporterTree: MLS.KeySchedule.ExporterTree
		let newResumptionPsk: SecretBytes

		// The memberwise initializer stays `internal` (the delta fields are
		// internal), so a `PendingCommit` is produced only by the library's
		// receive (`validating`/`processing`) and send (`committing`) paths —
		// never constructed by a caller.

		/// Compose the epoch advance onto `live` (D17 §4). The new-epoch state
		/// comes from the delta; the retained **old**-epoch message-secret
		/// stores and resumption PSKs come from `live` (more consumed than at
		/// validation); `pendingUpdates` is cleared by the epoch advance;
		/// retention pruning runs on the composed result. Throws `staleBase`
		/// unless `live.context == base`, and `membershipMismatch` unless `live`'s
		/// local-membership set still equals `baseMemberships`.
		public consuming func apply(onto live: Group) throws
			-> Transition<CommitEffects>
		{
			guard live.context == base else {
				throw MLS.RFC9420.GroupError.staleBase
			}
			// The count check makes the comparison insensitive to nothing: a `Set`
			// alone would let a live group with a *duplicated* leaf index match a
			// base that names it once, and the positional install below would then
			// leave the duplicate membership with stale keys — the silent-loss the
			// guard exists to exclude.
			let liveLeaves = live.memberships.map(\.leafIndex)
			guard liveLeaves.count == baseMemberships.count,
				Set(liveLeaves) == baseMemberships
			else {
				throw MLS.RFC9420.GroupError.membershipMismatch
			}
			var result = live
			result.context = newContext
			result.tree = newTree
			result.epoch = newEpoch
			result.interimTranscriptHash = newInterimTranscriptHash
			// Install each local membership's own new-epoch path keys (slice 4a).
			// The membership set equals `baseMemberships` (guarded above), so every
			// membership has an entry. Throw rather than install an empty set: an
			// empty key map would silently strand the membership at `notAMember` —
			// the exact silent-loss this per-membership slice exists to remove.
			for index in result.memberships.indices {
				guard
					let keys = newSecretKeysByLeaf[
						result.memberships[index].leafIndex]
				else {
					throw MLS.RFC9420.GroupError.membershipMismatch
				}
				result.memberships[index].secretKeys = keys
			}
			// Proposed-but-uncommitted self-Update secrets do not outlive the
			// epoch (forward secrecy) — the advance retires the whole set.
			for index in result.memberships.indices {
				result.memberships[index].pendingUpdate = nil
			}
			// Likewise each local membership's own send ratchet: the retired
			// epoch's head secret is dropped, and the new epoch starts unseeded
			// (re-seeded lazily from the new secret tree on its first send). The
			// send path also self-corrects on an epoch-tag mismatch, so this is
			// forward secrecy, not correctness — it just drops the old secret now
			// rather than at the next send (slice 3b).
			for index in result.memberships.indices {
				result.memberships[index].ownSend =
					MLS.RFC9420.Membership.OwnSendState(epoch: newContext.epoch)
			}
			// live's retained old-epoch stores are already in `result`; add the
			// new epoch's, then prune to the retention window against the NEW
			// epoch (pruning against the old could evict the entry just added).
			result.messageSecrets[newContext.epoch] = newMessageStore
			let depth = UInt64(result.retention.messageSecretsDepth)
			let floor = newContext.epoch >= depth ? newContext.epoch - depth : 0
			result.messageSecrets = result.messageSecrets.filter { $0.key >= floor }
			// Single-epoch (past epochs' export seeds are not retained).
			result.exporterTrees = [newContext.epoch: newExporterTree]
			result.resumptionPsks[newContext.epoch] = newResumptionPsk
			result.pruneResumptionPsks(currentEpoch: newContext.epoch)
			return Transition(group: result, output: effects)
		}
	}
}

extension MLS.RFC9420.Transition: Copyable where Output: Copyable {}
