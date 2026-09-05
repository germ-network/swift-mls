import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

// D17 — the handshake state machine expressed in types. Slice 1: the
// `Transition`/`PendingCommit` foundation (the H1/GER-2413 fix). The public
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
	}

	/// One effect a commit had, for the application to adjudicate at the seam
	/// between validation and apply. Slice 1 emits only `epochAdvanced`; the
	/// membership and §5.3.1 credential effects (`added`, `credentialReplaced`,
	/// `updated`, `removed`, `selfRemoved`, …) arrive with GER-2412 in a later
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

	/// Step 2 of a handshake: a validated epoch **delta**, never a successor
	/// `Group`. `apply(onto:)` composes it onto the *live* group the
	/// application has kept operating on, taking that group's (more-consumed)
	/// retained message-secret stores — so consumption made while the commit
	/// was pending is never rolled back (D17 §4, GER-2413). Non-copyable, and
	/// `apply` is `consuming`: a pending applies at most once, and applying it
	/// onto a group that has moved past its base throws `staleBase` rather than
	/// forking.
	///
	/// The delta fields are `internal`: a `PendingCommit` is produced only by
	/// the library's `validating`/`processing` paths, never constructed by a
	/// caller.
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
		let newSecretKeys: [UInt32: MLS.HpkeSecretKey]
		let newInterimTranscriptHash: Data
		let newMessageStore: Group.MessageSecrets
		let newExporterTree: MLS.KeySchedule.ExporterTree
		let newResumptionPsk: SecretBytes

		// The memberwise initializer stays `internal` (the delta fields are
		// internal), so a `PendingCommit` is produced only by the library's
		// `validating`/`processing` paths — never constructed by a caller.

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
			guard Set(live.memberships.map(\.leafIndex)) == baseMemberships else {
				throw MLS.RFC9420.GroupError.membershipMismatch
			}
			var result = live
			result.context = newContext
			result.tree = newTree
			result.epoch = newEpoch
			result.secretKeys = newSecretKeys
			result.interimTranscriptHash = newInterimTranscriptHash
			// Proposed-but-uncommitted self-Update secrets do not outlive the
			// epoch (forward secrecy) — the advance retires the whole set.
			result.pendingUpdates = nil
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
