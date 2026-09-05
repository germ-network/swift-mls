import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import MLSTreeKEM
import SecretBytes

extension MLS.RFC9420 {
	/// The client-agnostic half of a group (D18): everything that is identical
	/// for every member — the `GroupContext`, public tree, transcript hash,
	/// epoch secrets, resumption PSKs, the receive-side message-secret state
	/// (the consuming secret tree and remote senders' ratchet chains), and the
	/// exporter tree. **One copy per group on a device**, shared by every local
	/// `Membership`; the composite an app holds is `Group { core, memberships }`.
	///
	/// Slice 1a keeps the per-epoch `MessageSecrets` whole here; the send-side
	/// slice moves each local leaf's own chains and send positions onto its
	/// `Membership`, leaving only remote chains + the secret tree here.
	public struct GroupCore: Sendable {
		public internal(set) var context: GroupContext
		public internal(set) var tree: MLS.TreeKEM.RatchetTree
		public internal(set) var interimTranscriptHash: Data
		public internal(set) var epoch: Group.EpochSecrets

		/// See `Group.RetentionPolicy`. Lowering it prunes immediately, not at the next
		/// commit — a group that never processes another commit must still be
		/// able to shed history.
		public var retention: Group.RetentionPolicy = Group.RetentionPolicy() {
			didSet { pruneResumptionPsks(currentEpoch: context.epoch) }
		}

		/// `resumption_psk` for recent epochs, keyed by epoch — bounded by
		/// `retention.resumptionPskDepth`. Held zeroizing; the single retained
		/// representation of each epoch's resumption PSK.
		var resumptionPsks: [UInt64: SecretBytes]

		/// Per-epoch application-message state (secret tree, ratchets, epoch
		/// snapshots) — the §9.2 consuming store, bounded by
		/// `retention.messageSecretsDepth`. See `MessageProtection.swift`.
		var messageSecrets: [UInt64: Group.MessageSecrets] = [:]

		/// The current epoch's draft §4.4 Exporter Tree — the *consuming* tree,
		/// never the raw root (forward secrecy, RFC 9420 §9.2). Keyed by epoch and
		/// reset to the current epoch on every install.
		var exporterTrees: [UInt64: MLS.KeySchedule.ExporterTree] = [:]

		mutating func pruneResumptionPsks(currentEpoch: UInt64) {
			// Saturating: at epochs below the depth, everything survives.
			let depth = UInt64(retention.resumptionPskDepth)
			let floor = currentEpoch >= depth ? currentEpoch - depth : 0
			resumptionPsks = resumptionPsks.filter { $0.key >= floor }
		}

		init(
			context: GroupContext, tree: MLS.TreeKEM.RatchetTree,
			interimTranscriptHash: Data, epoch: Group.EpochSecrets,
			retention: Group.RetentionPolicy = Group.RetentionPolicy(),
			resumptionPsks: [UInt64: SecretBytes],
			messageSecrets: [UInt64: Group.MessageSecrets] = [:],
			exporterTrees: [UInt64: MLS.KeySchedule.ExporterTree] = [:]
		) {
			self.context = context
			self.tree = tree
			self.interimTranscriptHash = interimTranscriptHash
			self.epoch = epoch
			self.retention = retention
			self.resumptionPsks = resumptionPsks
			self.messageSecrets = messageSecrets
			self.exporterTrees = exporterTrees
		}
	}
}
