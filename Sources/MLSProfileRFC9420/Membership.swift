import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.RFC9420 {
	/// One client's membership in a group (D18): the per-(client, group) state
	/// that differs between two clients occupying the same group on one device —
	/// its leaf, its HPKE private keys for that leaf and direct path, and its
	/// pending self-Update. The client-agnostic state (context, tree, epoch
	/// secrets, receive-side consumption, …) lives in `GroupCore`; the composite
	/// an app holds and operates on is `Group { core, memberships }`.
	///
	/// Identity is the leaf index — unique among members, and stable across a
	/// self-Update (which replaces the leaf in place), so the membership persists
	/// across its LeafNode transition.
	///
	/// Slice 1a carves these fields out of `Group`; own-leaf message-ratchet
	/// chains and send positions (`ownNextGeneration`) move here in the send-side
	/// slice, where `committing(as:)` needs them on the sealing membership.
	public struct Membership: Sendable {
		/// Which leaf this client occupies in the group.
		public internal(set) var leafIndex: MLS.LeafIndex

		/// This client's HPKE secret keys, keyed by *node* index — its own leaf
		/// (`2 * leafIndex`) plus whatever direct-path ancestors the last Welcome
		/// or Commit installed.
		var secretKeys: [UInt32: MLS.HpkeSecretKey]

		/// This client's self-proposed Updates awaiting a commit — the pending
		/// membership → new-LeafNode transition. Seeded by `proposeUpdate` and
		/// consumed by `processing` when a landing commit applies one; a *set*,
		/// because the committer (not the proposer) chooses which Update lands.
		/// Valid only for the epoch it names; cleared on every epoch advance.
		var pendingUpdate:
			(
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)?

		init(
			leafIndex: MLS.LeafIndex, secretKeys: [UInt32: MLS.HpkeSecretKey],
			pendingUpdate: (
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)? = nil
		) {
			self.leafIndex = leafIndex
			self.secretKeys = secretKeys
			self.pendingUpdate = pendingUpdate
		}
	}
}
