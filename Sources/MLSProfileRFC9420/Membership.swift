import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
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
	/// Slice 1a carves these fields out of `Group`; slice 3b moves this client's
	/// own-leaf send ratchets and positions (`ownSend`) here, where
	/// `committing(as:)` and `protect(as:)` spend the *sealing* membership's own
	/// generation — the shared `GroupCore` retains only remote senders' chains and
	/// the consuming secret tree.
	public struct Membership: Sendable {
		/// Which leaf this client occupies in the group.
		public internal(set) var leafIndex: MLS.LeafIndex

		/// This client's HPKE secret keys, keyed by *node* index — its own leaf
		/// (`2 * leafIndex`) plus whatever direct-path ancestors the last Welcome
		/// or Commit installed.
		var secretKeys: [UInt32: MLS.HpkeSecretKey]

		/// This client's self-proposed Updates awaiting a commit — the pending
		/// membership → new-LeafNode transition. Seeded by `proposeUpdate` and
		/// consumed when a landing commit applies one (`validating` → `apply`); a *set*,
		/// because the committer (not the proposer) chooses which Update lands.
		/// Valid only for the epoch it names; cleared on every epoch advance.
		var pendingUpdate:
			(
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)?

		/// This client's own send ratchets and positions for the **current epoch**
		/// (slice 3b). A member frames messages only in its current epoch, so a
		/// single epoch's state suffices; the `epoch` tag makes cross-epoch reuse
		/// structurally impossible — a send whose tag does not match the group's
		/// current epoch resets to a fresh, unseeded state before deriving, so a
		/// generation is never carried from one epoch's ratchet into the next
		/// (§9.1 key/nonce reuse). Seeded lazily from `GroupCore`'s current-epoch
		/// consuming secret tree on the first send, and reset on every epoch
		/// advance (forward secrecy: the retired epoch's head secret is dropped).
		var ownSend: OwnSendState

		/// The own-leaf send state for one epoch. Both ratchets are seeded together
		/// from a single consumed leaf secret (§9.1), so `handshakeChain == nil`
		/// means neither has been seeded yet — the next generation is 0. Send is
		/// strictly sequential, so the next generation is exactly the chain's head
		/// generation (own chains never retire — `deriveOwnSendKey` throws at
		/// `.max`), and no skipped keys ever accumulate here (unlike the
		/// receive-side chains in `GroupCore`). The chain is the sole consumption
		/// authority; there is no separate counter to drift from it.
		struct OwnSendState: Sendable {
			var epoch: UInt64
			var handshakeChain: MLS.KeySchedule.RatchetChain?
			var applicationChain: MLS.KeySchedule.RatchetChain?

			init(epoch: UInt64) {
				self.epoch = epoch
				self.handshakeChain = nil
				self.applicationChain = nil
			}

			/// The next generation this ratchet will send — its chain's head, or 0
			/// before the chain is seeded.
			func nextGeneration(isHandshake: Bool) -> UInt32 {
				(isHandshake ? handshakeChain : applicationChain)?.headGeneration
					?? 0
			}
		}

		init(
			leafIndex: MLS.LeafIndex, secretKeys: [UInt32: MLS.HpkeSecretKey],
			pendingUpdate: (
				epoch: UInt64, node: UInt32,
				updates: [(publicKey: MLS.HpkePublicKey, secret: MLS.HpkeSecretKey)]
			)? = nil,
			ownSend: OwnSendState = OwnSendState(epoch: 0)
		) {
			self.leafIndex = leafIndex
			self.secretKeys = secretKeys
			self.pendingUpdate = pendingUpdate
			self.ownSend = ownSend
		}
	}
}
