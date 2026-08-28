import Foundation
import MLSCodec
import MLSKeySchedule

extension MLS.RFC9420.Group {
	/// The subset of an epoch's key-schedule fan-out this profile retains
	/// between operations. `MLS.KeySchedule.Epoch` stays a pure, complete
	/// 12-field fan-out — the anchor component does not decide retention;
	/// this profile does, here, and RFC 9420 §9.2 is why: "As soon as a
	/// group member consumes a value, they MUST immediately delete (all
	/// representations of) that value."
	///
	/// **"Not retained" is the honest claim — not "deleted".** Constructing
	/// this narrowed value releases the dropped fields' `Data` buffers
	/// without scrubbing them (copy-on-write shares, then frees), and the
	/// full `Epoch` lives on as a local through the rest of `join`'s and
	/// `processing`'s bodies. Erasure of freed bytes is a separate,
	/// best-effort concern with its own limits, tracked as this project's
	/// standing zeroization debt.
	///
	/// What is dropped, and why it is safe:
	/// - `joinerSecret`, `welcomeSecret`: consumed by Welcome processing —
	///   the §9.2 MUST applies directly.
	/// - `confirmationKey`: consumed once the epoch-establishing
	///   confirmation tag is verified. Later commits are checked with the
	///   *next* epoch's key, and a committer (`committing`) computes its tag
	///   from the new epoch it just derived in-line — nothing reads a
	///   retained confirmation key.
	/// - `externalSecret`, `externalPublicKey`: only power external
	///   commits, which this project rejects project-wide. Unconsumed, so
	///   dropping them is a choice, not a §9.2 mandate — retaining key
	///   material for a rejected feature is pointless risk. Foreclosed by
	///   this drop: a standalone "export GroupInfo for the current epoch"
	///   API, which would need both. A phase-6 committer captures them
	///   from the full `Epoch` at derivation time instead.
	/// - `resumptionPsk`: lives in `Group.resumptionPsks` keyed by epoch —
	///   its single retained representation, bounded by
	///   `RetentionPolicy`.
	///
	/// What is retained, and why: `initSecret` is unconsumed until the
	/// next commit's `advance`; `membershipKey` verifies every incoming
	/// `PublicMessage` this epoch; `exporterSecret` backs the exporter
	/// for the epoch's lifetime; `epochAuthenticator` is the value RFC
	/// 9420 exposes to applications. `senderDataSecret` and
	/// `encryptionSecret` moved into the per-epoch *message-secret store*
	/// (`MessageProtection.swift`) the moment message handling arrived —
	/// there they are consumed per §9.2's own schedule, which a flat
	/// retained field could never express.
	public struct EpochSecrets: Sendable {
		public let initSecret: Data
		public let exporterSecret: Data
		public let epochAuthenticator: Data
		public let membershipKey: Data

		/// The §11 creation path: an epoch-0 fan-out has no joiner or
		/// welcome secret to drop in the first place.
		init(retaining fanOut: MLS.KeySchedule.EpochFanOut) {
			self.initSecret = fanOut.initSecret
			self.exporterSecret = fanOut.exporterSecret
			self.epochAuthenticator = fanOut.epochAuthenticator
			self.membershipKey = fanOut.membershipKey
		}

		init(retaining epoch: MLS.KeySchedule.Epoch) {
			self.initSecret = epoch.initSecret
			self.exporterSecret = epoch.exporterSecret
			self.epochAuthenticator = epoch.epochAuthenticator
			self.membershipKey = epoch.membershipKey
		}
	}

	/// How much per-epoch history this group keeps. Retention is enforced
	/// at the end of every successful `process` and immediately when the
	/// policy itself is changed.
	public struct RetentionPolicy: Sendable {
		/// Resumption PSKs are kept for the current epoch plus this many
		/// past epochs — depth 3 at epoch N retains `{N-3 ... N}`, so a
		/// commit can reference a resumption PSK at most 3 epochs back.
		/// Depth 0 keeps only the current epoch's.
		///
		/// The default matches mls-rs (`DEFAULT_EPOCH_RETENTION_LIMIT = 3`
		/// prior epoch records beside the live group). The official
		/// passive-client vectors constrain this only weakly: every
		/// resumption reference in `passive-client-handling-commit.json`
		/// is to the immediately preceding epoch, and
		/// `passive-client-random.json` carries no PSKs at all — so 3 is
		/// peer parity, not an empirically validated bound. RFC 9420 §9.2
		/// governs *unconsumed* values here: "Members MAY keep unconsumed
		/// values around for some reasonable amount of time" — a bound is
		/// hygiene under that MAY, and the MUST-delete applies only once a
		/// PSK is consumed.
		public var resumptionPskDepth: Int

		/// Past epochs whose *message* secrets stay decryptable — the
		/// cross-epoch out-of-order window. 0 = current epoch only.
		/// RFC 9420 §15.3 makes all three message-secret bounds
		/// application policy; these defaults are deliberately modest.
		public var messageSecretsDepth: Int
		/// §15.3's "maximum number of steps... move the ratchet forward"
		/// — checked BEFORE any derivation loop, because the RFC's own
		/// DoS is a forged generation of 0xffffffff.
		public var maxForwardJump: Int
		/// §15.3's cap on retained unconsumed key/nonce pairs, per
		/// sender chain.
		public var maxSkippedKeysPerSender: Int

		public init(
			resumptionPskDepth: Int = 3, messageSecretsDepth: Int = 1,
			maxForwardJump: Int = 1_000, maxSkippedKeysPerSender: Int = 1_024
		) {
			self.resumptionPskDepth = max(0, resumptionPskDepth)
			self.messageSecretsDepth = max(0, messageSecretsDepth)
			self.maxForwardJump = max(0, maxForwardJump)
			self.maxSkippedKeysPerSender = max(0, maxSkippedKeysPerSender)
		}
	}
}
