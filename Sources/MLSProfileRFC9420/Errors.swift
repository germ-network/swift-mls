import MLSCodec
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420 {
	public enum WireError: Error, Sendable, Equatable {
		case unknownLeafNodeSource(UInt8)
		case unknownWireFormat(MLS.WireFormat)
		case unknownProposalType(UInt16)
		case unknownProposalOrRefType(UInt8)
		case unknownContentType(MLS.ContentType)
		case unsupportedProtocolVersion(MLS.ProtocolVersion)
		/// RFC 9420 §10: "The field leaf_node.leaf_node_source of the
		/// LeafNode in a KeyPackage MUST be set to key_package"; §7.3
		/// restates it as a validation step. A leaf found in a KeyPackage
		/// whose source is `update` or `commit` cannot even be signed —
		/// §7.2's `LeafNodeTBS` would bind a `(group_id, leaf_index)` that
		/// does not exist — so this is thrown at TBS assembly rather than
		/// waiting for the signature to fail.
		///
		/// `KeyPackage.validate` runs the full §10.1 suite on every Add;
		/// this error is the TBS-assembly half of the source rule, thrown
		/// before a signature could even be checked.
		case leafNodeSourceNotKeyPackage
		/// `KeyPackage.reference` was called with a provider for a
		/// different cipher suite than the package itself declares.
		case cipherSuiteMismatch
	}

	/// Errors from `MLS.RFC9420.Group`'s join/commit-processing pipeline —
	/// `WireError` is decode-only and doesn't cover semantic failures like
	/// a mismatched cipher suite or an unresolved PSK.
	public enum GroupError: Error, Sendable, Equatable {
		/// S1: no `Welcome.secrets` entry matches our own `KeyPackageRef`.
		case noMatchingWelcomeSecret
		/// S2/S6: `Welcome.cipherSuite` or `GroupContext.cipherSuite`
		/// doesn't match the joiner's own `KeyPackage.cipherSuite`.
		case cipherSuiteMismatch
		/// RFC 9420 §10.1's other half: "Verify that the cipher suite and
		/// protocol version of the KeyPackage match those in the
		/// GroupContext."
		case protocolVersionMismatch
		/// RFC 9420 §7.3: "Verify that the following fields are unique
		/// among the members of the group: signature_key, encryption_key."
		/// This is the `signature_key` half; the `encryption_key` half is
		/// `MLS.TreeKEM.TreeError.duplicateEncryptionKey`.
		case duplicateSignatureKey(leaf: MLS.LeafIndex)
		/// Neither an externally-supplied tree nor a `ratchet_tree`
		/// extension on `GroupInfo` was available.
		case missingRatchetTree
		/// S5: `GroupInfo.signer`'s leaf is blank.
		case blankSignerLeaf
		/// S10: no leaf in the tree matches the joiner's own `KeyPackage`.
		case ownLeafNotFound
		/// S13: a `GroupSecrets`/commit PSK proposal named an id the
		/// caller's `psk` closure couldn't resolve.
		case unresolvedPreSharedKey
		/// A resolved PSK (external or resumption) was zero-length. Distinct
		/// from `unresolvedPreSharedKey` (the resolver returned nothing): an
		/// empty-but-present PSK is malformed input, so it is rejected at the
		/// custody boundary rather than folded into the key schedule.
		case emptyPreSharedKey
		/// A Welcome's decrypted `joiner_secret` was zero-length — it cannot
		/// key the schedule, so a hostile or malformed Welcome is rejected
		/// here rather than deriving garbage that only fails later at the
		/// confirmation tag.
		case emptyJoinerSecret
		/// RFC 9420 §12.4.3.1's `reinit`/`branch` resumption-PSK rules
		/// (uniqueness among the Welcome's PSKs, `GroupInfo.epoch == 1`)
		/// are out of scope — ReInit and branching are deferred
		/// project-wide. Rejected outright rather than silently accepted
		/// without those checks.
		case unsupportedResumptionUsage
		/// S12/S25: a `confirmation_tag` didn't match the locally
		/// recomputed value.
		case confirmationTagMismatch
		/// S14: the commit's epoch isn't this group's current epoch.
		case wrongEpoch(expected: UInt64, actual: UInt64)
		/// The commit's `group_id`, or a resumption PSK's `psk_group_id`,
		/// names a different group.
		case wrongGroup
		/// A `PublicMessage` that isn't a commit was handed to commit
		/// processing.
		case notACommit
		/// `ProposalStore.insert` was handed an `AuthenticatedContent`
		/// whose framed content isn't a proposal.
		case notAProposal
		/// External commits and external senders are deferred
		/// project-wide, so a non-member sender is rejected rather than
		/// silently mishandled.
		case unsupportedSender
		/// `safeExportSecret` found no Exporter Tree for the current epoch — an
		/// internal inconsistency (every epoch-entry path and `restore` install
		/// one), surfaced rather than force-unwrapped.
		case exporterTreeUnavailable
		/// The commit's sender names a blank leaf.
		case blankSenderLeaf
		/// S22: a by-reference proposal names a `ProposalRef` the caller's
		/// store doesn't hold. An error, never a skip — applying a shorter
		/// proposal list than the sender used diverges state silently.
		case unknownProposalReference
		/// S18: RFC 9420 §12.4 requires a path for this proposal list.
		case pathRequired
		/// A commit carried a ReInit proposal. RFC 9420 §12.4.2: such a
		/// client "MUST NOT use the group to send messages anymore" and
		/// must wait for a §11.2 Welcome — a transition this project
		/// defers project-wide. Rejected rather than applied because
		/// ReInit, uniquely, does not perturb the key schedule: applying
		/// it would *succeed* and hand back a live-looking `Group` the
		/// caller must not send from.
		case unsupportedReInit
		/// A Remove naming a leaf that is already blank. The
		/// tree's own mutation primitives stay unconditional by design;
		/// "is this leaf currently a member" is context only commit
		/// processing has.
		case removeOfNonMember(leaf: MLS.LeafIndex)
		/// An Update proposal whose sender occupies no leaf. RFC 9420
		/// §12.1.2 defines the operation as replacing *the sender's*
		/// LeafNode, which does not exist in that case.
		///
		/// Historically load-bearing beyond the undefined semantics: it
		/// was the only guard between an out-of-range store-supplied
		/// sender and a process abort. The tree's setters now throw on
		/// out-of-range indices themselves, so this is the spec-shaped
		/// error in front of a structural backstop.
		case updateFromNonMember(leaf: MLS.LeafIndex)
		/// §7.3: a leaf `extensions` entry (non-default type) missing
		/// from its own `capabilities.extensions`. Default types are
		/// exempt — see `defaultExtensionTypes`'s doc comment for the
		/// §7.2/§7.3 tension this resolves.
		case unsupportedExtensionInLeaf(ExtensionType)
		/// §7.3: the leaf's own credential type is not in its own
		/// `capabilities.credentials`.
		case credentialTypeNotInOwnCapabilities
		/// §7.3's mutual-support bullet, first half: an existing member's
		/// capabilities do not include this leaf's credential type.
		case credentialTypeUnsupportedByMember
		/// §7.3's mutual-support bullet, second half: this leaf's
		/// capabilities omit a credential type currently in use.
		case memberCredentialUnsupportedByLeaf
		/// §7.3: the GroupContext's `required_capabilities` names a
		/// non-default type this leaf's capabilities do not list
		/// (credential types are never default-exempt — §11.1).
		case requiredCapabilitiesNotMet
		/// §7.3: an Update whose LeafNode carries the same
		/// `encryption_key` as the leaf it replaces.
		case updateDidNotChangeEncryptionKey
		/// §7.3: `leaf_node_source` disagrees with where the leaf was
		/// found (KeyPackage → `key_package`, Update proposal → `update`,
		/// UpdatePath → `commit`).
		case wrongLeafNodeSource
		/// §7.3: the current time is outside `[not_before, not_after]`.
		/// Only thrown when the caller supplies a time — the receive-path
		/// check is RECOMMENDED, not mandatory.
		case leafNodeLifetimeOutOfRange
		/// §7.2: total lifetime exceeds the application-supplied maximum.
		/// Only thrown when the caller supplies one.
		case leafNodeLifetimeTooLong
		/// §10.1: `leaf_node.encryption_key` equals the `init_key`.
		case keyPackageInitKeyReused
		/// §12.2: a commit containing an Update generated by the
		/// committer. Inline Updates are always committer-attributed, so
		/// an inline Update is always invalid — that is correct, not a
		/// bug: an Update in your own commit is yours, and the RFC gives
		/// committers `UpdatePath` for exactly that purpose.
		case updateByCommitter
		/// §12.2: a Remove naming the committer's own leaf.
		case removeOfCommitter
		/// §12.2: multiple Update/Remove proposals applying to one leaf.
		case duplicateProposalForLeaf(leaf: MLS.LeafIndex)
		/// §12.2: two PreSharedKey proposals naming one `PreSharedKeyID`.
		case duplicatePreSharedKey
		/// §12.2: more than one GroupContextExtensions proposal.
		case multipleGroupContextExtensions
		/// §12.1.4: `psk_nonce` length must equal the suite's KDF.Nh.
		case wrongPskNonceLength(expected: Int, actual: Int)
		/// S20: `UpdatePath.leaf_node.leaf_node_source` must be `commit`.
		case updatePathLeafNotCommitSource
		/// §12.4.2: the UpdatePath leaf carries the committer's own
		/// *current* leaf encryption key — the specific bullet, distinct
		/// from `updatePathReusesEncryptionKey`'s whole-tree sweep so the
		/// two are separately testable (a leaf tripping this necessarily
		/// also trips the sweep, which made a shared case
		/// mutation-invisible).
		case updatePathReusesCommitterKey
		/// S20: an `UpdatePath` public key already appears in the new
		/// ratchet tree — including the committer's own previous leaf key.
		case updatePathReusesEncryptionKey
		/// §12.4.3.1: "the set of Welcome messages produced in this step
		/// MUST cover every new member added in the Commit." An added
		/// member whose KeyPackage could not be matched to a tree leaf —
		/// an internal invariant violation surfaced as a throw rather
		/// than a silently incomplete Welcome.
		case welcomeCoverageIncomplete
		/// A `PrivateMessage` from an epoch whose message secrets are no
		/// longer retained (or never existed). Below the retention floor
		/// this is an expected, §15.3-shaped rejection, not an anomaly.
		case messageFromUnretainedEpoch(epoch: UInt64)
		/// The generation's key was consumed (or its whole subtree was) —
		/// §9.2 deletion doubles as the replay authority: a deleted key
		/// cannot be re-derived, so a replay is *rejected*, never
		/// re-decrypted.
		case generationAlreadyConsumed(generation: UInt32)
		/// §15.3: the requested generation is further ahead of the chain
		/// head than policy allows. Checked before any derivation.
		case generationJumpTooLarge(requested: UInt32, head: UInt32)
		/// §15.3: deriving this generation would retain more skipped
		/// key/nonce pairs for one sender than policy allows.
		case tooManySkippedKeys(leaf: MLS.LeafIndex)
		/// Peer-derived hardening both mls-rs and OpenMLS have: a member must not
		/// decrypt its own message — its own ratchet is for sending, and
		/// "decrypting yourself" is always a reflection or a bug.
		case cannotDecryptOwnMessage
		/// The message names this group's id or an epoch inconsistently
		/// with its framing — routed and rejected before any ratchet is
		/// touched.
		case wrongContentType(MLS.ContentType)
		/// Own send ratchet exhausted (generation == UInt32.max): refuse
		/// rather than wrap or trap. §15.2's AEAD-volume MUST is reached
		/// long before this in any real deployment.
		case sendGenerationExhausted
		/// S19: this commit removed us. Note what is and isn't proven:
		/// the framing signature and membership MAC have both passed, so
		/// an *authenticated member* sent it — but the confirmation tag
		/// has not been checked and cannot be, since it needs an epoch
		/// whose `commit_secret` a removed member can no longer derive.
		/// So this means "an authenticated member removed me", not "a
		/// fully verified commit removed me".
		///
		/// RFC 9420 §12.4.2 says such a client "SHOULD promptly delete its
		/// group state and secret tree", and explicitly allows keeping the
		/// secret tree briefly "to decrypt late messages in the previous
		/// epoch" — so this is the caller's decision to make, not a
		/// mandate to wipe immediately.
		case removedFromGroup
	}
}
