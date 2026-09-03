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
		/// Note what still has no caller: nothing in `Sources/` yet
		/// verifies a *received* KeyPackage's leaf. §10.1 validation
		/// arrives with phase 6's Add-proposal handling; this error is the
		/// half of it that already exists.
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
		/// External commits and external senders are deferred
		/// project-wide, so a non-member sender is rejected rather than
		/// silently mishandled.
		case unsupportedSender
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
		/// Load-bearing beyond the undefined semantics: `setLeaf` grows
		/// the backing array to reach any index it is given, and
		/// `LeafIndex` is bounded only by its own 2^24 ceiling, never
		/// against the tree it indexes. Without this guard an
		/// out-of-range sender in a caller-supplied `ProposalStore`
		/// allocates its way toward 2^25 array entries and then aborts
		/// the process on `RatchetTree.leafCount`'s `try!`.
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
		/// S20: an `UpdatePath` public key already appears in the new
		/// ratchet tree — including the committer's own previous leaf key.
		case updatePathReusesEncryptionKey
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
