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
		/// `groupContext` must be supplied to `LeafNode.toBeSigned` iff
		/// `source` is `.update` or `.commit` (RFC 9420 §7.2's
		/// `LeafNodeTBS`) — never for `.keyPackage`.
		case leafNodeTBSContextMismatch
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
		/// GER-2355: a Remove naming a leaf that is already blank. The
		/// tree's own mutation primitives stay unconditional by design;
		/// "is this leaf currently a member" is context only commit
		/// processing has.
		case removeOfNonMember(leaf: MLS.LeafIndex)
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
