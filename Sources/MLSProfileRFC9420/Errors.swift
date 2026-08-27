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
	}
}
