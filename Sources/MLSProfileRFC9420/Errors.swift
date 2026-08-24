import MLSCodec
import MLSFraming

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
		/// S12/S25: a `confirmation_tag` didn't match the locally
		/// recomputed value.
		case confirmationTagMismatch
	}
}
