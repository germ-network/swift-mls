import MLSCodec
import MLSFraming

extension MLS.RFC9420 {
	public enum WireError: Error, Sendable, Equatable {
		case unknownLeafNodeSource(UInt8)
		case unknownWireFormat(MLS.WireFormat)
		/// `groupContext` must be supplied to `LeafNode.toBeSigned` iff
		/// `source` is `.update` or `.commit` (RFC 9420 §7.2's
		/// `LeafNodeTBS`) — never for `.keyPackage`.
		case leafNodeTBSContextMismatch
		/// `KeyPackage.reference` was called with a provider for a
		/// different cipher suite than the package itself declares.
		case cipherSuiteMismatch
	}
}
