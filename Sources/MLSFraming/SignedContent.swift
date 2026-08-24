import Foundation
import MLSCodec

extension MLS {
	public enum Framing {}
}

extension MLS.Framing {
	/// The parts RFC 9420 §6.1's `FramedContentTBS` is built from, held
	/// separately rather than as one struct-then-encode.
	///
	/// `encodedContent` arrives already encoded. That is the whole point:
	/// the TBH variant a later profile needs (a second encoding of the
	/// same framed content, e.g. with the update path's leaf node omitted
	/// to avoid a circular signature dependency) is this same assembly
	/// over a *different byte string* — no new API. A struct that owned a
	/// typed `FramedContent` could only ever emit that one type's one
	/// encoding. Same reasoning as `EncodedPathNodes` in
	/// `MLSProfileRFC9420` carrying bytes instead of typed nodes.
	public struct SignedContent: Sendable {
		public var protocolVersion: MLS.ProtocolVersion
		public var wireFormat: MLS.WireFormat
		public var encodedContent: Data
		/// Present exactly when the sender binds the group context — see
		/// `MLS.Sender.bindsGroupContext`. Written with no presence byte.
		public var encodedGroupContext: Data?

		public init(
			protocolVersion: MLS.ProtocolVersion, wireFormat: MLS.WireFormat,
			encodedContent: Data, encodedGroupContext: Data?
		) {
			self.protocolVersion = protocolVersion
			self.wireFormat = wireFormat
			self.encodedContent = encodedContent
			self.encodedGroupContext = encodedGroupContext
		}

		/// `FramedContentTBS` — version ‖ wire_format ‖ content ‖ context?
		public func toBeSigned() throws -> Data {
			var writer = MLS.Writer()
			try protocolVersion.encode(to: &writer)
			try wireFormat.encode(to: &writer)
			writer.writeBytes(encodedContent)
			if let encodedGroupContext { writer.writeBytes(encodedGroupContext) }
			return Data(writer.bytes)
		}

		/// `FramedContentTBM` = TBS ‖ FramedContentAuthData. Takes encoded
		/// auth data for the same reason `encodedContent` is encoded: a
		/// profile that changes the signature's representation changes
		/// exactly that part, nothing else.
		public func toBeMACed(encodedAuthData: Data) throws -> Data {
			var writer = MLS.Writer()
			writer.writeBytes(try toBeSigned())
			writer.writeBytes(encodedAuthData)
			return Data(writer.bytes)
		}

		/// `ConfirmedTranscriptHashInput` — wire_format ‖ content ‖
		/// signature. Reuses two of the four parts, drops protocol version
		/// and group context. (Verified against `transcript-hashes.json`
		/// across all seven RFC 9420 cipher suites.)
		public func confirmedTranscriptHashInput(encodedSignature: Data) throws -> Data {
			var writer = MLS.Writer()
			try wireFormat.encode(to: &writer)
			writer.writeBytes(encodedContent)
			writer.writeBytes(encodedSignature)
			return Data(writer.bytes)
		}
	}
}
