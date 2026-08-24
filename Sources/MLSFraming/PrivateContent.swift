import Foundation
import MLSCodec

extension MLS.Framing {
	/// `struct { opaque group_id<V>; uint64 epoch; ContentType
	/// content_type; opaque authenticated_data<V>; } PrivateContentAAD;`
	public struct PrivateContentAAD: Sendable, MLSEncodable {
		public var groupID: Data
		public var epoch: UInt64
		public var contentType: MLS.ContentType
		public var authenticatedData: Data

		public init(
			groupID: Data, epoch: UInt64, contentType: MLS.ContentType,
			authenticatedData: Data
		) {
			self.groupID = groupID
			self.epoch = epoch
			self.contentType = contentType
			self.authenticatedData = authenticatedData
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(groupID)
			writer.writeUInt64(epoch)
			try contentType.encode(to: &writer)
			try writer.writeOpaque(authenticatedData)
		}
	}

	/// RFC 9420 §6.3.1: append zero bytes to reach a target length; a
	/// decoder MUST reject any non-zero padding byte. RFC 9420 leaves the
	/// target-length *policy* unspecified — this component only offers the
	/// mechanism. Encode-only: decoding a `PrivateMessageContent`'s padding
	/// means decoding its content and auth data first (self-delimiting,
	/// but only a profile knows how — the content body carries no type tag
	/// of its own here, unlike public `FramedContent`) and treating
	/// whatever the reader has left as padding, which is a profile-side
	/// concern, not this function's.
	public static func padded(_ content: Data, toLength length: Int) -> Data {
		content.count >= length
			? content : content + Data(repeating: 0, count: length - content.count)
	}
}
