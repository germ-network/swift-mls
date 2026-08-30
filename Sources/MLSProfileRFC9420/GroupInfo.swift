import Foundation
import MLSCodec
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420 {
	/// `struct { GroupContext group_context; Extension extensions<V>; MAC
	/// confirmation_tag; uint32 signer; opaque signature<V>; } GroupInfo;`
	public struct GroupInfo: Sendable, Equatable {
		public var groupContext: GroupContext
		public var extensions: [Extension]
		public var confirmationTag: MLS.ConfirmationTag
		public var signer: MLS.LeafIndex
		public var signature: Data

		public init(
			groupContext: GroupContext, extensions: [Extension],
			confirmationTag: MLS.ConfirmationTag,
			signer: MLS.LeafIndex, signature: Data
		) {
			self.groupContext = groupContext
			self.extensions = extensions
			self.confirmationTag = confirmationTag
			self.signer = signer
			self.signature = signature
		}
	}
}

extension MLS.RFC9420.GroupInfo: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try writer.encode(groupContext)
		try writer.encodeVector(extensions)
		try writer.encode(confirmationTag)
		try writer.encode(signer)
		try writer.writeOpaque(signature)
	}
}

extension MLS.RFC9420.GroupInfo: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		groupContext = try MLS.RFC9420.GroupContext(from: &reader)
		extensions = try reader.decodeVector()
		confirmationTag = try MLS.ConfirmationTag(from: &reader)
		signer = try MLS.LeafIndex(from: &reader)
		signature = Data(try reader.readOpaque())
	}
}

extension MLS.RFC9420.GroupInfo {
	/// `GroupInfoTBS` — every field above except `signature`.
	public func toBeSigned() throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(groupContext)
		try writer.encodeVector(extensions)
		try writer.encode(confirmationTag)
		try writer.encode(signer)
		return Data(writer.bytes)
	}
}
