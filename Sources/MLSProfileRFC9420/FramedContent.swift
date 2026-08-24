import Foundation
import MLSCodec
import MLSFraming

extension MLS.RFC9420 {
	/// `select (FramedContent.content_type) { case application: opaque
	/// application_data<V>; case proposal: Proposal proposal; case commit:
	/// Commit commit; };` — tagged by `ContentType`, whose values (1/2/3)
	/// are exactly `Content`'s own wire tag; there is no separate,
	/// independent tag byte for the select.
	public enum Content: Sendable, Equatable {
		case application(Data)
		case proposal(Proposal)
		case commit(Commit)

		public var contentType: MLS.ContentType {
			switch self {
			case .application: .application
			case .proposal: .proposal
			case .commit: .commit
			}
		}
	}

	/// `struct { opaque group_id<V>; uint64 epoch; Sender sender; opaque
	/// authenticated_data<V>; ContentType content_type; select(...){...};
	/// } FramedContent;`
	public struct FramedContent: Sendable, Equatable {
		public var groupID: Data
		public var epoch: UInt64
		public var sender: MLS.Sender
		public var authenticatedData: Data
		public var content: Content

		public init(
			groupID: Data, epoch: UInt64, sender: MLS.Sender, authenticatedData: Data,
			content: Content
		) {
			self.groupID = groupID
			self.epoch = epoch
			self.sender = sender
			self.authenticatedData = authenticatedData
			self.content = content
		}
	}

	/// `struct { WireFormat wire_format; FramedContent content;
	/// FramedContentAuthData auth; } AuthenticatedContent;`
	public struct AuthenticatedContent: Sendable, Equatable {
		public var wireFormat: MLS.WireFormat
		public var content: FramedContent
		public var auth: MLS.FramedContentAuthData

		public init(
			wireFormat: MLS.WireFormat, content: FramedContent,
			auth: MLS.FramedContentAuthData
		) {
			self.wireFormat = wireFormat
			self.content = content
			self.auth = auth
		}
	}
}

extension MLS.RFC9420.Content: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try contentType.encode(to: &writer)
		switch self {
		case .application(let data): try writer.writeOpaque(data)
		case .proposal(let proposal): try proposal.encode(to: &writer)
		case .commit(let commit): try commit.encode(to: &writer)
		}
	}
}

extension MLS.RFC9420.Content: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		switch try MLS.ContentType(from: &reader) {
		case .application: self = .application(Data(try reader.readOpaque()))
		case .proposal: self = .proposal(try MLS.RFC9420.Proposal(from: &reader))
		case .commit: self = .commit(try MLS.RFC9420.Commit(from: &reader))
		case let other: throw MLS.RFC9420.WireError.unknownContentType(other)
		}
	}
}

extension MLS.RFC9420.Content {
	/// The body alone, with no leading `ContentType` tag — RFC 9420's
	/// `PrivateMessageContent` select carries this shape, since the
	/// content type there is already known from the outer (unencrypted)
	/// `PrivateMessage.content_type` field and isn't repeated inside the
	/// encrypted plaintext.
	func encodeBody(to writer: inout MLS.Writer) throws {
		switch self {
		case .application(let data): try writer.writeOpaque(data)
		case .proposal(let proposal): try proposal.encode(to: &writer)
		case .commit(let commit): try commit.encode(to: &writer)
		}
	}

	static func decodeBody(contentType: MLS.ContentType, from reader: inout MLS.Reader) throws
		-> Self
	{
		switch contentType {
		case .application: .application(Data(try reader.readOpaque()))
		case .proposal: .proposal(try MLS.RFC9420.Proposal(from: &reader))
		case .commit: .commit(try MLS.RFC9420.Commit(from: &reader))
		default: throw MLS.RFC9420.WireError.unknownContentType(contentType)
		}
	}
}

extension MLS.RFC9420.FramedContent: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(groupID)
		writer.writeUInt64(epoch)
		try sender.encode(to: &writer)
		try writer.writeOpaque(authenticatedData)
		try content.encode(to: &writer)
	}
}

extension MLS.RFC9420.FramedContent: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		groupID = Data(try reader.readOpaque())
		epoch = try reader.readUInt64()
		sender = try MLS.Sender(from: &reader)
		authenticatedData = Data(try reader.readOpaque())
		content = try MLS.RFC9420.Content(from: &reader)
	}
}

extension MLS.RFC9420.AuthenticatedContent: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try wireFormat.encode(to: &writer)
		try content.encode(to: &writer)
		try auth.encodeRequiringSignature(
			contentType: content.content.contentType, to: &writer)
	}
}

extension MLS.RFC9420.AuthenticatedContent: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		wireFormat = try MLS.WireFormat(from: &reader)
		content = try MLS.RFC9420.FramedContent(from: &reader)
		auth = try MLS.FramedContentAuthData.decodeRequiringSignature(
			contentType: content.content.contentType, from: &reader)
	}
}
