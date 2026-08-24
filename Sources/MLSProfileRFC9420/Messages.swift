import Foundation
import MLSCodec
import MLSFraming

extension MLS.RFC9420 {
	/// `struct { select(...){ case application: opaque application_data<V>;
	/// case proposal: Proposal proposal; case commit: Commit commit; };
	/// FramedContentAuthData auth; opaque padding[length_of_padding]; }
	/// PrivateMessageContent;`
	///
	/// Unlike `FramedContent.content`, the body here carries no leading
	/// `ContentType` — it's already known from the outer, unencrypted
	/// `PrivateMessage.content_type`, so `content`/`auth` here decode via
	/// `Content.decodeBody`/`FramedContentAuthData.decodeRequiringSignature`
	/// rather than `Content`'s own tagged codec.
	public struct PrivateMessageContent: Sendable, Equatable {
		public var content: Content
		public var auth: MLS.FramedContentAuthData

		public init(content: Content, auth: MLS.FramedContentAuthData) {
			self.content = content
			self.auth = auth
		}

		public func encode(paddedToLength length: Int) throws -> Data {
			var writer = MLS.Writer()
			try content.encodeBody(to: &writer)
			try auth.encodeRequiringSignature(
				contentType: content.contentType, to: &writer)
			return MLS.Framing.padded(Data(writer.bytes), toLength: length)
		}

		public static func decode(_ plaintext: Data, contentType: MLS.ContentType) throws
			-> Self
		{
			var reader = MLS.Reader(plaintext)
			let content = try Content.decodeBody(
				contentType: contentType, from: &reader)
			let auth = try MLS.FramedContentAuthData.decodeRequiringSignature(
				contentType: contentType, from: &reader)
			guard try reader.readBytes(reader.bytesRemaining).allSatisfy({ $0 == 0 })
			else {
				throw MLS.FramingError.paddingNotZero
			}
			return Self(content: content, auth: auth)
		}
	}

	/// `struct { FramedContent content; FramedContentAuthData auth;
	/// select(...){ case member: MAC membership_tag; ... }; } PublicMessage;`
	public struct PublicMessage: Sendable, Equatable {
		public var content: FramedContent
		public var auth: MLS.FramedContentAuthData
		public var membershipTag: MLS.MembershipTag?

		public init(
			content: FramedContent, auth: MLS.FramedContentAuthData,
			membershipTag: MLS.MembershipTag?
		) {
			self.content = content
			self.auth = auth
			self.membershipTag = membershipTag
		}
	}

	/// `struct { opaque group_id<V>; uint64 epoch; ContentType
	/// content_type; opaque authenticated_data<V>; opaque
	/// encrypted_sender_data<V>; opaque ciphertext<V>; } PrivateMessage;`
	public struct PrivateMessage: Sendable, Equatable, MLSCodable {
		public var groupID: Data
		public var epoch: UInt64
		public var contentType: MLS.ContentType
		public var authenticatedData: Data
		public var encryptedSenderData: Data
		public var ciphertext: Data

		public init(
			groupID: Data, epoch: UInt64, contentType: MLS.ContentType,
			authenticatedData: Data,
			encryptedSenderData: Data, ciphertext: Data
		) {
			self.groupID = groupID
			self.epoch = epoch
			self.contentType = contentType
			self.authenticatedData = authenticatedData
			self.encryptedSenderData = encryptedSenderData
			self.ciphertext = ciphertext
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(groupID)
			writer.writeUInt64(epoch)
			try contentType.encode(to: &writer)
			try writer.writeOpaque(authenticatedData)
			try writer.writeOpaque(encryptedSenderData)
			try writer.writeOpaque(ciphertext)
		}

		public init(from reader: inout MLS.Reader) throws {
			groupID = Data(try reader.readOpaque())
			epoch = try reader.readUInt64()
			contentType = try MLS.ContentType(from: &reader)
			authenticatedData = Data(try reader.readOpaque())
			encryptedSenderData = Data(try reader.readOpaque())
			ciphertext = Data(try reader.readOpaque())
		}
	}
}

extension MLS.RFC9420.PublicMessage: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try content.encode(to: &writer)
		try auth.encodeRequiringSignature(
			contentType: content.content.contentType, to: &writer)
		if content.sender.carriesMembershipTag {
			guard let membershipTag else { throw MLS.FramingError.membershipTagMissing }
			try membershipTag.encode(to: &writer)
		}
	}
}

extension MLS.RFC9420.PublicMessage: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		content = try MLS.RFC9420.FramedContent(from: &reader)
		auth = try MLS.FramedContentAuthData.decodeRequiringSignature(
			contentType: content.content.contentType, from: &reader)
		membershipTag =
			content.sender.carriesMembershipTag
			? try MLS.MembershipTag(from: &reader) : nil
	}
}

extension MLS.RFC9420 {
	/// `MLSMessage`'s payload select. Written per §4.3: a closed switch —
	/// this is the one place that DOES need to be closed, since it's the
	/// only place that knows the full set of RFC 9420 wire-format payload
	/// types. A profile-pluggable *tag* (`MLS.WireFormat`, an open
	/// newtype) plus a closed *dispatcher* per profile is exactly the
	/// split §4.3 argues for.
	public enum Message: Sendable, Equatable {
		case publicMessage(PublicMessage)
		case privateMessage(PrivateMessage)
		case welcome(Welcome)
		case groupInfo(GroupInfo)
		case keyPackage(KeyPackage)

		public var wireFormat: MLS.WireFormat {
			switch self {
			case .publicMessage: .publicMessage
			case .privateMessage: .privateMessage
			case .welcome: .welcome
			case .groupInfo: .groupInfo
			case .keyPackage: .keyPackage
			}
		}
	}
}

extension MLS.RFC9420.Message: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try MLS.ProtocolVersion.mls10.encode(to: &writer)
		try wireFormat.encode(to: &writer)
		switch self {
		case .publicMessage(let m): try m.encode(to: &writer)
		case .privateMessage(let m): try m.encode(to: &writer)
		case .welcome(let m): try m.encode(to: &writer)
		case .groupInfo(let m): try m.encode(to: &writer)
		case .keyPackage(let m): try m.encode(to: &writer)
		}
	}
}

extension MLS.RFC9420.Message: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		_ = try MLS.ProtocolVersion(from: &reader)
		let wireFormat = try MLS.WireFormat(from: &reader)
		switch wireFormat {
		case .publicMessage:
			self = .publicMessage(try MLS.RFC9420.PublicMessage(from: &reader))
		case .privateMessage:
			self = .privateMessage(try MLS.RFC9420.PrivateMessage(from: &reader))
		case .welcome: self = .welcome(try MLS.RFC9420.Welcome(from: &reader))
		case .groupInfo: self = .groupInfo(try MLS.RFC9420.GroupInfo(from: &reader))
		case .keyPackage: self = .keyPackage(try MLS.RFC9420.KeyPackage(from: &reader))
		default: throw MLS.RFC9420.WireError.unknownWireFormat(wireFormat)
		}
	}
}
