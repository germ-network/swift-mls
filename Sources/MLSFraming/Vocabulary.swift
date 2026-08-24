import Foundation
import MLSCodec
import MLSTreeMath

/// `ProtocolVersion`, `WireFormat`, and `ContentType` are open `UInt8`/
/// `UInt16` newtypes with well-known constants — modeled exactly like
/// `MLS.CipherSuite` (`MLSCrypto/CipherSuite.swift`), not as
/// `MLSClosedEnum`s, even though RFC 9420 §17.1 lists WireFormat and
/// ContentType as closed and ProtocolVersion as the canonical *extensible*
/// example (see `MLSCodec/Enum.swift`'s doc comment, written in phase 0).
///
/// This phase reverses that assignment for all three types. Closedness is
/// a decoder *policy*, and the only place that actually knows the full set
/// of payload types for a given tag is a profile's top-level message
/// select (`MLS.RFC9420.Message`) — not this shared vocabulary. Keeping
/// the tag itself open lets a second profile (SlimMLS: wire formats
/// 0x0007–0x000B) claim values in the same registry without redefining a
/// type that `SignedContent`'s TBS assembly and `AuthenticatedContent`
/// carry verbatim. `MLSClosedEnum` can't do this: a profile can't add a
/// case to a closed Swift enum it doesn't own. `MLS.ExtensibleEnum` can't
/// either, for a different reason — it preserves an unrecognized *value*,
/// but tells a caller nothing about how to parse the payload that value
/// selects, and a second profile's `Known` case set would be a distinct
/// Swift type (`MLS.ExtensibleEnum<Slim.KnownWireFormat>`) that no shared
/// framing function typed on the RFC 9420 instantiation could accept.
/// Observable behavior is unchanged either way: an unrecognized wire
/// format still fails to decode — just one level up, at the profile's
/// `Message` switch, not at this type.
extension MLS {
	public struct ProtocolVersion: Hashable, Sendable {
		public let id: UInt16
		public init(id: UInt16) { self.id = id }
		public static let mls10 = ProtocolVersion(id: 1)
	}

	public struct WireFormat: Hashable, Sendable {
		public let id: UInt16
		public init(id: UInt16) { self.id = id }
		public static let publicMessage = WireFormat(id: 1)
		public static let privateMessage = WireFormat(id: 2)
		public static let welcome = WireFormat(id: 3)
		public static let groupInfo = WireFormat(id: 4)
		public static let keyPackage = WireFormat(id: 5)
	}

	public struct ContentType: Hashable, Sendable {
		public let id: UInt8
		public init(id: UInt8) { self.id = id }
		public static let application = ContentType(id: 1)
		public static let proposal = ContentType(id: 2)
		public static let commit = ContentType(id: 3)
	}
}

extension MLS.ProtocolVersion: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt16(id) }
	public init(from reader: inout MLS.Reader) throws { id = try reader.readUInt16() }
}

extension MLS.WireFormat: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt16(id) }
	public init(from reader: inout MLS.Reader) throws { id = try reader.readUInt16() }
}

extension MLS.ContentType: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt8(id) }
	public init(from reader: inout MLS.Reader) throws { id = try reader.readUInt8() }
}

extension MLS {
	/// RFC 9420 §6's `Sender` — a closed 4-way tag, unlike the three types
	/// above: every arm here is fixed by the base spec's framing mechanics
	/// (TBS context-inclusion, membership-tag eligibility) that this
	/// package itself implements, not by a profile's payload types. A new
	/// profile can add wire formats or content types without touching
	/// framing's mechanisms; it cannot add a fifth sender kind without
	/// also rewriting `SignedContent` and the transcript-hash rules.
	public enum Sender: Hashable, Sendable {
		case member(LeafIndex)
		case external(UInt32)
		case newMemberProposal
		case newMemberCommit

		/// FramedContentTBS includes the GroupContext iff the sender is
		/// `member` or `newMemberCommit` (`group/message_signature.rs`).
		public var bindsGroupContext: Bool {
			switch self {
			case .member, .newMemberCommit: true
			case .external, .newMemberProposal: false
			}
		}

		/// PublicMessage carries a membership tag iff the sender is a
		/// current group member.
		public var carriesMembershipTag: Bool {
			if case .member = self { return true }
			return false
		}
	}
}

extension MLS.Sender: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .member(let index):
			writer.writeUInt8(1)
			try index.encode(to: &writer)
		case .external(let index):
			writer.writeUInt8(2)
			writer.writeUInt32(index)
		case .newMemberProposal:
			writer.writeUInt8(3)
		case .newMemberCommit:
			writer.writeUInt8(4)
		}
	}

	public init(from reader: inout MLS.Reader) throws {
		switch try reader.readUInt8() {
		case 1: self = .member(try MLS.LeafIndex(from: &reader))
		case 2: self = .external(try reader.readUInt32())
		case 3: self = .newMemberProposal
		case 4: self = .newMemberCommit
		case let other: throw MLS.FramingError.unknownSenderType(other)
		}
	}
}
