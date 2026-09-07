import MLSCodec
import MLSProfileRFC9420

// draft-ietf-mls-combiner-02 §7's paired APQ structures — a classical (traditional)
// half and a PQ half of the same RFC 9420 object. Each is the trivial MLS-presentation
// struct `{ X t_*; X pq_*; }`, so the codec is `encode(t) ‖ encode(pq)`, each field via
// its own type's `MLSCodable` (the profile types already conform). This draft §7 codec
// is the GENERIC default; the deployed TwoMLSPQ wire uses Germ tag+length framing
// instead (`[tag][u32-LE a_len][a][u32-LE b_len][b]`), which twomlspq-swift supplies as
// a compat override reading `.t`/`.pq` — swift-mls owns the logical pairs + the draft
// codec, not the deployed framing.
//
// `APQPartialGroupInfo` is DEFERRED: its base `PartialGroupInfo` is not an RFC 9420
// type and appears nowhere in the deployed code or this profile, so TwoMLSPQ does not
// use it. The five structs below are the deployed set.

extension MLS.Combiner {
	/// `struct { KeyPackage t_key_package; KeyPackage pq_key_package; } APQKeyPackage`
	public struct APQKeyPackage: Sendable, Equatable, MLSCodable {
		public var tKeyPackage: MLS.RFC9420.KeyPackage
		public var pqKeyPackage: MLS.RFC9420.KeyPackage

		public init(
			tKeyPackage: MLS.RFC9420.KeyPackage, pqKeyPackage: MLS.RFC9420.KeyPackage
		) {
			self.tKeyPackage = tKeyPackage
			self.pqKeyPackage = pqKeyPackage
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(tKeyPackage)
			try writer.encode(pqKeyPackage)
		}

		public init(from reader: inout MLS.Reader) throws {
			tKeyPackage = try MLS.RFC9420.KeyPackage(from: &reader)
			pqKeyPackage = try MLS.RFC9420.KeyPackage(from: &reader)
		}
	}

	/// `struct { MLSPublicMessage t_message; MLSPublicMessage pq_message; } APQPublicMessage`
	public struct APQPublicMessage: Sendable, Equatable, MLSCodable {
		public var tMessage: MLS.RFC9420.PublicMessage
		public var pqMessage: MLS.RFC9420.PublicMessage

		public init(
			tMessage: MLS.RFC9420.PublicMessage, pqMessage: MLS.RFC9420.PublicMessage
		) {
			self.tMessage = tMessage
			self.pqMessage = pqMessage
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(tMessage)
			try writer.encode(pqMessage)
		}

		public init(from reader: inout MLS.Reader) throws {
			tMessage = try MLS.RFC9420.PublicMessage(from: &reader)
			pqMessage = try MLS.RFC9420.PublicMessage(from: &reader)
		}
	}

	/// `struct { MLSPrivateMessage t_message; MLSPrivateMessage pq_message; } APQPrivateMessage`
	///
	/// A FULL commit travels as this — `t_message` carries the classical commit,
	/// `pq_message` the PQ one. draft §7 adds one validity rule: "Messages in
	/// APQPrivateMessage MUST NOT be of content type application" — enforced by
	/// [`validate()`], not at wire decode (a decoder reports structural failures; the
	/// content-type rule is a separate semantic check the caller runs).
	public struct APQPrivateMessage: Sendable, Equatable, MLSCodable {
		public var tMessage: MLS.RFC9420.PrivateMessage
		public var pqMessage: MLS.RFC9420.PrivateMessage

		public init(
			tMessage: MLS.RFC9420.PrivateMessage, pqMessage: MLS.RFC9420.PrivateMessage
		) {
			self.tMessage = tMessage
			self.pqMessage = pqMessage
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(tMessage)
			try writer.encode(pqMessage)
		}

		public init(from reader: inout MLS.Reader) throws {
			tMessage = try MLS.RFC9420.PrivateMessage(from: &reader)
			pqMessage = try MLS.RFC9420.PrivateMessage(from: &reader)
		}

		/// draft §7: neither half may carry `application` content — an `APQPrivateMessage`
		/// frames handshake messages (a FULL commit's two halves), not application data.
		public func validate() throws {
			guard tMessage.contentType != .application,
				pqMessage.contentType != .application
			else {
				throw MLS.Combiner.Error.commitShapeMismatch
			}
		}
	}

	/// `struct { Welcome t_welcome; Welcome pq_welcome; } APQWelcome`
	public struct APQWelcome: Sendable, Equatable, MLSCodable {
		public var tWelcome: MLS.RFC9420.Welcome
		public var pqWelcome: MLS.RFC9420.Welcome

		public init(tWelcome: MLS.RFC9420.Welcome, pqWelcome: MLS.RFC9420.Welcome) {
			self.tWelcome = tWelcome
			self.pqWelcome = pqWelcome
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(tWelcome)
			try writer.encode(pqWelcome)
		}

		public init(from reader: inout MLS.Reader) throws {
			tWelcome = try MLS.RFC9420.Welcome(from: &reader)
			pqWelcome = try MLS.RFC9420.Welcome(from: &reader)
		}
	}

	/// `struct { GroupInfo t_group_info; GroupInfo pq_group_info; } APQGroupInfo`
	public struct APQGroupInfo: Sendable, Equatable, MLSCodable {
		public var tGroupInfo: MLS.RFC9420.GroupInfo
		public var pqGroupInfo: MLS.RFC9420.GroupInfo

		public init(
			tGroupInfo: MLS.RFC9420.GroupInfo, pqGroupInfo: MLS.RFC9420.GroupInfo
		) {
			self.tGroupInfo = tGroupInfo
			self.pqGroupInfo = pqGroupInfo
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(tGroupInfo)
			try writer.encode(pqGroupInfo)
		}

		public init(from reader: inout MLS.Reader) throws {
			tGroupInfo = try MLS.RFC9420.GroupInfo(from: &reader)
			pqGroupInfo = try MLS.RFC9420.GroupInfo(from: &reader)
		}
	}
}
