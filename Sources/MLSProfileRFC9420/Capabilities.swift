import MLSCodec
import MLSCrypto
import MLSFraming

extension MLS.RFC9420 {
	/// RFC 9420 §17.4's Proposal Types registry is extensible, same
	/// reasoning as `ExtensionType`. Declared here (not in `Proposal.swift`,
	/// stage 3b) because `Capabilities` needs it as a vector element type
	/// before `Proposal` itself exists.
	public typealias ProposalType = MLS.ExtensibleEnum<KnownProposalType>

	public enum KnownProposalType: UInt16, RawRepresentable, Sendable, Equatable, Hashable {
		case add = 1
		case update = 2
		case remove = 3
		case preSharedKey = 4
		case reInit = 5
		case externalInit = 6
		case groupContextExtensions = 7
		/// draft-ietf-mls-extensions-09 §7.2.1's `app_data_update` (0x0008). A
		/// non-default extension proposal type — unlike the seven above it is NOT in
		/// `defaultProposalTypes`, so a supporting leaf lists it in
		/// `capabilities.proposals` and a group may require it via
		/// `required_capabilities`.
		case appDataUpdate = 8
	}

	/// `struct { ProtocolVersion versions<V>; CipherSuite cipher_suites<V>;
	/// ExtensionType extensions<V>; ProposalType proposals<V>;
	/// CredentialType credentials<V>; } Capabilities;`
	public struct Capabilities: Sendable, Equatable, MLSCodable {
		public var versions: [MLS.ProtocolVersion]
		public var cipherSuites: [MLS.CipherSuite]
		public var extensions: [ExtensionType]
		public var proposals: [ProposalType]
		public var credentials: [CredentialType]

		public init(
			versions: [MLS.ProtocolVersion], cipherSuites: [MLS.CipherSuite],
			extensions: [ExtensionType], proposals: [ProposalType],
			credentials: [CredentialType]
		) {
			self.versions = versions
			self.cipherSuites = cipherSuites
			self.extensions = extensions
			self.proposals = proposals
			self.credentials = credentials
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encodeVector(versions)
			try writer.encodeVector(cipherSuites)
			try writer.encodeVector(extensions)
			try writer.encodeVector(proposals)
			try writer.encodeVector(credentials)
		}

		public init(from reader: inout MLS.Reader) throws {
			versions = try reader.decodeVector()
			cipherSuites = try reader.decodeVector()
			extensions = try reader.decodeVector()
			proposals = try reader.decodeVector()
			credentials = try reader.decodeVector()
		}
	}
}
