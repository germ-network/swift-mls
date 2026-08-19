/// RFC 9420 splits its enums into two policies (§17.1), and getting this
/// wrong breaks interop in opposite directions:
///
/// - **Closed** — `WireFormat`, `ContentType`, `SenderType`, `NodeType`.
///   Every value is defined by the RFC; a decoder MUST reject anything
///   else. Conform to ``MLSClosedEnum``.
/// - **Extensible** — `ProposalType`, `ExtensionType`, `CredentialType`,
///   `ProtocolVersion`. New values are expected (that is the whole point
///   of `required_capabilities` and GREASE-style forward compatibility),
///   so a decoder MUST preserve an unrecognized value rather than reject
///   it — rejecting would make an unrelated future extension unparsable.
///   Use ``MLS/ExtensibleEnum``.
///
/// A `RawRepresentable` enum with a plain `MLSCodable` conformance is
/// neither of these — it would silently pick the closed policy by
/// throwing on decode, which is wrong for half of RFC 9420's enums.
public protocol MLSClosedEnum: MLSCodable, RawRepresentable, Sendable
where RawValue: MLSCodable & FixedWidthInteger & UnsignedInteger {}

extension MLSClosedEnum {
    public func encode(to writer: inout MLS.Writer) throws {
        try rawValue.encode(to: &writer)
    }

    public init(from reader: inout MLS.Reader) throws {
        let raw = try RawValue(from: &reader)
        guard let value = Self(rawValue: raw) else {
            throw MLS.CodecError.unknownEnumValue(UInt64(raw))
        }
        self = value
    }
}

extension MLS {
    /// An RFC 9420 extensible enum: a known case, or an unrecognized raw
    /// value carried through unchanged. See ``MLSClosedEnum`` for why this
    /// must not simply reject unknown values.
    public enum ExtensibleEnum<Known>: Sendable, Equatable, Hashable
    where Known: RawRepresentable & Sendable & Equatable & Hashable,
          Known.RawValue: FixedWidthInteger & UnsignedInteger & Sendable {
        case known(Known)
        case unknown(Known.RawValue)

        public var rawValue: Known.RawValue {
            switch self {
            case .known(let value): value.rawValue
            case .unknown(let raw): raw
            }
        }

        public init(_ known: Known) { self = .known(known) }

        public init(rawValue: Known.RawValue) {
            self = Known(rawValue: rawValue).map(Self.known) ?? .unknown(rawValue)
        }
    }
}

extension MLS.ExtensibleEnum: MLSEncodable where Known.RawValue: MLSEncodable {
    public func encode(to writer: inout MLS.Writer) throws {
        try rawValue.encode(to: &writer)
    }
}

extension MLS.ExtensibleEnum: MLSDecodable where Known.RawValue: MLSDecodable {
    public init(from reader: inout MLS.Reader) throws {
        self.init(rawValue: try Known.RawValue(from: &reader))
    }
}
