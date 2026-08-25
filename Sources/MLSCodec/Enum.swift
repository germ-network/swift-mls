/// Two decode behaviors for an enumerated wire value. Which one a type
/// needs is a property of the *field* it appears in, not of the type.
///
/// RFC 9420 §2.1 adopts the TLS presentation language, whose default
/// (RFC 8446 §3.5) is permissive: implementations "parse and ignore
/// unknown values unless the definition of the field states otherwise."
/// Rejecting is the exception, and needs a reason.
///
/// - ``MLSClosedEnum`` rejects an unrecognized value. The reason that
///   actually applies is skippability: where the value is a `select`
///   discriminant over variants carrying no length prefix of their own,
///   an unknown one leaves the rest of the struct unparseable, so there
///   is nothing to skip to.
/// - ``MLS/ExtensibleEnum`` carries the raw value through. A code point
///   that only tags a self-delimiting field — sitting beside an
///   `opaque<V>` payload, or as a bare entry in a capabilities list —
///   leaves the bytes parseable either way, so whether an unsupported
///   value is *tolerated* is a protocol-layer call this target has no
///   business making. RFC 9420 §13.4 requires ignoring unknown
///   capability and extension entries; §13.5 names four fields where an
///   unsupported value instead rejects the enclosing message. Both
///   answers need the raw value preserved to be reachable at all.
///
/// A `RawRepresentable` enum with a plain `MLSCodable` conformance is
/// neither — it takes the rejecting path silently, which is the case
/// needing justification, not the default.
///
/// Deliberately no list of which RFC 9420 types land where: this target
/// defines none of them, and one code point can need both behaviors — a
/// proposal type is fatal as `Proposal`'s own discriminant, ignorable as
/// an entry in `Capabilities.proposals`.
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
	where
		Known: RawRepresentable & Sendable & Equatable & Hashable,
		Known.RawValue: FixedWidthInteger & UnsignedInteger & Sendable
	{
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
