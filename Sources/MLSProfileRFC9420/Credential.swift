import Foundation
import MLSCodec

extension MLS.RFC9420 {
	public typealias CredentialType = MLS.ExtensibleEnum<KnownCredentialType>

	public enum KnownCredentialType: UInt16, RawRepresentable, Sendable, Equatable, Hashable {
		case basic = 1
		case x509 = 2
	}

	/// `struct { CredentialType credential_type; select
	/// (Credential.credential_type) { case basic: opaque identity<V>;
	/// case x509: Certificate certificates<V>; }; } Credential;` where
	/// `struct { opaque cert_data<V>; } Certificate;`.
	///
	/// RFC 9420's `select` has no generic length prefix, so a credential
	/// type this package doesn't recognize is not skippable purely from
	/// the wire — an implementation would need out-of-band knowledge of
	/// that type's body shape. mls-rs works around this for its own
	/// forward compatibility by treating anything past `basic`/`x509` as
	/// `opaque<V>` (`mls-rs-core/src/identity/credential.rs:206-212`); this
	/// type follows the same convention, and applies it to `x509` too
	/// (deferred — see `germ-swift-mls/docs/plan.md`'s credential section
	/// — so its `certificates<V>` body is carried as opaque bytes for
	/// round-trip purposes, not parsed).
	public enum Credential: Sendable, Equatable {
		case basic(identity: Data)
		case other(type: CredentialType, data: Data)
	}
}

extension MLS.RFC9420.Credential: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .basic(let identity):
			try writer.encode(MLS.RFC9420.CredentialType(.basic))
			try writer.writeOpaque(identity)
		case .other(let type, let data):
			try writer.encode(type)
			try writer.writeOpaque(data)
		}
	}

	public init(from reader: inout MLS.Reader) throws {
		let type = try MLS.RFC9420.CredentialType(from: &reader)
		let data = Data(try reader.readOpaque())
		if type == MLS.RFC9420.CredentialType(.basic) {
			self = .basic(identity: data)
		} else {
			self = .other(type: type, data: data)
		}
	}
}
