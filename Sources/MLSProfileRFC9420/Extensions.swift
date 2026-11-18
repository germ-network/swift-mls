import Foundation
import MLSCodec

extension MLS.RFC9420 {
	/// RFC 9420 §17.3's Extension Types registry is extensible. §13.4:
	/// "A client processing a KeyPackage object MUST ignore ... all
	/// unknown extensions" — an unrecognized value must round-trip, not
	/// be rejected. `MLS.ExtensibleEnum` exists for exactly this.
	public typealias ExtensionType = MLS.ExtensibleEnum<KnownExtensionType>

	public enum KnownExtensionType: UInt16, RawRepresentable, Sendable, Equatable, Hashable {
		case applicationID = 1
		case ratchetTree = 2
		case requiredCapabilities = 3
		case externalPub = 4
		case externalSenders = 5
	}

	/// `struct { ExtensionType extension_type; opaque extension_data<V>; } Extension;`
	public struct Extension: Sendable, Equatable, MLSCodable {
		public var type: ExtensionType
		public var data: Data

		public init(type: ExtensionType, data: Data) {
			self.type = type
			self.data = data
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(type)
			try writer.writeOpaque(data)
		}

		public init(from reader: inout MLS.Reader) throws {
			type = try ExtensionType(from: &reader)
			data = Data(try reader.readOpaque())
		}
	}
}

extension MLS.Reader {
	/// Decodes an `Extension extensions<V>` field, enforcing §13.4's
	/// one-extension-per-type rule (`checkUniqueTypes`).
	mutating func decodeExtensionList() throws -> [MLS.RFC9420.Extension] {
		let extensions: [MLS.RFC9420.Extension] = try decodeVector()
		try extensions.checkUniqueTypes()
		return extensions
	}
}

extension MLS.Writer {
	/// Encodes an `Extension extensions<V>` field, refusing to write one that
	/// breaks §13.4's one-extension-per-type rule (`checkUniqueTypes`), so
	/// nothing this library encodes fails to decode.
	mutating func encodeExtensionList(_ extensions: [MLS.RFC9420.Extension]) throws {
		try encodeVector(extensions)
	}
}

extension [MLS.RFC9420.Extension] {
	/// Throws `WireError.duplicateExtensionType` if two entries share a type.
	/// RFC 9420 §13.4: "Any field containing a list of extensions MUST NOT have
	/// more than one extension of any given type." Compares wire values, since a
	/// hand-built `.unknown(raw)` is unequal to the `.known` case with the same
	/// raw value.
	func checkUniqueTypes() throws {
		var seen = Set<UInt16>()
		for ext in self where !seen.insert(ext.type.rawValue).inserted {
			throw MLS.RFC9420.WireError.duplicateExtensionType(ext.type)
		}
	}
}
