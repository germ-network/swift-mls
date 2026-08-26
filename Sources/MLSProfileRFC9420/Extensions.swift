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
			try type.encode(to: &writer)
			try writer.writeOpaque(data)
		}

		public init(from reader: inout MLS.Reader) throws {
			type = try ExtensionType(from: &reader)
			data = Data(try reader.readOpaque())
		}
	}
}
