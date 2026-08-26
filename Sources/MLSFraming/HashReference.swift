import Foundation
import MLSCodec
import MLSCrypto

extension MLS {
	/// The result of `RefHash` (`MLS.refHash` in `MLSCrypto`) — a `Data`
	/// wrapper distinct from a raw hash output so a `KeyPackageRef` can't
	/// be passed where any other hash is expected, matching the convention
	/// in `Keys.swift` for HPKE/signature keys.
	public struct HashReference: Hashable, Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}
}

extension MLS.HashReference {
	/// `RefHash(label, value)`, wrapped. `label` is used as given — see
	/// `MLS.refHash`'s own doc comment for why it isn't auto-prefixed with
	/// "MLS 1.0 ".
	public static func compute(
		_ provider: any MLS.CipherSuiteProvider, label: String, value: Data
	) throws -> MLS.HashReference {
		MLS.HashReference(try MLS.refHash(provider, label: label, value: value))
	}
}
