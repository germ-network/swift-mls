import Foundation
import MLSCodec

/// Thin `Data` wrappers, distinct per key kind so an HPKE ciphertext can
/// never be passed where a public key is expected, and vice versa. All are
/// profile-independent — every profile and every `CryptoProvider` shares
/// these, so they sit at the top level rather than nested under either.
extension MLS {
	public struct HpkePublicKey: Hashable, Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}

	// Secret keys deliberately do not conform to MLSCodable: RFC 9420
	// never puts one on the wire, and giving them an encoding would
	// make "accidentally serialize a secret key" a type-checkable
	// mistake instead of an impossible one.
	public struct HpkeSecretKey: Sendable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
	}

	public struct SignaturePublicKey: Hashable, Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}

	public struct SignatureSecretKey: Sendable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
	}

	/// `struct { opaque kem_output<V>; opaque ciphertext<V>; } HPKECiphertext;`
	/// — the result of `EncryptWithLabel`/HPKE seal, as it appears embedded
	/// in other wire structures (e.g. `UpdatePathNode`, `EncryptedGroupSecrets`).
	public struct HpkeCiphertext: Hashable, Sendable, MLSCodable {
		public var kemOutput: Data
		public var ciphertext: Data

		public init(kemOutput: Data, ciphertext: Data) {
			self.kemOutput = kemOutput
			self.ciphertext = ciphertext
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(kemOutput)
			try writer.writeOpaque(ciphertext)
		}

		public init(from reader: inout MLS.Reader) throws {
			kemOutput = Data(try reader.readOpaque())
			ciphertext = Data(try reader.readOpaque())
		}
	}
}
