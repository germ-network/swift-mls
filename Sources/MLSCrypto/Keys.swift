import MLSCodec
import Foundation

/// Thin `Data` wrappers, distinct per key kind so an HPKE ciphertext can
/// never be passed where a public key is expected, and vice versa. All are
/// profile-independent — every profile and every `CryptoProvider` shares
/// these, so they sit at the top level rather than nested under either.
extension MLS {
    public struct HpkePublicKey: Hashable, Sendable, MLSCodable {
        public var data: Data
        public init(_ data: Data) { self.data = data }
        public func encode(to writer: inout MLS.Writer) throws { try writer.writeOpaque(data) }
        public init(from reader: inout MLS.Reader) throws { data = Data(try reader.readOpaque()) }
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
        public func encode(to writer: inout MLS.Writer) throws { try writer.writeOpaque(data) }
        public init(from reader: inout MLS.Reader) throws { data = Data(try reader.readOpaque()) }
    }

    public struct SignatureSecretKey: Sendable {
        public var data: Data
        public init(_ data: Data) { self.data = data }
    }
}
