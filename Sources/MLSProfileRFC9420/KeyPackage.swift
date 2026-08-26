import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming

extension MLS.RFC9420 {
	/// `struct { ProtocolVersion version; CipherSuite cipher_suite;
	/// HPKEPublicKey init_key; LeafNode leaf_node; Extension extensions<V>;
	/// opaque signature<V>; } KeyPackage;`
	public struct KeyPackage: Sendable, Equatable {
		public var version: MLS.ProtocolVersion
		public var cipherSuite: MLS.CipherSuite
		public var initKey: MLS.HpkePublicKey
		public var leafNode: LeafNode
		public var extensions: [Extension]
		public var signature: Data

		public init(
			version: MLS.ProtocolVersion, cipherSuite: MLS.CipherSuite,
			initKey: MLS.HpkePublicKey,
			leafNode: LeafNode, extensions: [Extension], signature: Data
		) {
			self.version = version
			self.cipherSuite = cipherSuite
			self.initKey = initKey
			self.leafNode = leafNode
			self.extensions = extensions
			self.signature = signature
		}
	}
}

extension MLS.RFC9420.KeyPackage: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try version.encode(to: &writer)
		try cipherSuite.encode(to: &writer)
		try initKey.encode(to: &writer)
		try leafNode.encode(to: &writer)
		try writer.encodeVector(extensions)
		try writer.writeOpaque(signature)
	}
}

extension MLS.RFC9420.KeyPackage: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		version = try MLS.ProtocolVersion(from: &reader)
		cipherSuite = try MLS.CipherSuite(from: &reader)
		initKey = try MLS.HpkePublicKey(from: &reader)
		leafNode = try MLS.RFC9420.LeafNode(from: &reader)
		extensions = try reader.decodeVector()
		signature = Data(try reader.readOpaque())
	}
}

extension MLS.RFC9420.KeyPackage {
	/// `KeyPackageTBS` — every field above except `signature`.
	public func toBeSigned() throws -> Data {
		var writer = MLS.Writer()
		try version.encode(to: &writer)
		try cipherSuite.encode(to: &writer)
		try initKey.encode(to: &writer)
		try leafNode.encode(to: &writer)
		try writer.encodeVector(extensions)
		return Data(writer.bytes)
	}

	/// `MakeKeyPackageRef` — `RefHash("MLS 1.0 KeyPackage Reference",
	/// Encode(KeyPackage))`, over the *whole* signed package, not just the
	/// TBS — unlike the signature, which excludes itself.
	public func reference(_ provider: any MLS.CipherSuiteProvider) throws -> MLS.HashReference {
		guard provider.cipherSuite == cipherSuite else {
			throw MLS.RFC9420.WireError.cipherSuiteMismatch
		}
		return try MLS.HashReference.compute(
			provider, label: "MLS 1.0 KeyPackage Reference", value: try mlsEncoded())
	}
}
