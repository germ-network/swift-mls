import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.RFC9420 {
	/// `enum { key_package(1), update(2), commit(3) } LeafNodeSourceType;`
	/// paired with its `select` payload as one Swift enum — the tag and its
	/// payload are written back-to-back on the wire with no length prefix
	/// between them, exactly what an enum-with-payload's encode already
	/// does, so there is no separate "select" type the way `Credential`
	/// needed one (that select has three cases with genuinely different
	/// shapes and an unknown-type escape hatch; this one is closed and
	/// every case is a fixed field this package itself defines).
	public enum LeafNodeSource: Sendable, Equatable {
		case keyPackage(Lifetime)
		case update
		case commit(parentHash: Data)
	}

	/// `struct { HPKEPublicKey encryption_key; SignaturePublicKey
	/// signature_key; Credential credential; Capabilities capabilities;
	/// LeafNodeSource leaf_node_source; select(...) {...}; Extension
	/// extensions<V>; opaque signature<V>; } LeafNode;`
	///
	/// (`signature_key`+`credential` is RFC 9420's `SigningIdentity`,
	/// inlined here rather than kept as its own nested type — nothing else
	/// in this phase needs a standalone `SigningIdentity`, and RFC 9420's
	/// wire encoding is identical either way since `SigningIdentity` has
	/// no framing of its own.)
	public struct LeafNode: Sendable, Equatable {
		public var encryptionKey: MLS.HpkePublicKey
		public var signatureKey: MLS.SignaturePublicKey
		public var credential: Credential
		public var capabilities: Capabilities
		public var source: LeafNodeSource
		public var extensions: [Extension]
		public var signature: Data

		public init(
			encryptionKey: MLS.HpkePublicKey, signatureKey: MLS.SignaturePublicKey,
			credential: Credential, capabilities: Capabilities, source: LeafNodeSource,
			extensions: [Extension], signature: Data
		) {
			self.encryptionKey = encryptionKey
			self.signatureKey = signatureKey
			self.credential = credential
			self.capabilities = capabilities
			self.source = source
			self.extensions = extensions
			self.signature = signature
		}
	}
}

extension MLS.RFC9420.LeafNodeSource: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .keyPackage(let lifetime):
			writer.writeUInt8(1)
			try lifetime.encode(to: &writer)
		case .update:
			writer.writeUInt8(2)
		case .commit(let parentHash):
			writer.writeUInt8(3)
			try writer.writeOpaque(parentHash)
		}
	}
}

extension MLS.RFC9420.LeafNodeSource: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		switch try reader.readUInt8() {
		case 1: self = .keyPackage(try MLS.RFC9420.Lifetime(from: &reader))
		case 2: self = .update
		case 3: self = .commit(parentHash: Data(try reader.readOpaque()))
		case let other: throw MLS.RFC9420.WireError.unknownLeafNodeSource(other)
		}
	}
}

extension MLS.RFC9420.LeafNode: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try encryptionKey.encode(to: &writer)
		try signatureKey.encode(to: &writer)
		try credential.encode(to: &writer)
		try capabilities.encode(to: &writer)
		try source.encode(to: &writer)
		try writer.encodeVector(extensions)
		try writer.writeOpaque(signature)
	}
}

extension MLS.RFC9420.LeafNode: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		encryptionKey = try MLS.HpkePublicKey(from: &reader)
		signatureKey = try MLS.SignaturePublicKey(from: &reader)
		credential = try MLS.RFC9420.Credential(from: &reader)
		capabilities = try MLS.RFC9420.Capabilities(from: &reader)
		source = try MLS.RFC9420.LeafNodeSource(from: &reader)
		extensions = try reader.decodeVector()
		signature = Data(try reader.readOpaque())
	}
}

extension MLS.RFC9420.LeafNode {
	/// `LeafNodeTBS` — the six pre-signature fields above, then `group_id`
	/// and `leaf_index` iff `source` is `update` or `commit` (never for
	/// `key_package`, where a leaf isn't yet bound to any group).
	///
	/// A free-standing assembly rather than a stored `SignedContent`-style
	/// parts type (contrast `MLSFraming/SignedContent.swift`'s §4.2
	/// design): nothing here needs a *second* encoding of these same
	/// fields the way a later profile's TBH needs a second encoding of
	/// `FramedContentTBS`'s content. If that need arises, this is the
	/// function to split.
	public func toBeSigned(groupContext: (groupID: Data, leafIndex: MLS.LeafIndex)?) throws
		-> Data
	{
		var writer = MLS.Writer()
		try encryptionKey.encode(to: &writer)
		try signatureKey.encode(to: &writer)
		try credential.encode(to: &writer)
		try capabilities.encode(to: &writer)
		try source.encode(to: &writer)
		try writer.encodeVector(extensions)
		if let (groupID, leafIndex) = groupContext {
			try writer.writeOpaque(groupID)
			try leafIndex.encode(to: &writer)
		}
		return Data(writer.bytes)
	}
}
