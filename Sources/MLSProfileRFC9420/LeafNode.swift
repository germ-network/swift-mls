import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.RFC9420 {
	/// `enum { reserved(0), key_package(1), update(2), commit(3), (255) }
	/// LeafNodeSource;` paired with its `select` payload as one Swift
	/// enum — the tag and its
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
			try writer.encode(lifetime)
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
		try writer.encode(encryptionKey)
		try writer.encode(signatureKey)
		try writer.encode(credential)
		try writer.encode(capabilities)
		try writer.encode(source)
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
	/// Where a `LeafNode` was found. Not "what to append to the TBS" — RFC
	/// 9420 §7.2's second `select (LeafNodeTBS.leaf_node_source)` decides
	/// that from the leaf's own `source`, and nothing else.
	///
	/// GER-2345. `toBeSigned` used to take the binding itself, as an
	/// optional `(groupID, leafIndex)`, and throw when it disagreed with
	/// `source`. That made two things wrong at once. Callers had to
	/// pre-compute the `source` switch to decide what to pass, so
	/// `Group.validateLeaves` carried a copy of the same three-way match
	/// this file already performs; and the mismatch it threw on was API
	/// misuse, not a wire condition, so an unreachable error case sat in
	/// the middle of a validation path.
	///
	/// Taking the *placement* instead makes the API-misuse half
	/// unrepresentable — a caller states where it found the leaf, which it
	/// always knows, and never chooses the encoding. What survives as a
	/// throw is a real §7.3/§10 violation: a leaf in a KeyPackage whose
	/// source claims a group it cannot have been in.
	public enum Placement: Sendable, Equatable {
		/// At a known index in a known group's ratchet tree — a tree being
		/// joined, an Update proposal, or a Commit's `UpdatePath`. A
		/// `key_package`-sourced leaf reached this way is normal (a member
		/// added but never yet updated) and still signs without the
		/// binding.
		case inGroup(groupID: Data, leafIndex: MLS.LeafIndex)
		/// In a `KeyPackage`, which belongs to no group yet.
		case keyPackage
	}

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
	public func toBeSigned(placement: Placement) throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(encryptionKey)
		try writer.encode(signatureKey)
		try writer.encode(credential)
		try writer.encode(capabilities)
		try writer.encode(source)
		try writer.encodeVector(extensions)
		switch (source, placement) {
		case (.keyPackage, _):
			break
		case (.update, .inGroup(let groupID, let leafIndex)),
			(.commit, .inGroup(let groupID, let leafIndex)):
			try writer.writeOpaque(groupID)
			try writer.encode(leafIndex)
		case (.update, .keyPackage), (.commit, .keyPackage):
			throw MLS.RFC9420.WireError.leafNodeSourceNotKeyPackage
		}
		return Data(writer.bytes)
	}

	/// RFC 9420 §7.3's "Verify that the signature on the LeafNode is valid
	/// using signature_key" -- the half of leaf validation that's
	/// authenticity, not policy (contrast lifetime bounds,
	/// capability/extension consistency, `required_capabilities`
	/// satisfaction, and §5.3.1 credential validation, which stay
	/// deferred). The "LeafNodeTBS" label and the signed structure itself
	/// are §7.2's; §12.4.3.1's tree-integrity bullet delegates here
	/// ("validate the LeafNode as described in Section 7.3"), which is why
	/// a joiner runs this over every non-blank leaf. `placement` says where
	/// the leaf was found; the leaf's own `source` decides what the TBS
	/// binds -- see `toBeSigned`'s own doc comment.
	public func verifySignature(
		_ provider: any MLS.CipherSuiteProvider, placement: Placement
	) throws {
		let valid = try MLS.verifyWithLabel(
			provider, publicKey: signatureKey, label: "LeafNodeTBS",
			content: try toBeSigned(placement: placement), signature: signature)
		guard valid else { throw MLS.CryptoError.signatureVerificationFailed }
	}
}
