import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420 {
	/// `struct { GroupContext group_context; Extension extensions<V>; MAC
	/// confirmation_tag; uint32 signer; opaque signature<V>; } GroupInfo;`
	public struct GroupInfo: Sendable, Equatable {
		public var groupContext: GroupContext
		public var extensions: [Extension]
		public var confirmationTag: MLS.ConfirmationTag
		public var signer: MLS.LeafIndex
		public var signature: Data

		public init(
			groupContext: GroupContext, extensions: [Extension],
			confirmationTag: MLS.ConfirmationTag,
			signer: MLS.LeafIndex, signature: Data
		) {
			self.groupContext = groupContext
			self.extensions = extensions
			self.confirmationTag = confirmationTag
			self.signer = signer
			self.signature = signature
		}
	}
}

extension MLS.RFC9420.GroupInfo: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try writer.encode(groupContext)
		try writer.encodeVector(extensions)
		try writer.encode(confirmationTag)
		try writer.encode(signer)
		try writer.writeOpaque(signature)
	}
}

extension MLS.RFC9420.GroupInfo: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		groupContext = try MLS.RFC9420.GroupContext(from: &reader)
		extensions = try reader.decodeVector()
		confirmationTag = try MLS.ConfirmationTag(from: &reader)
		signer = try MLS.LeafIndex(from: &reader)
		signature = Data(try reader.readOpaque())
	}
}

extension MLS.RFC9420.GroupInfo {
	/// `GroupInfoTBS` — every field above except `signature`.
	public func toBeSigned() throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(groupContext)
		try writer.encodeVector(extensions)
		try writer.encode(confirmationTag)
		try writer.encode(signer)
		return Data(writer.bytes)
	}

	/// RFC 9420 §12.4.3.1: verify `signature` under `SignWithLabel`'s
	/// "GroupInfoTBS" label. Throws rather than returning `Bool` — a
	/// caller cannot silently ignore a throw the way it can drop a `Bool`,
	/// matching `unprotectPrivate`'s choice over `verifyPublic`'s
	/// (`Protect.swift`) for exactly this reason.
	public func verifySignature(
		_ provider: any MLS.CipherSuiteProvider, signatureKey: MLS.SignaturePublicKey
	) throws {
		let valid = try MLS.verifyWithLabel(
			provider, publicKey: signatureKey, label: "GroupInfoTBS",
			content: try toBeSigned(), signature: signature)
		guard valid else { throw MLS.CryptoError.signatureVerificationFailed }
	}

	/// The `ratchet_tree` extension's payload decoded to `[Node?]`, or nil
	/// if this `GroupInfo` carries none. Lives in `extensions`, **not**
	/// `groupContext.extensions` — the two are distinct vectors, and only
	/// this one is where RFC 9420 puts the out-of-band tree.
	public func ratchetTreeExtension() throws -> [MLS.RFC9420.Node?]? {
		guard
			let treeExtension = extensions.first(where: {
				$0.type == MLS.RFC9420.ExtensionType(.ratchetTree)
			})
		else { return nil }
		var reader = MLS.Reader(treeExtension.data)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return nodes
	}
}
