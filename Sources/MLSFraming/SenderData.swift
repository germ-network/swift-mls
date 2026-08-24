import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.Framing {
	/// `struct { uint32 leaf_index; uint32 generation; opaque
	/// reuse_guard[4]; } SenderData;` — `reuse_guard` is a fixed-size
	/// field (`[4]`, not `<V>`): four raw bytes, no length prefix.
	public struct SenderData: Sendable, Equatable, MLSCodable {
		public var leafIndex: MLS.LeafIndex
		public var generation: UInt32
		public var reuseGuard: ReuseGuard

		public init(leafIndex: MLS.LeafIndex, generation: UInt32, reuseGuard: ReuseGuard) {
			self.leafIndex = leafIndex
			self.generation = generation
			self.reuseGuard = reuseGuard
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try leafIndex.encode(to: &writer)
			writer.writeUInt32(generation)
			writer.writeBytes(reuseGuard.bytes)
		}

		public init(from reader: inout MLS.Reader) throws {
			leafIndex = try MLS.LeafIndex(from: &reader)
			generation = try reader.readUInt32()
			reuseGuard = ReuseGuard(Data(try reader.readBytes(4)))
		}
	}

	/// `struct { opaque group_id<V>; uint64 epoch; ContentType
	/// content_type; } SenderDataAAD;` — encode-only: this is the AEAD
	/// associated data for sealing/opening `SenderData`, never decoded on
	/// its own from an untrusted stream (a peer never sends it separately;
	/// the recipient reconstructs it from fields it already has).
	public struct SenderDataAAD: Sendable {
		public var groupID: Data
		public var epoch: UInt64
		public var contentType: MLS.ContentType

		public init(groupID: Data, epoch: UInt64, contentType: MLS.ContentType) {
			self.groupID = groupID
			self.epoch = epoch
			self.contentType = contentType
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(groupID)
			writer.writeUInt64(epoch)
			try contentType.encode(to: &writer)
		}
	}

	/// RFC 9420 §6.3.2: the sender-data key/nonce, derived from the first
	/// `Nh` bytes of the ciphertext itself (or the whole ciphertext, if
	/// shorter) — not from any per-message secret, since the recipient
	/// doesn't know who sent a message, or its generation, until *after*
	/// decrypting the sender data that names them.
	public static func senderDataKeyNonce(
		_ provider: any MLS.CipherSuiteProvider, secret: Data, ciphertextSample: Data
	) throws -> (key: Data, nonce: Data) {
		let sample = Data(ciphertextSample.prefix(provider.hashSize))
		let key = try MLS.expandWithLabel(
			provider, secret: secret, label: "key", context: sample,
			length: provider.aeadKeySize)
		let nonce = try MLS.expandWithLabel(
			provider, secret: secret, label: "nonce", context: sample,
			length: provider.aeadNonceSize)
		return (key, nonce)
	}

	public static func sealSenderData(
		_ provider: any MLS.CipherSuiteProvider, key: Data, nonce: Data,
		senderData: SenderData, aad: SenderDataAAD
	) throws -> Data {
		var senderDataWriter = MLS.Writer()
		try senderData.encode(to: &senderDataWriter)
		var aadWriter = MLS.Writer()
		try aad.encode(to: &aadWriter)
		return try provider.aeadSeal(
			key: key, nonce: nonce, aad: Data(aadWriter.bytes),
			plaintext: Data(senderDataWriter.bytes))
	}

	public static func openSenderData(
		_ provider: any MLS.CipherSuiteProvider, key: Data, nonce: Data,
		ciphertext: Data, aad: SenderDataAAD
	) throws -> SenderData {
		var aadWriter = MLS.Writer()
		try aad.encode(to: &aadWriter)
		let plaintext = try provider.aeadOpen(
			key: key, nonce: nonce, aad: Data(aadWriter.bytes), ciphertext: ciphertext)
		var reader = MLS.Reader(plaintext)
		let senderData = try SenderData(from: &reader)
		try reader.finish()
		return senderData
	}
}
