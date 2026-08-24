import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming

extension MLS.RFC9420 {
	/// `struct { ProtocolVersion version; CipherSuite cipher_suite; opaque
	/// group_id<V>; uint64 epoch; opaque tree_hash<V>; opaque
	/// confirmed_transcript_hash<V>; Extension extensions<V>; } GroupContext;`
	public struct GroupContext: Sendable, Equatable, MLSCodable {
		public var version: MLS.ProtocolVersion
		public var cipherSuite: MLS.CipherSuite
		public var groupID: Data
		public var epoch: UInt64
		public var treeHash: Data
		public var confirmedTranscriptHash: Data
		public var extensions: [Extension]

		public init(
			version: MLS.ProtocolVersion, cipherSuite: MLS.CipherSuite, groupID: Data,
			epoch: UInt64,
			treeHash: Data, confirmedTranscriptHash: Data, extensions: [Extension]
		) {
			self.version = version
			self.cipherSuite = cipherSuite
			self.groupID = groupID
			self.epoch = epoch
			self.treeHash = treeHash
			self.confirmedTranscriptHash = confirmedTranscriptHash
			self.extensions = extensions
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try version.encode(to: &writer)
			try cipherSuite.encode(to: &writer)
			try writer.writeOpaque(groupID)
			writer.writeUInt64(epoch)
			try writer.writeOpaque(treeHash)
			try writer.writeOpaque(confirmedTranscriptHash)
			try writer.encodeVector(extensions)
		}

		public init(from reader: inout MLS.Reader) throws {
			version = try MLS.ProtocolVersion(from: &reader)
			cipherSuite = try MLS.CipherSuite(from: &reader)
			groupID = Data(try reader.readOpaque())
			epoch = try reader.readUInt64()
			treeHash = Data(try reader.readOpaque())
			confirmedTranscriptHash = Data(try reader.readOpaque())
			extensions = try reader.decodeVector()
		}
	}
}
