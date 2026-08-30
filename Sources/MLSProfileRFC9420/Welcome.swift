import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming

extension MLS.RFC9420 {
	/// `struct { opaque joiner_secret<V>; optional<PathSecret> path_secret;
	/// PreSharedKeyID psks<V>; } GroupSecrets;` — `PathSecret` is `opaque<V>`.
	public struct GroupSecrets: Sendable, Equatable, MLSCodable {
		public var joinerSecret: Data
		public var pathSecret: Data?
		public var psks: [PreSharedKeyIdentifier]

		public init(joinerSecret: Data, pathSecret: Data?, psks: [PreSharedKeyIdentifier]) {
			self.joinerSecret = joinerSecret
			self.pathSecret = pathSecret
			self.psks = psks
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(joinerSecret)
			try writer.encodeOptional(pathSecret.map(OpaqueField.init))
			try writer.encodeVector(psks)
		}

		public init(from reader: inout MLS.Reader) throws {
			joinerSecret = Data(try reader.readOpaque())
			pathSecret = try reader.decodeOptional(OpaqueField.self)?.data
			psks = try reader.decodeVector()
		}
	}

	/// `struct { KeyPackageRef new_member; HPKECiphertext
	/// encrypted_group_secrets; } EncryptedGroupSecrets;`
	public struct EncryptedGroupSecrets: Sendable, Equatable, MLSCodable {
		public var newMember: MLS.HashReference
		public var encryptedGroupSecrets: MLS.HpkeCiphertext

		public init(newMember: MLS.HashReference, encryptedGroupSecrets: MLS.HpkeCiphertext)
		{
			self.newMember = newMember
			self.encryptedGroupSecrets = encryptedGroupSecrets
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(newMember)
			try writer.encode(encryptedGroupSecrets)
		}

		public init(from reader: inout MLS.Reader) throws {
			newMember = try MLS.HashReference(from: &reader)
			encryptedGroupSecrets = try MLS.HpkeCiphertext(from: &reader)
		}
	}

	/// `struct { CipherSuite cipher_suite; EncryptedGroupSecrets
	/// secrets<V>; opaque encrypted_group_info<V>; } Welcome;`
	public struct Welcome: Sendable, Equatable, MLSCodable {
		public var cipherSuite: MLS.CipherSuite
		public var secrets: [EncryptedGroupSecrets]
		public var encryptedGroupInfo: Data

		public init(
			cipherSuite: MLS.CipherSuite, secrets: [EncryptedGroupSecrets],
			encryptedGroupInfo: Data
		) {
			self.cipherSuite = cipherSuite
			self.secrets = secrets
			self.encryptedGroupInfo = encryptedGroupInfo
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(cipherSuite)
			try writer.encodeVector(secrets)
			try writer.writeOpaque(encryptedGroupInfo)
		}

		public init(from reader: inout MLS.Reader) throws {
			cipherSuite = try MLS.CipherSuite(from: &reader)
			secrets = try reader.decodeVector()
			encryptedGroupInfo = Data(try reader.readOpaque())
		}
	}
}

/// A plain `opaque<V>` wrapper — needed only because `optional<T>`'s
/// generic conformance (`MLSCodec/Protocols.swift`) requires `T: MLSCodable`,
/// and `PathSecret`'s wire shape is bare `opaque<V>`, not a nested struct.
private struct OpaqueField: MLSCodable {
	var data: Data
	init(_ data: Data) { self.data = data }
	func encode(to writer: inout MLS.Writer) throws { try writer.writeOpaque(data) }
	init(from reader: inout MLS.Reader) throws { data = Data(try reader.readOpaque()) }
}
