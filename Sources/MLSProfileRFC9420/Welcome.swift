import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule

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

extension MLS.RFC9420.Welcome {
	/// RFC 9420 §12.4.3.1: HPKE-decrypt the `GroupSecrets` entry matching
	/// `keyPackageRef`. The HPKE context is this `Welcome`'s own
	/// `encryptedGroupInfo` field, not empty -- `DecryptWithLabel(init_key_priv,
	/// "Welcome", encrypted_group_info, kem_output, ciphertext)` binds the
	/// two together, so an attacker can't splice a `GroupSecrets` ciphertext
	/// from one Welcome onto another's `encrypted_group_info`.
	public func decryptGroupSecrets(
		_ provider: any MLS.CipherSuiteProvider,
		keyPackageRef: MLS.HashReference, initKey: MLS.HpkeSecretKey
	) throws -> MLS.RFC9420.GroupSecrets {
		guard let entry = secrets.first(where: { $0.newMember == keyPackageRef }) else {
			throw MLS.RFC9420.GroupError.noMatchingWelcomeSecret
		}
		let plaintext = try MLS.decryptWithLabel(
			provider, privateKey: initKey, label: "Welcome",
			context: encryptedGroupInfo,
			enc: entry.encryptedGroupSecrets.kemOutput,
			ciphertext: entry.encryptedGroupSecrets.ciphertext)
		return try MLS.RFC9420.GroupSecrets(mlsEncoded: plaintext)
	}

	/// RFC 9420 §12.4.3.1: AEAD-decrypt `encryptedGroupInfo`. `welcome_key`/
	/// `welcome_nonce` only need `joinerSecret`/`pskSecret` -- not the group
	/// context, which doesn't exist from a joiner's perspective until this
	/// call succeeds -- so `MLS.KeySchedule.welcomeKeyNonce` derives them
	/// directly rather than through `fromJoinerSecret`'s full fan-out. Once
	/// `GroupInfo` (and therefore the real group context) is in hand, the
	/// full `Epoch` is derived properly via `fromJoinerSecret`. The AEAD
	/// associated data is empty: §12.4.3.1 says only "use the key and
	/// nonce to decrypt the encrypted_group_info field" and specifies no
	/// AAD input, so there is none to pass.
	public func decryptGroupInfo(
		_ provider: any MLS.CipherSuiteProvider,
		joinerSecret: Data, pskSecret: Data
	) throws -> (groupInfo: MLS.RFC9420.GroupInfo, epoch: MLS.KeySchedule.Epoch) {
		// `epoch_seed` is the parent of the entire epoch fan-out — more
		// sensitive than any single retained field — so it is derived on the
		// zeroizing path even here, where only `welcome_secret` (for the AEAD
		// that opens the GroupInfo) is needed before the full fan-out.
		let epochSeed = try provider.kdfExtractSecret(salt: joinerSecret, ikm: pskSecret)
		let welcomeSecret = try MLS.deriveSecretSecret(
			provider, secret: epochSeed, label: "welcome")
		let (key, nonce) = try MLS.KeySchedule.welcomeKeyNonce(
			provider, welcomeSecret: welcomeSecret)
		let plaintext = try provider.aeadOpen(
			key: key, nonce: nonce, aad: nil, ciphertext: encryptedGroupInfo)
		let groupInfo = try MLS.RFC9420.GroupInfo(mlsEncoded: plaintext)
		let epoch = try MLS.KeySchedule.fromJoinerSecret(
			provider, joinerSecret: joinerSecret, pskSecret: pskSecret,
			groupContext: try groupInfo.groupContext.mlsEncoded())
		return (groupInfo, epoch)
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
