import Foundation
import MLSCodec

/// `struct { opaque label<V>; opaque context<V>; } EncryptContext;` with
/// `label = "MLS 1.0 " + Label`. The only MLS-specific part of
/// EncryptWithLabel — everything else is RFC 9180 base-mode HPKE, supplied
/// by whatever `CipherSuiteProvider` is in use.
private struct EncryptContext: MLSEncodable {
	var label: String
	var context: Data

	func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(Data("MLS 1.0 ".utf8) + Data(label.utf8))
		try writer.writeOpaque(context)
	}
}

extension MLS {
	/// `EncryptWithLabel(PublicKey, Label, Context, Plaintext) =
	/// SealBase(PublicKey, Encode(EncryptContext), "", Plaintext)`.
	public static func encryptWithLabel(
		_ provider: any CipherSuiteProvider,
		publicKey: HpkePublicKey, label: String, context: Data, plaintext: Data
	) throws -> (enc: Data, ciphertext: Data) {
		let info = try EncryptContext(label: label, context: context).mlsEncoded()
		return try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: nil, plaintext: plaintext)
	}

	/// `DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext) =
	/// OpenBase(KEMOutput, PrivateKey, Encode(EncryptContext), "",
	/// Ciphertext)`.
	public static func decryptWithLabel(
		_ provider: any CipherSuiteProvider,
		privateKey: HpkeSecretKey, label: String, context: Data, enc: Data, ciphertext: Data
	) throws -> Data {
		let info = try EncryptContext(label: label, context: context).mlsEncoded()
		return try provider.hpkeOpen(
			enc: enc, secretKey: privateKey, info: info, aad: nil,
			ciphertext: ciphertext)
	}
}
