import Foundation
import MLSCodec
import SecretBytes

/// `struct { uint16 length; opaque label<V>; opaque context<V>; } KDFLabel;`
/// with `label = "MLS 1.0 " + Label`. Field order matters: it is signed and
/// hashed over verbatim.
private struct KDFLabel: MLSEncodable {
	var length: UInt16
	var label: Data
	var context: Data

	func encode(to writer: inout MLS.Writer) throws {
		writer.writeUInt16(length)
		try writer.writeOpaque(mlsLabel)
		try writer.writeOpaque(context)
	}

	private var mlsLabel: Data { Data("MLS 1.0 ".utf8) + label }

	init(length: UInt16, label: String, context: Data) {
		self.length = length
		self.label = Data(label.utf8)
		self.context = context
	}
}

/// `struct { opaque label<V>; opaque content<V>; } SignContent;` with
/// `label = "MLS 1.0 " + Label`.
private struct SignContent: MLSEncodable {
	var label: String
	var content: Data

	func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(Data("MLS 1.0 ".utf8) + Data(label.utf8))
		try writer.writeOpaque(content)
	}
}

/// `struct { opaque label<V>; opaque value<V>; } RefHashInput;`. Unlike
/// KDFLabel/SignContent/EncryptContext, `label` here is used exactly as
/// given — RefHash does not prepend "MLS 1.0 "; callers that want it
/// include it in the string they pass (e.g. `"MLS 1.0 KeyPackage
/// Reference"`).
private struct RefHashInput: MLSEncodable {
	var label: String
	var value: Data

	func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(Data(label.utf8))
		try writer.writeOpaque(value)
	}
}

extension MLS {
	/// `ExpandWithLabel(Secret, Label, Context, Length) = KDF.Expand(Secret,
	/// Encode(KDFLabel), Length)`.
	public static func expandWithLabel(
		_ provider: any CipherSuiteProvider,
		secret: some ContiguousBytes, label: String, context: Data, length: Int
	) throws -> Data {
		let info = try KDFLabel(length: UInt16(length), label: label, context: context)
			.mlsEncoded()
		return try provider.kdfExpand(prk: secret, info: info, length: length)
	}

	/// `DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "",
	/// KDF.Nh)`.
	public static func deriveSecret(
		_ provider: any CipherSuiteProvider, secret: some ContiguousBytes,
		label: String
	) throws -> Data {
		try expandWithLabel(
			provider, secret: secret, label: label, context: Data(),
			length: provider.hashSize)
	}

	/// `ExpandWithLabel` returning a zeroizing `SecretBytes` — the same
	/// derivation as `expandWithLabel`, on the secret-returning KDF form, so
	/// a value bound for a retained key-schedule field is built with no
	/// unscrubbed `Data` between HKDF and storage.
	public static func expandWithLabelSecret(
		_ provider: any CipherSuiteProvider,
		secret: some ContiguousBytes, label: String, context: Data, length: Int
	) throws -> SecretBytes {
		let info = try KDFLabel(length: UInt16(length), label: label, context: context)
			.mlsEncoded()
		return try provider.kdfExpandSecret(prk: secret, info: info, length: length)
	}

	/// `DeriveSecret` returning a zeroizing `SecretBytes` — see
	/// `expandWithLabelSecret`.
	public static func deriveSecretSecret(
		_ provider: any CipherSuiteProvider, secret: some ContiguousBytes,
		label: String
	) throws -> SecretBytes {
		try expandWithLabelSecret(
			provider, secret: secret, label: label, context: Data(),
			length: provider.hashSize)
	}

	/// The secret-tree ratchet's per-generation derivation: `ExpandWithLabel`
	/// with the generation encoded as 4-byte big-endian context.
	public static func deriveTreeSecret(
		_ provider: any CipherSuiteProvider,
		secret: some ContiguousBytes, label: String, generation: UInt32,
		length: Int
	) throws -> Data {
		var generationBE = generation.bigEndian
		let context = withUnsafeBytes(of: &generationBE) { Data($0) }
		return try expandWithLabel(
			provider, secret: secret, label: label, context: context, length: length)
	}

	/// `deriveTreeSecret` returning a zeroizing `SecretBytes` — for the one
	/// tree-secret that is retained rather than consumed in-flight: a
	/// ratchet's `nextSecret`, which feeds the next generation. The per
	/// -generation key and nonce stay `Data`; they terminate at the AEAD.
	public static func deriveTreeSecretSecret(
		_ provider: any CipherSuiteProvider,
		secret: some ContiguousBytes, label: String, generation: UInt32,
		length: Int
	) throws -> SecretBytes {
		var generationBE = generation.bigEndian
		let context = withUnsafeBytes(of: &generationBE) { Data($0) }
		return try expandWithLabelSecret(
			provider, secret: secret, label: label, context: context, length: length)
	}

	/// `SignWithLabel(SignatureKey, Label, Content) = Sign(SignatureKey,
	/// Encode(SignContent))`.
	public static func signWithLabel(
		_ provider: any CipherSuiteProvider,
		privateKey: SignatureSecretKey, label: String, content: Data
	) throws -> Data {
		try provider.sign(
			privateKey: privateKey,
			content: try SignContent(label: label, content: content).mlsEncoded())
	}

	/// `VerifyWithLabel(VerificationKey, Label, Content, Signature) =
	/// Verify(VerificationKey, Encode(SignContent), Signature)`.
	public static func verifyWithLabel(
		_ provider: any CipherSuiteProvider,
		publicKey: SignaturePublicKey, label: String, content: Data, signature: Data
	) throws -> Bool {
		try provider.verify(
			publicKey: publicKey,
			content: try SignContent(label: label, content: content).mlsEncoded(),
			signature: signature
		)
	}

	/// `RefHash(Label, Value) = Hash(Encode(RefHashInput))`. `Label` is used
	/// as given — see `RefHashInput`'s doc comment.
	public static func refHash(_ provider: any CipherSuiteProvider, label: String, value: Data)
		throws -> Data
	{
		try provider.hash(try RefHashInput(label: label, value: value).mlsEncoded())
	}
}
