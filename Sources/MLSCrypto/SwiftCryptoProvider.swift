import Crypto
import Foundation
import MLSCodec

/// The default `MLS.CryptoProvider`, backing the five suites swift-crypto can
/// build: 1, 2, 3, 5, 7. Suites 4 and 6 need Ed448/X448, which swift-crypto
/// has on no platform; an adopter who needs those, or a PQ suite, supplies
/// their own `CipherSuiteProvider`.
public struct SwiftCryptoProvider: MLS.CryptoProvider {
	public init() {}

	public var supportedCipherSuites: [MLS.CipherSuite] {
		[.curve25519Aes128, .p256Aes128, .curve25519ChaCha, .p521Aes256, .p384Aes256]
	}

	public func cipherSuiteProvider(for suite: MLS.CipherSuite) -> (
		any MLS.CipherSuiteProvider
	)? {
		guard supportedCipherSuites.contains(suite) else { return nil }
		return SwiftCryptoCipherSuiteProvider(cipherSuite: suite)
	}
}

struct SwiftCryptoCipherSuiteProvider: MLS.CipherSuiteProvider {
	let cipherSuite: MLS.CipherSuite

	var hashSize: Int {
		switch cipherSuite {
		case .curve25519Aes128, .p256Aes128, .curve25519ChaCha: 32
		case .p384Aes256: 48
		case .p521Aes256: 64
		default: 0
		}
	}

	func hash(_ data: Data) throws -> Data {
		switch cipherSuite {
		case .curve25519Aes128, .p256Aes128, .curve25519ChaCha:
			Data(SHA256.hash(data: data))
		case .p384Aes256: Data(SHA384.hash(data: data))
		case .p521Aes256: Data(SHA512.hash(data: data))
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	/// `salt` is `some ContiguousBytes` so a zeroizing secret type can be
	/// passed without copying its bytes into a `Data` first. Unwrapped once
	/// here rather than at every call site: `UnsafeRawBufferPointer`
	/// satisfies both `ContiguousBytes` and the `DataProtocol` HKDF wants,
	/// so this borrows rather than copies.
	func kdfExtract(salt: some ContiguousBytes, ikm: Data) throws -> Data {
		try salt.withUnsafeBytes { salt in
			switch cipherSuite {
			case .curve25519Aes128, .p256Aes128, .curve25519ChaCha:
				Data(
					HKDF<SHA256>.extract(
						inputKeyMaterial: SymmetricKey(data: ikm),
						salt: salt))
			case .p384Aes256:
				Data(
					HKDF<SHA384>.extract(
						inputKeyMaterial: SymmetricKey(data: ikm),
						salt: salt))
			case .p521Aes256:
				Data(
					HKDF<SHA512>.extract(
						inputKeyMaterial: SymmetricKey(data: ikm),
						salt: salt))
			default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
			}
		}
	}

	/// `prk` is `some ContiguousBytes` so a zeroizing secret type can be
	/// passed without first copying its bytes into a `Data` — see
	/// `kdfExtract`.
	///
	/// The `Data` on the way *out* is a separate question, deliberately not
	/// answered here: HKDF hands back a `SymmetricKey` (already zeroizing)
	/// and this copies it into an unprotected buffer. Closing that means
	/// changing what every derivation in the key schedule returns, which is
	/// its own change with its own review.
	func kdfExpand(prk: some ContiguousBytes, info: Data, length: Int) throws -> Data {
		let key: SymmetricKey = try prk.withUnsafeBytes { prk in
			switch cipherSuite {
			case .curve25519Aes128, .p256Aes128, .curve25519ChaCha:
				HKDF<SHA256>.expand(
					pseudoRandomKey: SymmetricKey(data: prk), info: info,
					outputByteCount: length)
			case .p384Aes256:
				HKDF<SHA384>.expand(
					pseudoRandomKey: SymmetricKey(data: prk), info: info,
					outputByteCount: length)
			case .p521Aes256:
				HKDF<SHA512>.expand(
					pseudoRandomKey: SymmetricKey(data: prk), info: info,
					outputByteCount: length)
			default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
			}
		}
		return key.withUnsafeBytes { Data($0) }
	}

	func sign(privateKey: MLS.SignatureSecretKey, content: Data) throws -> Data {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey.data)
				.signature(for: content)
		case .p256Aes128:
			try P256.Signing.PrivateKey(rawRepresentation: privateKey.data).signature(
				for: content
			).derRepresentation
		case .p384Aes256:
			try P384.Signing.PrivateKey(rawRepresentation: privateKey.data).signature(
				for: content
			).derRepresentation
		case .p521Aes256:
			try P521.Signing.PrivateKey(rawRepresentation: p521Padded(privateKey.data))
				.signature(
					for: content
				).derRepresentation
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	func verify(publicKey: MLS.SignaturePublicKey, content: Data, signature: Data) throws
		-> Bool
	{
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			try Curve25519.Signing.PublicKey(rawRepresentation: publicKey.data)
				.isValidSignature(signature, for: content)
		case .p256Aes128:
			// MLS encodes an ECDSA public key as an uncompressed point
			// (RFC 9420 §5.1.1 / RFC 8446 §4.2.8.2), 0x04 || X || Y —
			// swift-crypto's `rawRepresentation` omits the 0x04, so decode
			// with `x963Representation`.
			try P256.Signing.PublicKey(x963Representation: publicKey.data)
				.isValidSignature(
					P256.Signing.ECDSASignature(derRepresentation: signature),
					for: content)
		case .p384Aes256:
			try P384.Signing.PublicKey(x963Representation: publicKey.data)
				.isValidSignature(
					P384.Signing.ECDSASignature(derRepresentation: signature),
					for: content)
		case .p521Aes256:
			try P521.Signing.PublicKey(x963Representation: publicKey.data)
				.isValidSignature(
					P521.Signing.ECDSASignature(derRepresentation: signature),
					for: content)
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	var aeadKeySize: Int {
		switch cipherSuite {
		case .curve25519Aes128, .p256Aes128: 16
		case .curve25519ChaCha, .p384Aes256, .p521Aes256: 32
		default: 0
		}
	}

	var aeadNonceSize: Int { 12 }

	func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data {
		do {
			switch cipherSuite {
			case .curve25519Aes128, .p256Aes128, .p384Aes256, .p521Aes256:
				let sealed = try AES.GCM.seal(
					plaintext, using: SymmetricKey(data: key),
					nonce: try AES.GCM.Nonce(data: nonce),
					authenticating: aad ?? Data()
				)
				guard let combined = sealed.combined else {
					throw MLS.CryptoError.aeadSealFailed
				}
				// `combined` is nonce || ciphertext || tag; MLS carries only
				// ciphertext || tag (the nonce is supplied separately), so
				// drop the leading nonce.
				return combined.dropFirst(aeadNonceSize)
			case .curve25519ChaCha:
				let sealed = try ChaChaPoly.seal(
					plaintext, using: SymmetricKey(data: key),
					nonce: try ChaChaPoly.Nonce(data: nonce),
					authenticating: aad ?? Data()
				)
				return sealed.ciphertext + sealed.tag
			default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
			}
		} catch let error as MLS.CryptoError {
			throw error
		} catch {
			throw MLS.CryptoError.aeadSealFailed
		}
	}

	func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data {
		do {
			switch cipherSuite {
			case .curve25519Aes128, .p256Aes128, .p384Aes256, .p521Aes256:
				let sealedBox = try AES.GCM.SealedBox(
					nonce: try AES.GCM.Nonce(data: nonce),
					ciphertext: ciphertext.dropLast(16),
					tag: ciphertext.suffix(16))
				return try AES.GCM.open(
					sealedBox, using: SymmetricKey(data: key),
					authenticating: aad ?? Data())
			case .curve25519ChaCha:
				let box = try ChaChaPoly.SealedBox(
					nonce: try ChaChaPoly.Nonce(data: nonce),
					ciphertext: ciphertext.dropLast(16),
					tag: ciphertext.suffix(16)
				)
				return try ChaChaPoly.open(
					box, using: SymmetricKey(data: key),
					authenticating: aad ?? Data())
			default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
			}
		} catch let error as MLS.CryptoError {
			throw error
		} catch {
			throw MLS.CryptoError.aeadOpenFailed
		}
	}

	private var hpkeCiphersuite: HPKE.Ciphersuite {
		switch cipherSuite {
		case .curve25519Aes128:
			HPKE.Ciphersuite(
				kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
		case .curve25519ChaCha:
			HPKE.Ciphersuite(
				kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .chaChaPoly)
		case .p256Aes128:
			HPKE.Ciphersuite(
				kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
		case .p384Aes256:
			HPKE.Ciphersuite(
				kem: .P384_HKDF_SHA384, kdf: .HKDF_SHA384, aead: .AES_GCM_256)
		case .p521Aes256:
			HPKE.Ciphersuite(
				kem: .P521_HKDF_SHA512, kdf: .HKDF_SHA512, aead: .AES_GCM_256)
		default:
			// Unreachable: every caller is guarded by this switch's `throw`.
			HPKE.Ciphersuite(
				kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
		}
	}

	func hpkeGenerateKeyPair() throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			let sk = Curve25519.KeyAgreement.PrivateKey()
			return (.init(sk.rawRepresentation), .init(sk.publicKey.rawRepresentation))
		case .p256Aes128:
			let sk = P256.KeyAgreement.PrivateKey()
			return (.init(sk.rawRepresentation), .init(sk.publicKey.x963Representation))
		case .p384Aes256:
			let sk = P384.KeyAgreement.PrivateKey()
			return (.init(sk.rawRepresentation), .init(sk.publicKey.x963Representation))
		case .p521Aes256:
			let sk = P521.KeyAgreement.PrivateKey()
			return (.init(sk.rawRepresentation), .init(sk.publicKey.x963Representation))
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	func hpkeSeal(publicKey: MLS.HpkePublicKey, info: Data, aad: Data?, plaintext: Data) throws
		-> (enc: Data, ciphertext: Data)
	{
		let suite = hpkeCiphersuite
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			var sender = try HPKE.Sender(
				recipientKey: try Curve25519.KeyAgreement.PublicKey(
					rawRepresentation: publicKey.data), ciphersuite: suite,
				info: info
			)
			let ct = try seal(&sender, aad: aad, plaintext: plaintext)
			return (sender.encapsulatedKey, ct)
		case .p256Aes128:
			var sender = try HPKE.Sender(
				recipientKey: try P256.KeyAgreement.PublicKey(
					x963Representation: publicKey.data), ciphersuite: suite,
				info: info
			)
			let ct = try seal(&sender, aad: aad, plaintext: plaintext)
			return (sender.encapsulatedKey, ct)
		case .p384Aes256:
			var sender = try HPKE.Sender(
				recipientKey: try P384.KeyAgreement.PublicKey(
					x963Representation: publicKey.data), ciphersuite: suite,
				info: info
			)
			let ct = try seal(&sender, aad: aad, plaintext: plaintext)
			return (sender.encapsulatedKey, ct)
		case .p521Aes256:
			var sender = try HPKE.Sender(
				recipientKey: try P521.KeyAgreement.PublicKey(
					x963Representation: publicKey.data), ciphersuite: suite,
				info: info
			)
			let ct = try seal(&sender, aad: aad, plaintext: plaintext)
			return (sender.encapsulatedKey, ct)
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	func hpkeOpen(
		enc: Data, secretKey: MLS.HpkeSecretKey, info: Data, aad: Data?, ciphertext: Data
	) throws -> Data {
		let suite = hpkeCiphersuite
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			var recipient = try HPKE.Recipient(
				privateKey: try Curve25519.KeyAgreement.PrivateKey(
					rawRepresentation: secretKey.data),
				ciphersuite: suite, info: info, encapsulatedKey: enc
			)
			return try open(&recipient, aad: aad, ciphertext: ciphertext)
		case .p256Aes128:
			var recipient = try HPKE.Recipient(
				privateKey: try P256.KeyAgreement.PrivateKey(
					rawRepresentation: secretKey.data),
				ciphersuite: suite, info: info, encapsulatedKey: enc
			)
			return try open(&recipient, aad: aad, ciphertext: ciphertext)
		case .p384Aes256:
			var recipient = try HPKE.Recipient(
				privateKey: try P384.KeyAgreement.PrivateKey(
					rawRepresentation: secretKey.data),
				ciphersuite: suite, info: info, encapsulatedKey: enc
			)
			return try open(&recipient, aad: aad, ciphertext: ciphertext)
		case .p521Aes256:
			var recipient = try HPKE.Recipient(
				privateKey: try P521.KeyAgreement.PrivateKey(
					rawRepresentation: p521Padded(secretKey.data)),
				ciphersuite: suite, info: info, encapsulatedKey: enc
			)
			return try open(&recipient, aad: aad, ciphertext: ciphertext)
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	private func seal(_ sender: inout HPKE.Sender, aad: Data?, plaintext: Data) throws -> Data {
		if let aad {
			try sender.seal(plaintext, authenticating: aad)
		} else {
			try sender.seal(plaintext)
		}
	}

	private func open(_ recipient: inout HPKE.Recipient, aad: Data?, ciphertext: Data) throws
		-> Data
	{
		if let aad {
			try recipient.open(ciphertext, authenticating: aad)
		} else {
			try recipient.open(ciphertext)
		}
	}

	// MARK: - DeriveKeyPair (RFC 9180 §7.1.3)
	//
	// The one HPKE operation this provider implements directly rather than
	// delegates — swift-crypto's DH key types expose no deterministic-keygen
	// entry point at all (confirmed by reading HPKEDiffieHellmanPrivateKeyGeneration:
	// only `generate()`, no seed-based initializer). Built directly over this
	// same type's own `kdfExtract`/`kdfExpand` (RFC 5869 Extract/Expand),
	// which the delegated HPKE path never needed exposed at this level but
	// this one does.

	/// RFC 9180 §3's `I2OSP(n, w)`: "Convert non-negative integer n to a
	/// w-length, big-endian byte string." Every use in this file has
	/// `w == 2`, so the width is pinned to `UInt16` rather than taken as a
	/// parameter.
	private func i2osp(_ value: UInt16) -> Data {
		var bigEndian = value.bigEndian
		return withUnsafeBytes(of: &bigEndian) { Data($0) }
	}

	/// RFC 9180 §4.1: `suite_id = concat("KEM", I2OSP(kem_id, 2))`, this
	/// suite's KEM half only — DeriveKeyPair never touches the combined
	/// HPKE suite_id (KEM+KDF+AEAD), only the KEM's own.
	private var kemSuiteID: Data {
		Data("KEM".utf8) + i2osp(hpkeKemID)
	}

	private var hpkeKemID: UInt16 {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha: 0x0020  // DHKEM(X25519, HKDF-SHA256)
		case .p256Aes128: 0x0010  // DHKEM(P-256, HKDF-SHA256)
		case .p384Aes256: 0x0011  // DHKEM(P-384, HKDF-SHA384)
		case .p521Aes256: 0x0012  // DHKEM(P-521, HKDF-SHA512)
		default: 0
		}
	}

	private var hpkeSecretKeySize: Int {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha, .p256Aes128: 32
		case .p384Aes256: 48
		case .p521Aes256: 66
		default: 0
		}
	}

	/// `0xFF` for P-256/P-384, `0x01` for P-521 (RFC 9180 Table 2's
	/// bitmask column — applied to the first byte of a DeriveKeyPair
	/// candidate before validating it), `nil` where no rejection sampling
	/// is needed (X25519: any clamped 32 bytes is a valid scalar).
	private var hpkeRejectionSamplingBitmask: UInt8? {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha: nil
		case .p256Aes128, .p384Aes256: 0xFF
		case .p521Aes256: 0x01
		default: nil
		}
	}

	/// RFC 9180 §4: `LabeledExtract`/`LabeledExpand` scoped to the KEM's own
	/// suite_id — the general HPKE-level versions (which additionally fold
	/// in KDF/AEAD ids) live nowhere in this file because nothing else here
	/// needs them; swift-crypto's own HPKE type does that composition
	/// internally for `hpkeSeal`/`hpkeOpen`.
	private func kemLabeledExtract(salt: Data, label: String, ikm: Data) throws -> Data {
		try kdfExtract(
			salt: salt, ikm: Data("HPKE-v1".utf8) + kemSuiteID + Data(label.utf8) + ikm)
	}

	private func kemLabeledExpand(prk: Data, label: String, info: Data, length: Int) throws
		-> Data
	{
		let labeledInfo =
			i2osp(UInt16(length)) + Data("HPKE-v1".utf8) + kemSuiteID + Data(label.utf8)
			+ info
		return try kdfExpand(prk: prk, info: labeledInfo, length: length)
	}

	/// The public key for a raw private-key byte string. Used only by
	/// `hpkeDeriveKeyPair`: it both computes the final public key and,
	/// for the NIST curves, doubles as the rejection-sampling candidate's
	/// validity check — an out-of-range scalar throws here rather than
	/// silently producing a point that isn't actually on the curve.
	private func hpkePublicKey(for secretKey: MLS.HpkeSecretKey) throws -> MLS.HpkePublicKey {
		switch cipherSuite {
		case .curve25519Aes128, .curve25519ChaCha:
			.init(
				try Curve25519.KeyAgreement.PrivateKey(
					rawRepresentation: secretKey.data
				).publicKey.rawRepresentation)
		case .p256Aes128:
			.init(
				try P256.KeyAgreement.PrivateKey(rawRepresentation: secretKey.data)
					.publicKey.x963Representation)
		case .p384Aes256:
			.init(
				try P384.KeyAgreement.PrivateKey(rawRepresentation: secretKey.data)
					.publicKey.x963Representation)
		case .p521Aes256:
			.init(
				try P521.KeyAgreement.PrivateKey(
					rawRepresentation: p521Padded(secretKey.data)
				)
				.publicKey.x963Representation)
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	func hpkeDeriveKeyPair(ikm: Data) throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
		let dkpPrk = try kemLabeledExtract(salt: Data(), label: "dkp_prk", ikm: ikm)

		guard let bitmask = hpkeRejectionSamplingBitmask else {
			// X25519: no candidate loop: any clamped 32 bytes is valid.
			let sk = try kemLabeledExpand(
				prk: dkpPrk, label: "sk", info: Data(), length: hpkeSecretKeySize)
			return (.init(sk), try hpkePublicKey(for: .init(sk)))
		}

		// NIST curves: RFC 9180 gives 255 attempts to land inside the
		// curve's order; each candidate's leading byte is masked down to
		// the curve's real bit width before validating it as a scalar.
		for counter in UInt8(0)...254 {
			var candidate = try kemLabeledExpand(
				prk: dkpPrk, label: "candidate", info: Data([counter]),
				length: hpkeSecretKeySize)
			candidate[0] &= bitmask
			if let publicKey = try? hpkePublicKey(for: .init(candidate)) {
				return (.init(candidate), publicKey)
			}
		}
		throw MLS.CryptoError.invalidKey
	}

	/// P-521's scalar is 66 bytes (⌈521/8⌉), but the top byte holds only
	/// one significant bit, so roughly half of all P-521 private keys have
	/// a leading zero byte in that representation — and some encoders
	/// (confirmed: the official `message-protection.json` RFC 9420 test
	/// vector) strip it as a minimal-length integer, producing 65 bytes.
	/// swift-crypto's `P521....PrivateKey(rawRepresentation:)` requires
	/// exactly 66 and throws otherwise. Left-padding restores the value
	/// without changing it — zero-extending a big-endian integer is a
	/// no-op on its magnitude.
	private func p521Padded(_ raw: Data) -> Data {
		raw.count >= 66 ? raw : Data(repeating: 0, count: 66 - raw.count) + raw
	}
}
