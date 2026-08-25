import Crypto
import Foundation
import MLSCodec

/// The default `MLS.CryptoProvider`, backing the five cipher suites
/// buildable on swift-crypto alone: 1, 2, 3, 5, 7. Suites 4 and 6 need
/// Ed448/X448, which swift-crypto implements on no platform — confirmed by
/// reading its `Crypto` and `_CryptoExtras` sources, not by absence from its
/// docs. Implementing Ed448/X448 ourselves would mean implementing our own
/// elliptic curve, which is exactly what "we are not implementing crypto"
/// rules out. An adopter who needs 4/6 — or a private-range PQ suite this
/// package doesn't know about — supplies their own `CipherSuiteProvider`;
/// nothing here has to change to admit one.
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

	func kdfExtract(salt: Data, ikm: Data) throws -> Data {
		switch cipherSuite {
		case .curve25519Aes128, .p256Aes128, .curve25519ChaCha:
			Data(
				HKDF<SHA256>.extract(
					inputKeyMaterial: SymmetricKey(data: ikm), salt: salt))
		case .p384Aes256:
			Data(
				HKDF<SHA384>.extract(
					inputKeyMaterial: SymmetricKey(data: ikm), salt: salt))
		case .p521Aes256:
			Data(
				HKDF<SHA512>.extract(
					inputKeyMaterial: SymmetricKey(data: ikm), salt: salt))
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
		}
	}

	func kdfExpand(prk: Data, info: Data, length: Int) throws -> Data {
		let key: SymmetricKey
		switch cipherSuite {
		case .curve25519Aes128, .p256Aes128, .curve25519ChaCha:
			key = HKDF<SHA256>.expand(
				pseudoRandomKey: SymmetricKey(data: prk), info: info,
				outputByteCount: length)
		case .p384Aes256:
			key = HKDF<SHA384>.expand(
				pseudoRandomKey: SymmetricKey(data: prk), info: info,
				outputByteCount: length)
		case .p521Aes256:
			key = HKDF<SHA512>.expand(
				pseudoRandomKey: SymmetricKey(data: prk), info: info,
				outputByteCount: length)
		default: throw MLS.CryptoError.unsupportedCipherSuite(cipherSuite)
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
			try P521.Signing.PrivateKey(rawRepresentation: privateKey.data).signature(
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
			// NIST Signing.PublicKey's `rawRepresentation` is the bare X||Y
			// pair with no format byte; RFC 9420 §5.1.1 encodes an ECDSA
			// SignaturePublicKey as an UncompressedPointRepresentation
			// (RFC 8446 §4.2.8.2) — 0x04 || X || Y, the same convention used
			// for HPKE keys below. Must deserialize with `x963Representation`,
			// not `rawRepresentation`.
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
				// `combined` is nonce || ciphertext || tag; MLS's AEAD
				// ciphertext fields carry ciphertext || tag only — the nonce
				// is derived by the caller and supplied separately, never
				// prepended to the ciphertext — so strip the leading nonce.
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
			// Unreachable: every caller of `hpkeCiphersuite` is itself guarded
			// by the same switch's `throw` case below.
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
					rawRepresentation: secretKey.data),
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
}
