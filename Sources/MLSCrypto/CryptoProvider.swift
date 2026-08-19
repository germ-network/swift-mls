import Foundation
import MLSCodec

extension MLS {
	public enum CryptoError: Error, Sendable {
		case unsupportedCipherSuite(CipherSuite)
		case signatureVerificationFailed
		case aeadSealFailed
		case aeadOpenFailed
		case invalidKey
		case invalidPublicKey
	}

	/// The raw cryptographic primitives for exactly one cipher suite —
	/// hash, HKDF-style Extract/Expand, AEAD, signature, and the
	/// Diffie-Hellman operations HPKE's DHKEM needs. Everything MLS-specific
	/// (ExpandWithLabel, DeriveSecret, HPKE's KeySchedule, EncryptWithLabel)
	/// is built once, generically, on top of this — never reimplemented per
	/// provider.
	///
	/// This is the seam. `SwiftCryptoProvider` is one conformer, backing the
	/// five suites buildable on swift-crypto alone (no suite needs an
	/// elliptic curve swift-crypto lacks). A suite it cannot back — 4, 6, a
	/// private-range PQ suite, anything else — is exactly what a second
	/// conformer is for; nothing above this protocol needs to change to add
	/// one.
	public protocol CipherSuiteProvider: Sendable {
		var cipherSuite: CipherSuite { get }

		/// `Nh` — the hash/KDF's native digest size in bytes.
		var hashSize: Int { get }
		func hash(_ data: Data) throws -> Data

		/// RFC 5869 `Extract(salt, ikm) -> PRK`.
		func kdfExtract(salt: Data, ikm: Data) throws -> Data
		/// RFC 5869 `Expand(prk, info, L) -> OKM`.
		func kdfExpand(prk: Data, info: Data, length: Int) throws -> Data

		func sign(privateKey: SignatureSecretKey, content: Data) throws -> Data
		func verify(publicKey: SignaturePublicKey, content: Data, signature: Data) throws
			-> Bool

		var aeadKeySize: Int { get }
		var aeadNonceSize: Int { get }
		func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data
		func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data

		/// RFC 9180 base-mode HPKE, single-shot — exactly what RFC 9420's
		/// EncryptWithLabel/DecryptWithLabel need and all they need. A
		/// provider owns its own KEM entirely: how `hpkeSeal` gets from a
		/// public key to `(enc, ciphertext)` is its business, not this
		/// protocol's. `SwiftCryptoProvider` answers these three by
		/// delegating straight to swift-crypto's own `HPKE.Sender` /
		/// `HPKE.Recipient` — swift-crypto's HPKE already covers all four
		/// KEMs our five suites need natively, so there is nothing to
		/// reimplement there. A suite whose KEM swift-crypto doesn't know
		/// about — a private-range ML-KEM suite, say — needs a different
		/// conformer, and that conformer answers these the same three
		/// questions using whatever KEM it has; nothing above this
		/// protocol has to know the difference.
		func hpkeGenerateKeyPair() throws -> (HpkeSecretKey, HpkePublicKey)
		func hpkeSeal(publicKey: HpkePublicKey, info: Data, aad: Data?, plaintext: Data)
			throws -> (enc: Data, ciphertext: Data)
		func hpkeOpen(
			enc: Data, secretKey: HpkeSecretKey, info: Data, aad: Data?,
			ciphertext: Data
		) throws -> Data

		/// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` — deterministic HPKE keygen
		/// from seed bytes. Phase 1 dropped this from the seam, reasoning
		/// that RFC 9420's core protocol never calls it (KeyPackage/LeafNode
		/// HPKE keys are always randomly generated) — wrong: the key
		/// schedule's `external_secret → external_pub` step (RFC 9420 §8,
		/// the `ExternalPubExt`/external-commit path) is exactly this
		/// operation, `kem_derive` in mls-rs's own naming. Restored once
		/// `MLSKeySchedule`'s own vectors needed it, rather than guessed at
		/// in advance — see `docs/status.md`'s "Phase 2" section.
		func hpkeDeriveKeyPair(ikm: Data) throws -> (HpkeSecretKey, HpkePublicKey)
	}

	/// Looks up the `CipherSuiteProvider` for a suite id. An app composes
	/// its providers here — e.g. `SwiftCryptoProvider` for the classical
	/// suites, a second conformer for anything it adds.
	public protocol CryptoProvider: Sendable {
		var supportedCipherSuites: [CipherSuite] { get }
		func cipherSuiteProvider(for suite: CipherSuite) -> (any CipherSuiteProvider)?
	}
}
