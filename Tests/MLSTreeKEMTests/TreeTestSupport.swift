import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes

@testable import MLSTreeKEM

/// Synthetic leaf payloads throughout — no `LeafNode`, no profile linked at
/// all, which is the actual proof that `MLSTreeKEM` doesn't secretly depend
/// on `MLSProfileRFC9420`. The official tree vectors, which do need a real
/// `LeafNode` decoder, run in `MLSProfileRFC9420Tests` instead.
func syntheticLeaf(_ tag: UInt8) -> MLS.TreeKEM.LeafRecord {
	MLS.TreeKEM.LeafRecord(
		encryptionKey: .init(Data([tag])), parentHash: nil, encoded: Data([tag, tag]))
}

func syntheticParent(_ tag: UInt8, unmerged: [UInt32] = []) -> MLS.TreeKEM.ParentNode {
	MLS.TreeKEM.ParentNode(
		encryptionKey: .init(Data([tag])), parentHash: Data(),
		unmergedLeaves: unmerged.map { MLS.LeafIndex(value: $0) })
}

final class HashCount: @unchecked Sendable {
	private let lock = NSLock()
	private var value = 0
	var count: Int { lock.withLock { value } }
	func increment() { lock.withLock { value += 1 } }
}

/// Forwards every requirement to a real provider and counts `hash(_:)` calls.
struct HashCountingProvider: MLS.CipherSuiteProvider {
	let inner: any MLS.CipherSuiteProvider
	let counter = HashCount()

	init() {
		inner = SwiftCryptoProvider().cipherSuiteProvider(for: .init(id: 1))!
	}

	var hashCalls: Int { counter.count }

	var cipherSuite: MLS.CipherSuite { inner.cipherSuite }
	var hashSize: Int { inner.hashSize }
	var aeadKeySize: Int { inner.aeadKeySize }
	var aeadNonceSize: Int { inner.aeadNonceSize }
	var hpkeSecretKeySize: Int? { inner.hpkeSecretKeySize }

	func randomBytes(_ count: Int) -> Data { inner.randomBytes(count) }
	func hash(_ data: Data) throws -> Data {
		counter.increment()
		return try inner.hash(data)
	}
	func kdfExtract(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws -> Data {
		try inner.kdfExtract(salt: salt, ikm: ikm)
	}
	func kdfExpand(prk: some ContiguousBytes, info: Data, length: Int) throws -> Data {
		try inner.kdfExpand(prk: prk, info: info, length: length)
	}
	func kdfExtractSecret(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws
		-> SecretBytes
	{
		try inner.kdfExtractSecret(salt: salt, ikm: ikm)
	}
	func kdfExpandSecret(prk: some ContiguousBytes, info: Data, length: Int) throws
		-> SecretBytes
	{
		try inner.kdfExpandSecret(prk: prk, info: info, length: length)
	}
	func sign(privateKey: MLS.SignatureSecretKey, content: Data) throws -> Data {
		try inner.sign(privateKey: privateKey, content: content)
	}
	func verify(publicKey: MLS.SignaturePublicKey, content: Data, signature: Data) throws
		-> Bool
	{
		try inner.verify(publicKey: publicKey, content: content, signature: signature)
	}
	func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data {
		try inner.aeadSeal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
	}
	func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data {
		try inner.aeadOpen(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}
	func hpkeGenerateKeyPair() throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
		try inner.hpkeGenerateKeyPair()
	}
	func hpkeSeal(publicKey: MLS.HpkePublicKey, info: Data, aad: Data?, plaintext: Data)
		throws -> (enc: Data, ciphertext: Data)
	{
		try inner.hpkeSeal(publicKey: publicKey, info: info, aad: aad, plaintext: plaintext)
	}
	func hpkeOpen(
		enc: Data, secretKey: MLS.HpkeSecretKey, info: Data, aad: Data?, ciphertext: Data
	) throws -> Data {
		try inner.hpkeOpen(
			enc: enc, secretKey: secretKey, info: info, aad: aad, ciphertext: ciphertext
		)
	}
	func hpkeDeriveKeyPair(ikm: some ContiguousBytes) throws -> (
		MLS.HpkeSecretKey, MLS.HpkePublicKey
	) {
		try inner.hpkeDeriveKeyPair(ikm: ikm)
	}
}
