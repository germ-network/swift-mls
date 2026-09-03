import Foundation
import MLSCodec
import SecretBytes
import Testing

@testable import MLSCrypto

/// P-521's raw scalar is 66 bytes, but roughly half of all valid keys have
/// a leading zero byte (the top byte holds only one significant bit) that a
/// minimal-length encoder strips, producing a 65-byte value. `sign` and
/// `hpkePublicKey` re-pad this on the way in; `hpkeOpen` needs the same
/// treatment for a secret key handed to it in that shorter form (e.g. a
/// `Welcome` vector's `init_priv`), and initially didn't get it — no
/// currently-vendored vector happens to exercise the stripped case (their
/// P-521 keys all landed at the full 66 bytes by chance), so this generates
/// keys until one does, deterministically closing the gap rather than
/// relying on luck.
@Suite("P-521 raw-scalar minimal encoding (SwiftCryptoProvider)")
struct P521MinimalKeyTests {
	@Test("hpkeOpen accepts a 65-byte (leading-zero-stripped) secret key")
	func opensWithMinimallyEncodedSecretKey() throws {
		let provider = try #require(
			SwiftCryptoProvider().cipherSuiteProvider(for: .p521Aes256))

		var stripped: (secretKey: MLS.HpkeSecretKey, publicKey: MLS.HpkePublicKey)?
		for _ in 0..<64 {
			let (secretKey, publicKey) = try provider.hpkeGenerateKeyPair()
			if secretKey.data.withUnsafeBytes({ $0.first == 0 }) {
				stripped = (secretKey, publicKey)
				break
			}
		}
		// Astronomically unlikely to exhaust 64 draws at ~50% odds per key.
		let (fullSecretKey, publicKey) = try #require(stripped)

		let minimalSecretKey = try MLS.HpkeSecretKey(
			fullSecretKey.data.withUnsafeBytes { Data($0.dropFirst()) })
		#expect(minimalSecretKey.data.byteCount == 65)

		let plaintext = Data("hpkeOpen must accept a minimally-encoded P-521 key".utf8)
		let (enc, ciphertext) = try provider.hpkeSeal(
			publicKey: publicKey, info: Data(), aad: nil, plaintext: plaintext)

		let opened = try provider.hpkeOpen(
			enc: enc, secretKey: minimalSecretKey, info: Data(), aad: nil,
			ciphertext: ciphertext)
		#expect(opened == plaintext)
	}
}
