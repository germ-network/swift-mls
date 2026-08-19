import Foundation
import Testing
@testable import MLSCrypto
import MLSCodec
import MLSVectorSupport

/// `hpke-base-mode.json` covers every KEM×KDF×AEAD combination cfrg
/// publishes for the KEMs we support — most of which no RFC 9420 cipher
/// suite actually uses (MLS pins one AEAD per suite). Filtered here to the
/// combinations that *do* match one of our five suites' canonical pairing,
/// so this exercises `SwiftCryptoCipherSuiteProvider.hpkeOpen` directly —
/// independent of `crypto-basics.json`'s provenance, and below
/// `EncryptWithLabel`'s info-wrapping rather than through it.
@Suite("hpke-base-mode.json (cfrg/draft-irtf-cfrg-hpke), filtered to real MLS suite pairings")
struct HpkeVectorTests {
    static let provider = SwiftCryptoProvider()

    // (kem_id, kdf_id, aead_id) -> MLS suite, RFC 9180 §7.1-§7.3 registry
    // values. No suite-7 (P-384) entry: kem_id 17 is absent from the
    // upstream vector file entirely — not a filtering choice, see
    // Vectors/README.md.
    static let suiteForTriple: [UInt16: [UInt16: [UInt16: MLS.CipherSuite]]] = [
        32: [1: [1: .curve25519Aes128, 3: .curve25519ChaCha]], // X25519, HKDF-SHA256
        16: [1: [1: .p256Aes128]], // P-256, HKDF-SHA256
        18: [3: [2: .p521Aes256]], // P-521, HKDF-SHA512
    ]

    static let matches: [(vector: HpkeVector, suite: MLS.CipherSuite)] = {
        (try! VectorFile.load("hpke-base-mode", as: [HpkeVector].self)).compactMap { vector in
            guard let suite = suiteForTriple[vector.kemID]?[vector.kdfID]?[vector.aeadID] else { return nil }
            return (vector, suite)
        }
    }()

    @Test("decrypts each matching vector's first message under its own key schedule")
    func decryptsFirstMessageOfMatchingVectors() throws {
        // Runs as one test, not `arguments:`, because the interesting
        // assertion is over *all* matches together — zero matches would
        // mean the filter above is broken and every subsequent assertion
        // is vacuous, which #expect-per-case would not surface clearly.
        #expect(!Self.matches.isEmpty)

        for (vector, suite) in Self.matches {
            let provider = try #require(Self.provider.cipherSuiteProvider(for: suite))
            // Only the first message in `encryptions[]` (sequence number 0,
            // the base nonce unmodified) is reachable through a one-shot
            // open — messages after it were sealed with the nonce XORed by
            // an incrementing sequence number, which needs a stateful
            // context our `hpkeOpen` deliberately doesn't keep, because
            // RFC 9420's EncryptWithLabel never sends more than one message
            // per HPKE context. Nothing else in `encryptions[]` is reachable
            // through the API MLS actually uses.
            let encryption = try #require(vector.encryptions.first)
            let plaintext = try provider.hpkeOpen(
                enc: vector.enc.bytes,
                secretKey: .init(vector.skRm.bytes),
                info: vector.info.bytes,
                aad: encryption.aad.bytes.isEmpty ? nil : encryption.aad.bytes,
                ciphertext: encryption.ciphertext.bytes
            )
            #expect(plaintext == encryption.plaintext.bytes)
        }
    }
}
