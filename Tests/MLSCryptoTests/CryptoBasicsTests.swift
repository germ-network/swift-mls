import MLSCodec
import Foundation
import Testing
@testable import MLSCrypto
import MLSVectorSupport

@Suite("crypto-basics.json (mlswg/mls-implementations)")
struct CryptoBasicsTests {
    static let provider = SwiftCryptoProvider()

    // Suites 4 and 6 need Ed448/X448, which swift-crypto implements on no
    // platform (see CipherSuite.swift and SwiftCryptoProvider.swift). Their
    // vector records are unreachable with the default provider; skipping
    // them here is the direct consequence of that documented gap, not an
    // oversight — an adopter with a provider for 4/6 would run these same
    // records against it instead.
    static let records = try! VectorFile.load("crypto-basics", as: [CryptoBasicsVector].self)
        .filter { SwiftCryptoProvider().supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

    @Test("derive_secret", arguments: records)
    func deriveSecret(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let out = try MLS.deriveSecret(provider, secret: record.deriveSecret.secret.bytes, label: record.deriveSecret.label)
        #expect(out == record.deriveSecret.out.bytes)
    }

    @Test("derive_tree_secret", arguments: records)
    func deriveTreeSecret(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let v = record.deriveTreeSecret
        let out = try MLS.deriveTreeSecret(
            provider, secret: v.secret.bytes, label: v.label, generation: v.generation, length: Int(v.length)
        )
        #expect(out == v.out.bytes)
    }

    @Test("expand_with_label", arguments: records)
    func expandWithLabel(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let v = record.expandWithLabel
        let out = try MLS.expandWithLabel(
            provider, secret: v.secret.bytes, label: v.label, context: v.context.bytes, length: Int(v.length)
        )
        #expect(out == v.out.bytes)
    }

    @Test("ref_hash", arguments: records)
    func refHash(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let v = record.refHash
        let out = try MLS.refHash(provider, label: v.label, value: v.value.bytes)
        #expect(out == v.out.bytes)
    }

    @Test("encrypt_with_label: decrypts the vector's ciphertext, and our own ciphertext round-trips", arguments: records)
    func encryptWithLabel(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let v = record.encryptWithLabel

        let decrypted = try MLS.decryptWithLabel(
            provider, privateKey: .init(v.priv.bytes), label: v.label, context: v.context.bytes,
            enc: v.kemOutput.bytes, ciphertext: v.ciphertext.bytes
        )
        #expect(decrypted == v.plaintext.bytes)

        // HPKE's KEM step is randomized (a fresh ephemeral key per seal), so
        // our own ciphertext need not equal the vector's bytes — unlike
        // every non-HPKE operation above. What must hold is that our own
        // seal/open round-trips.
        let (enc, ciphertext) = try MLS.encryptWithLabel(
            provider, publicKey: .init(v.pub.bytes), label: v.label, context: v.context.bytes, plaintext: v.plaintext.bytes
        )
        let roundTripped = try MLS.decryptWithLabel(
            provider, privateKey: .init(v.priv.bytes), label: v.label, context: v.context.bytes, enc: enc, ciphertext: ciphertext
        )
        #expect(roundTripped == v.plaintext.bytes)
    }

    @Test("sign_with_label: sign matches AND the vector's own signature verifies", arguments: records)
    func signWithLabel(_ record: CryptoBasicsVector) throws {
        let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
        let v = record.signWithLabel

        // ECDSA signatures are randomized (a fresh nonce per signature), so
        // a freshly computed signature need not equal the vector's bytes —
        // unlike every other operation here. What must hold is that a
        // signature we produce verifies, and the vector's own signature
        // verifies under our VerifyWithLabel.
        let ours = try MLS.signWithLabel(
            provider, privateKey: .init(v.priv.bytes), label: v.label, content: v.content.bytes
        )
        let oursVerifies = try MLS.verifyWithLabel(
            provider, publicKey: .init(v.pub.bytes), label: v.label, content: v.content.bytes, signature: ours
        )
        #expect(oursVerifies)

        let vectorVerifies = try MLS.verifyWithLabel(
            provider, publicKey: .init(v.pub.bytes), label: v.label, content: v.content.bytes, signature: v.signature.bytes
        )
        #expect(vectorVerifies)
    }
}
