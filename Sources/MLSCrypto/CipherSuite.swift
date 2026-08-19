import MLSCodec
/// An RFC 9420 §17.1 cipher suite id. Suite ids are monolithic — one id
/// fixes the KEM, KDF, AEAD, hash, and signature scheme together.
///
/// Naming a suite here does not imply anything backs it — that is a
/// `CryptoProvider`'s question, not this type's. `CipherSuite` is an
/// identifier with well-known RFC constants attached, nothing more.
extension MLS {
    public struct CipherSuite: Hashable, Sendable {
        public let id: UInt16

        public init(id: UInt16) { self.id = id }

        /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
        public static let curve25519Aes128 = CipherSuite(id: 1)
        /// `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
        public static let p256Aes128 = CipherSuite(id: 2)
        /// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
        public static let curve25519ChaCha = CipherSuite(id: 3)
        /// `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`
        public static let curve448Aes256 = CipherSuite(id: 4)
        /// `MLS_256_DHKEMP521_AES256GCM_SHA512_P521`
        public static let p521Aes256 = CipherSuite(id: 5)
        /// `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`
        public static let curve448ChaCha = CipherSuite(id: 6)
        /// `MLS_256_DHKEMP384_AES256GCM_SHA384_P384`
        public static let p384Aes256 = CipherSuite(id: 7)
    }
}
