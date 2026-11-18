---
"@germ-network/swift-mls": minor
---

`CipherSuiteProvider` gains `validateHpkePublicKey(_:)`, with a default that probe-seals the key. `SwiftCryptoProvider` rejects malformed and small-order HPKE public keys, and `hpkeSeal` now reports an invalid key as `CryptoError.invalidPublicKey`. Ed25519 `verify` throws `CryptoError.invalidPublicKey` for non-canonical or small-order public keys, and returns false for a signature whose R is small-order.
