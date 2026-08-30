# Seed-first custody for private keys

Every private key this project persists is generated as raw bytes *into*
zeroizing storage, and platform key objects (CryptoKit/swift-crypto) are
constructed *from* those bytes — never the reverse. The custody-held bytes
are the authoritative serialized form; `rawRepresentation` is not called
anywhere in a key's lifecycle.

The obvious path is the inverse — let the platform generate
(`Curve25519.KeyAgreement.PrivateKey()`) and extract bytes when persisting —
and it is wrong for a reason that is invisible until traced: extraction
mints an unscrubbable `Data` copy of the key, while *construction* accepts
`some ContiguousBytes` on every relevant key type, so a zeroizing buffer can
feed it directly with no plaintext hop. The danger in the key lifecycle is
one-directional, and generating seed-first removes the dirty direction
entirely instead of narrowing it.

## Randomness equivalence

Seeded generation is not weaker than the native constructors. The seed draw
bottoms out in a kernel-seeded CSPRNG on every platform — the same source
swift-crypto itself uses to generate every `SymmetricKey` (on Darwin, the
same corecrypto RNG the native key constructors use; on Linux, the system
generator beside BoringSSL's kernel-reseeded DRBG — different instance,
equivalent security). Distribution is per-algorithm identical: an Ed25519 or
X25519 private key *is* 32 uniform random bytes, with hashing and clamping
applied at use regardless of how the key was born; NIST-curve seeds with
mask-and-retry reproduce the FIPS rejection-sampling distribution exactly
(the mask is load-bearing for P-521, where unmasked candidates reject
~127/128 of the time); ML-KEM/ML-DSA define keys as seed expansions, so
seed-first is their native model. The one non-equivalence is certification:
the seeded path is not a FIPS-validated key generation. If a validated
keygen is ever required for a suite, that suite reverts to native generation
plus extraction as a documented exception.

## Consequences

- `hpkeGenerateKeyPair` derives the public key from custody-held secret
  bytes rather than extracting both from a platform-generated key.
- NIST curves reject out-of-range scalars at construction, so seeded
  generation there keeps the retry/derive loop the HPKE `DeriveKeyPair`
  path already implements; X25519 accepts any 32 bytes.
- The snapshot format stores exactly these bytes (`spec/snapshot.md` §7),
  so persistence and custody agree on what a serialized key is.
