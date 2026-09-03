---
status: accepted; implementation pending
---

# Seed-first custody for private keys

Every private key this project persists is to be generated as raw bytes
*into* zeroizing storage, with platform key objects (CryptoKit/swift-crypto)
constructed *from* those bytes — never the reverse. The custody-held bytes
are the authoritative serialized form; `rawRepresentation` is not called in a
key's lifecycle.

**This describes the decided target, not the current code.**
`hpkeGenerateKeyPair` today generates natively and extracts
(`sk.rawRepresentation`) on all four HPKE suites, and signature-key
generation does the same — the exact pattern this ADR rules out. The
conversion is tracked with the retained-secret custody work.

The obvious path is the inverse — let the platform generate
(`Curve25519.KeyAgreement.PrivateKey()`) and extract bytes when persisting —
and it is wrong for a reason that is invisible until traced: extraction
mints an unscrubbable `Data` copy of the key, while *construction* accepts
`some ContiguousBytes` on every relevant key type, so a zeroizing buffer can
feed it directly with no plaintext hop. The danger in the key lifecycle is
one-directional, and generating seed-first removes the dirty direction
entirely instead of narrowing it.

## Randomness equivalence

Seeded generation is not weaker than the native constructors, provided the
seed is drawn correctly — which is a requirement this decision imposes, not
a property the codebase currently has.

**The draw primitive is part of the decision.** `CipherSuiteProvider`'s
existing `randomBytes(_:)` is *not* a suitable seed source: it accumulates
bytes into a plain `Data`, which is an unscrubbable heap value, so routing
seeds through it would break custody at the moment of generation. Seed
generation MUST fill the zeroizing buffer in place. The equivalence argument
below is about the entropy source, and holds only for a draw that satisfies
this.

All the candidate sources are kernel-seeded CSPRNGs, and none is weaker than
the others for this purpose: `SystemRandomNumberGenerator` (which
`randomBytes` uses today) is `arc4random_buf` on Darwin and `getrandom(2)` on
Linux; swift-crypto's own `SecureBytes` random initializer draws the same
way; the native key constructors reach corecrypto on Darwin and BoringSSL's
kernel-reseeded DRBG on Linux. These are different generator *instances* with
equivalent security, not a quality gradient — the earlier claim that the seed
path and the native constructors share one RNG on Darwin was wrong, and
correcting it does not change the conclusion.

Distribution is per-algorithm identical. An Ed25519 or X25519 private key
*is* 32 uniform random bytes, with hashing and clamping applied at use
regardless of how the key was born. NIST-curve seeds with mask-and-retry
reproduce the FIPS rejection-sampling distribution exactly — the mask is
load-bearing for P-521, where unmasked candidates reject ~127/128 of the
time. ML-KEM and ML-DSA define key generation as expansion of a random seed
(FIPS 203 §7.1's `(d, z)`; FIPS 204 §5.1's `ξ`), so seed-first is their
native model rather than an accommodation.

The one non-equivalence is certification: the seeded path is not a
FIPS-validated key generation. If a validated keygen is ever required for a
suite, that suite reverts to native generation plus extraction as a
documented exception, with the custody cost accepted explicitly.

## Consequences

- `hpkeGenerateKeyPair` derives the public key from custody-held secret
  bytes rather than extracting both from a platform-generated key.
- A seed-drawing primitive that fills zeroizing storage in place is a
  prerequisite; `randomBytes(_:)` does not satisfy it and is not a
  substitute.
- NIST curves reject out-of-range scalars at construction, so seeded
  generation there keeps the retry/derive loop the HPKE `DeriveKeyPair`
  path already implements; X25519 accepts any 32 bytes.
- The snapshot format stores exactly these bytes (`spec/snapshot.md` §7),
  so persistence and custody agree on what a serialized key is.
