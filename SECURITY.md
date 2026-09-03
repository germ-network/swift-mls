# Security policy

## Reporting

Please do not report suspected vulnerabilities through public GitHub issues.

- Preferred: [GitHub private vulnerability reporting](https://github.com/germ-network/swift-mls/security/advisories/new)
- Alternatively: security@germ.network

This is a small project: reports are read, but no response timeline is
promised, and there is no bug bounty.

## Scope

**In scope:** anything with concrete security impact — key or plaintext
disclosure, authentication bypass, acceptance of input the code or spec
documents as rejected, memory-safety failures reachable from untrusted
input, divergence between `spec/` and the code with a security consequence
(this repo's rule is that the spec is the contract: where they disagree,
the code has the bug).

**Out of scope:** hardening suggestions without concrete impact. Those are
welcome as ordinary issues.

## Memory hygiene (zeroization)

The retained secret material — the key schedule's per-epoch fan-out, retained
resumption PSKs, HPKE private keys, the per-message secret store (the §9.2
consuming secret tree, its ratchet chains, and the skipped-key cache), and the
KDF Extract/Expand seam that derives them — is held in zeroizing storage
(swift-crypto's `SymmetricKey`, via the `swift-secret-bytes` package), so a
derived secret is born and kept in a buffer that scrubs on release rather than
an ordinary `Data`. This is **defense-in-depth with an unprovable ceiling**,
not a guarantee:

- It narrows the *same-process* exposure window (a heap over-read, a core
  dump, swap, a hibernation image). It does **not** defend against another
  process reading our memory — the OS zeroes freed pages before another
  process sees them, and zeroization adds nothing there.
- On Apple platforms the scrubbing is CryptoKit's closed-source behavior,
  which we state but cannot verify; on Linux it rests on a best-effort
  optimizer barrier. Value-type copies, register spills, and
  compiler-materialized temporaries are outside what zeroizing a buffer can
  reach.
- Coverage stops at the terminal boundaries. The per-message AEAD key/nonce
  handed to `aeadSeal`/`aeadOpen`, the HPKE-seal plaintext, and the plaintext
  transients at wire decode/encode are ordinary `Data` — a secret must
  materialize as `Data` to cross those provider/wire seams, so custody ends
  there by construction; several are marked in the source as deliberate custody
  exits. Application-supplied signature private keys (`SignatureSecretKey`) are
  also `Data`; the group never retains one, so their custody is the
  application's.

A provable, testable companion to this ships alongside it: per-epoch key
material is dropped as soon as it can no longer be needed, and the
resumption-PSK history is bounded to a caller-configured depth — "this key is
no longer retained" is a property a test can assert, unlike "these bytes are
no longer in memory."

