---
"@germ-network/swift-mls": minor
---

Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
`swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
org-wide swift-crypto 5 migration.

**Breaking — platform floor rises to macOS 15 / iOS 18 / tvOS 18 / watchOS 11.**
swift-secret-bytes 0.5.0, the swift-crypto-5 release this package now rides,
declares iOS 18 / macOS 15; the new floor is the higher of that and the
existing CryptoKit-HPKE floor.

No source changes were required — the library targets compiled and tested
unchanged against swift-crypto 5. The one non-obvious dependency change is
`swift-certificates` (pulled in transitively by the interop harness's
grpc-swift-nio-transport): its released line caps swift-crypto at `..<5.0.0`,
so it is pinned to the upstream main commit that widened the cap to `..<6.0.0`,
to be replaced with the released version once it cuts.

Secret custody is already complete: `HpkeSecretKey`/`SignatureSecretKey` hold
their `data` as `SecretBytes`, and the retained KDF outputs use the
`kdfExtractSecret`/`kdfExpandSecret` SecretBytes seams; the remaining
`Data`-returning paths are non-secret outputs (MACs, AEAD tags, ciphertext) or
the documented P-521 fixed-width padding hop.
