# @germ-network/swift-mls

## 0.1.7

### Patch Changes

- [#113](https://github.com/germ-network/swift-mls/pull/113) [`4acf84c`](https://github.com/germ-network/swift-mls/commit/4acf84c24bd6346039d27cf9635a4c5a3b714a36) Thanks [@germ-mark](https://github.com/germ-mark)! - `CombinerGroup.establish` rejects a classical GroupContext extension list that repeats a type (RFC 9420 §13.4), and `establish`/`join` forget the founding `apq_psk` once it is folded. `verifyFullCommitAttestation`/`verifyFullCommit` decode a wrapped attestation at the `Codepoints`' own wire width, so they can be called outside that scope. `Group.exportSecret` throws `exportLengthOutOfRange` instead of trapping on a length outside `1...255·Nh`. `ProposalStore.insert` no longer overwrites a migration-restored entry: a matching verified proposal leaves it in place, and a mismatched one throws `migratedUpdateRefAlreadyStored`.

## 0.1.6

### Patch Changes

- [#111](https://github.com/germ-network/swift-mls/pull/111) [`42a9682`](https://github.com/germ-network/swift-mls/commit/42a968286289d6152f7b4f60a2b1252d78e57718) Thanks [@germ-mark](https://github.com/germ-mark)! - The migration-only own-Update insert (`@_spi(Migration) Group.insertMigratedOwnUpdate`) can now take the Update's leaf secret directly instead of requiring it in the group state.

## 0.1.5

### Patch Changes

- [#109](https://github.com/germ-network/swift-mls/pull/109) [`66ba6c4`](https://github.com/germ-network/swift-mls/commit/66ba6c40e6848134abdcfc885a9c630a4870fa74) Thanks [@germ-mark](https://github.com/germ-mark)! - Adds `Group.insertMigratedOwnUpdate` (`@_spi(Migration)`), a narrow, migration-only way to restore a member's own outstanding Update proposal when it was carried over from another implementation without the signed framing bytes `ProposalStore.insert` normally requires.

- [#107](https://github.com/germ-network/swift-mls/pull/107) [`472bd86`](https://github.com/germ-network/swift-mls/commit/472bd8688e5b82d4c95a3103d13ecae8578009a5) Thanks [@germ-mark](https://github.com/germ-mark)! - Self-Update proposals can carry authenticated data: `proposeUpdate`/`proposingUpdate(as:)` now take a trailing `authenticatedData: Data = Data()` parameter.

## 0.1.4

### Patch Changes

- [#105](https://github.com/germ-network/swift-mls/pull/105) [`49b4465`](https://github.com/germ-network/swift-mls/commit/49b4465edf81a6ce586db66c0b22db7330194057) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-secret-bytes` pin from `.upToNextMinor(from: "0.5.0")` to
  `from: "0.5.0"`.

  `.upToNextMinor` on a 0.x version fences the range at `0.5.x`, so this package
  capped the whole graph below swift-secret-bytes 0.6.0 — the release that carries
  the shared `SecretBytes`↔`String` text bridge. `from:` keeps the 0.5.0 floor and
  admits 0.6.0 when it cuts. No source changes.

## 0.1.3

### Patch Changes

- [#103](https://github.com/germ-network/swift-mls/pull/103) [`9182f87`](https://github.com/germ-network/swift-mls/commit/9182f8755690c2129b57f8ba5b8ef549c57cb9ab) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
  `swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
  org-wide swift-crypto 5 migration.

  Note — the platform floor rises to macOS 15 / iOS 18 / tvOS 18 / watchOS 11.
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

## 0.1.2

### Patch Changes

- [#100](https://github.com/germ-network/swift-mls/pull/100) [`c55fb15`](https://github.com/germ-network/swift-mls/commit/c55fb1544f2a1742e3260bcf2dadb9703c83c6cd) Thanks [@germ-mark](https://github.com/germ-mark)! - Opt `MLS.Combiner`'s founding-commit orchestration out of optimization: a Swift 6.4.0 optimizer bug (SIL ownership verifier, Android cross-compilation only) crashed `-c release` builds of `MLSCombiner`.

## 0.1.1

### Patch Changes

- [#97](https://github.com/germ-network/swift-mls/pull/97) [`5ccb0af`](https://github.com/germ-network/swift-mls/commit/5ccb0afffc5370d64c3234bbe01716b7c5f4ad95) Thanks [@germ-mark](https://github.com/germ-mark)! - Snapshot restore length-checks `tree_secret_keys` and `pending_update.secret` against the provider's HPKE secret-key size (`Nsk`, spec/snapshot.md §3.1/§4.1.2) instead of accepting any non-empty byte string.

## 0.1.0

### Minor Changes

- [#96](https://github.com/germ-network/swift-mls/pull/96) [`3a26c4d`](https://github.com/germ-network/swift-mls/commit/3a26c4de2b9455ab12be570df927fec8d8626054) Thanks [@germ-mark](https://github.com/germ-mark)! - First pre-release.

  swift-mls is a construction kit for [MLS](https://datatracker.ietf.org/doc/rfc9420/)-family
  protocols in Swift, built on [swift-crypto](https://github.com/apple/swift-crypto). RFC 9420
  is implemented as a **profile** on top of separated mechanisms — ratchet tree, epoch key
  schedule, and wire format — so that a protocol which changes one of them can reuse the
  other two.

  This release includes a complete RFC 9420 profile implementation, a modular cipher-suite
  provider seam, and the combiner infrastructure for building non-RFC-9420 profiles on the
  same underlying mechanisms.
