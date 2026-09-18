# @germ-network/swift-mls

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
