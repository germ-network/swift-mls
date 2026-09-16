# @germ-network/swift-mls

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
