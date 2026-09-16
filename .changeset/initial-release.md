---
"@germ-network/swift-mls": minor
---

First pre-release.

swift-mls is a construction kit for [MLS](https://datatracker.ietf.org/doc/rfc9420/)-family
protocols in Swift, built on [swift-crypto](https://github.com/apple/swift-crypto). RFC 9420
is implemented as a **profile** on top of separated mechanisms — ratchet tree, epoch key
schedule, and wire format — so that a protocol which changes one of them can reuse the
other two.

This release includes a complete RFC 9420 profile implementation, a modular cipher-suite
provider seam, and the combiner infrastructure for building non-RFC-9420 profiles on the
same underlying mechanisms.
