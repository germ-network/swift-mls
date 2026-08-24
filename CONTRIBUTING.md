# Contributing

Contributions are welcomed and encouraged.

To give clarity of what is expected of our members, Germ has adopted the code of
conduct defined by the Contributor Covenant. This document is used across many
open source communities, and we think it articulates our values well. For more,
see the [Code of Conduct](./CODE_OF_CONDUCT.md).

## What this repository is

A protocol construction kit and its specifications. Three kinds of contribution
are especially useful:

- **Specification issues** — an ambiguity, a requirement that cannot be
  satisfied as written, or a place where two readings would produce
  non-interoperating implementations.
- **Interop reports** — a disagreement between this implementation and another
  over the same test vector or the same wire bytes. Please include the bytes.
- **Security review of the non-RFC profiles** — the schemes here that reduce
  signature count change *what a signature covers*. Review from someone who did
  not write them is the most valuable thing this project can receive.

## Tests

```
swift test
```

Every wire-format change needs a test that pins the bytes, not only the
round-trip: re-encoding must be byte-identical, because signatures and hashes
are taken over these encodings.
