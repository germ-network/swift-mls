# Specifications

## The specification is the contract

Where these documents and the code disagree, the specification is right and the
code has a bug.

That rule is what makes this directory worth publishing rather than merely
open: an independent implementation should be able to interoperate from the
specification alone, without reading the Swift.

## Documents

Nothing here yet. RFC 9420 itself is the specification for the `MLS.RFC9420`
profile; documents appear here only for profiles that are *not* an existing RFC
or draft.

## Maturity

Each profile states its own maturity, and the bar is deliberately explicit:

| level | meaning |
|---|---|
| **conformant** | implements a published RFC; verified against the official test vectors and against at least one independent implementation |
| **tracking** | implements someone else's draft; follows it, does not extend it |
| **experimental** | our own scheme; **the security argument has not been reviewed by anyone who did not write it**. Not fit to deploy |

A profile that changes what a signature covers stays **experimental** until that
review happens, however well its tests pass. Test vectors demonstrate agreement
between implementations; they do not demonstrate that the scheme is sound.

## Not yet specified

- Everything. This section will list known-open questions as profiles land.
