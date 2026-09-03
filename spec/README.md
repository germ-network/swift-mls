# Specifications

## The specification is the contract

Where these documents and the code disagree, the specification is right and the
code has a bug.

That rule is what makes this directory worth publishing rather than merely
open: an independent implementation should be able to interoperate from the
specification alone, without reading the Swift.

## Documents

| document | covers |
|---|---|
| [`conformance.md`](conformance.md) | What `MLS.RFC9420` actually verifies, per official test vector, and what it does not |

RFC 9420 itself is the specification for the `MLS.RFC9420` profile; *profile*
documents appear here only for profiles that are not an existing RFC or draft.
`conformance.md` is not a profile document — it is the coverage accounting the
maturity table below demands, and it exists because "verified against the
official test vectors" is a claim that has to be auditable to mean anything.

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

Current levels:

| profile | level | why |
|---|---|---|
| `MLS.RFC9420` | **not yet conformant** | Meets the first clause — every official vector in scope is consumed and asserted against. Does not meet the second: no independent-implementation interop yet. See [`conformance.md`](conformance.md) |

The bar is only worth stating if it is applied to us too. `MLS.RFC9420` is a
shipping library product that does not currently earn its own directory's top
label, and says so.

## Not yet specified

No profile of our own has landed yet, so there is no profile text to write.
The open questions that exist today are about *coverage*, not specification,
and live in [`conformance.md`](conformance.md):

- Independent-implementation interop — the second half of **conformant**.
- Zeroization: unimplemented, and no test vector can detect it.
- Rejection-path coverage bounded by the absence of a committer's signing key
  in any official vector.

Profile-level open questions will be listed here as `MLS.Slim` and
`MLS.MultiGroup` land.
