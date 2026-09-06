# swift-mls

A construction kit for [MLS](https://datatracker.ietf.org/doc/rfc9420/)-family
protocols in Swift, built on [swift-crypto](https://github.com/apple/swift-crypto).

MLS is specified as one protocol, but it is really several mechanisms that
happen to be described together: a ratchet tree, an epoch key schedule, and a
wire format. This repository separates them, so that a protocol which changes
one of them can reuse the other two.

RFC 9420 is implemented here as a **profile** — the conformance reference and
the interop target — rather than as a core with extension points. Other
profiles sit beside it, not beneath it.

## Motivation

There are mature implementations of MLS already in peer languages to Swift —
why this one?

First, to enable full access to MLS capabilities for a Swift adopter without
the flattening of API expressiveness through an FFI layer.

There are two additional goals that come out of our experience with shipping
MLS.

**Reusable Components**
The [MLS WG](https://datatracker.ietf.org/wg/mls/about/) continues to
spawn new drafts and extensions as adoption continues and features grow.
We've found it cumbersome to implement behaviors that diverge from RFC
9420 either inline, or as a permanently maintained fork.

Motivated by our work with
[oauth4swift](https://github.com/germ-network/oauth4swift), we want to explore
modular code reuse for many profiles. That library, in the pattern of the
mature [oauth4web](https://github.com/panva/oauth4webapi), exposes reusable
building blocks from which adopters can construct particular varieties of
OAuth clients. Similarly, we want to extract the modular building blocks of
MLS, so that we can more easily, expressively, and clearly define draft
behavior (or combinatorics of draft behavior[^combinatorics]) without
impacting the core RFC 9420 implementation. That core spec is one core
profile, which this repo builds out of those components.

**State Machine Persistence**
We've found it helpful to model MLS as a state machine, so that the outcome of
processing a message — both the decrypted message and the mutation of the
epoch state(s) — is returned to the application to save atomically.

## Status

The component libraries — `MLSCodec`, `MLSCrypto`, `MLSTreeMath`,
`MLSKeySchedule`, `MLSFraming`, `MLSTreeKEM` — and the `MLSProfileRFC9420`
profile built on them are implemented.

| profile | status |
|---|---|
| `MLS.RFC9420` | **conformant** — core group lifecycle |

`MLS.RFC9420` is verified against the official RFC 9420 test vectors and runs
against mls-rs under the mlswg interop harness, agreeing in both directions on
every feature both stacks implement. The qualifier is load-bearing: ReInit,
branching, external join/commit, and external senders are deferred and refused
explicitly, and persistence is not yet in the claim. See
[`spec/conformance.md`](spec/conformance.md) for the per-vector accounting.

Profiles that are not RFC 9420 will each carry their own maturity note. A
profile that changes what a signature covers is **experimental until its
security argument has been reviewed by someone who did not write it**, and will
say so in its own words, in `spec/`.

## The specification is the contract

Where [`spec/`](spec/) and the code disagree, the specification is right and the
code has a bug. Report it as one.

## What this repository does not decide

Group policy. Who may join, when to rotate, how many members a group may hold,
how messages reach their recipients — none of that is here. This is the protocol
machinery and the wire format; the decisions belong to whatever is built on top.

**This library implements no Authentication Service.** RFC 9420 §5.3.1 defines
the AS as whichever part of the system validates credentials — that a credential
legitimately presents its identifiers, that those identifiers are bound to the
LeafNode's signature key, and that they match the application's reference
identifiers. Here that part is the application. Credentials are opaque to this
library: it holds no identity policy, interprets no identifiers, and never calls
into the application.

Because the application is the AS, the library *surfaces* every §5.3.1-relevant
event rather than judging it. The two-step handshake API (issue #32) is that
seam: validating a commit returns a pending value whose effects report each
credential replacement — old and new credential together — alongside every add,
update, and removal, before anything is applied; joining from a Welcome returns
the roster it is about to trust, for the same adjudication. The application
inspects the report, applies its identity policy, and only then adopts the
pending — or declines it.

## Licence

MIT. See [LICENSE](LICENSE).

[^combinatorics]: Rohan Mahy, "Rohan's Draft," IETF 124 MLS working group, slide 22: <https://datatracker.ietf.org/meeting/124/materials/slides-124-mls-rohans-draft-00>
