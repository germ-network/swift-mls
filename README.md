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

## Status

Early. `MLSCodec` is the only target that exists.

| profile | status |
|---|---|
| `MLS.RFC9420` | in progress |

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

## Licence

MIT. See [LICENSE](LICENSE).
