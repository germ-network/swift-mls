# Wire-size and signature-count baseline

The numbers the draft profiles measure against, established at phase 6 —
`BaselineBenchmarkTests` asserts every figure here exactly, so this file
and the code cannot drift apart silently.

## Scenario

Cipher suite 1 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — every
primitive fixed-length), 5-byte basic-credential identities, empty
capability lists. "One rotation" = an empty commit with a full UpdatePath
in a 2-member group: the operation a member performs to rotate its own
keys, and the operation the SlimMLS and multi-group drafts exist to make
cheaper.

## Baseline (RFC 9420, this implementation)

| message | bytes |
|---|---|
| KeyPackage | 275 |
| Add commit (1 → 2 members, full path) | 682 |
| Welcome (one new member) | 795 |
| **Rotation commit (empty, full path, 2 members)** | **491** |

One rotation carries **2 signatures**: the framing signature over
`FramedContentTBS` and the UpdatePath leaf's `LeafNodeTBS` signature.

## The row that motivates the drafts

TwoMLS runs four parallel MLS groups per session (two send groups x
classical/PQ halves). The same identity rotation therefore costs, today:

| construction | leaf sigs | framing sigs | total | wire bytes |
|---|---:|---:|---:|---:|
| RFC 9420 baseline, 4 groups | 4 | 4 | **8** | 1,964 |
| single-signature (phase 8 target) | 4 | 0 | 4 | — |
| shared leaf (phase 9 target) | 1 | 4 | 5 | — |
| both (the draft candidate) | 1 | 0 | **1** | — |

The dashes are the point of phases 8–9: they get filled by measurement,
not estimation, as each construction lands — and re-measured at ML-DSA-65
sizes in phase 10, where the byte column is what changes dramatically
(an Ed25519 signature is 64 bytes; an ML-DSA-65 signature is 3,309).

Suite-1 sizes are exact and asserted; other suites differ only by their
fixed primitive sizes (P-521 signatures are variable-length DER on this
stack, which is why the pinned suite is 1).
