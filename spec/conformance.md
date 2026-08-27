# RFC 9420 conformance: what is verified, and what is not

`MLSProfileRFC9420` is a SwiftPM library product. It is **not yet
`conformant`** by this directory's own definition, and this document says
exactly where the gap is rather than leaving it implied.

`README.md` sets the bar at two clauses:

> **conformant** — implements a published RFC; verified against the official
> test vectors **and against at least one independent implementation**

The first clause is met: every official mlswg vector file the profile's scope
covers is vendored and asserted against, with no unconsumed file left in the
tree. The second is not. It requires the gRPC interop harness, which is phase
7's work. Until then the honest label is **implements RFC 9420; vector-verified,
not interop-verified**.

Two things are worth separating, because passing vectors invites conflating
them. Vectors demonstrate that this code and the implementations that generated
them compute the same values from the same inputs. They demonstrate almost
nothing about behaviour on inputs an *adversary* chose — a vector suite has no
malformed cases, so every rejection path in this codebase is pinned by tests
this project wrote, not by upstream data. Section 4 below is where that shows.

---

## 1. Cipher-suite coverage

Every "N records" figure in this repo is a **filtered** count. swift-crypto
exposes no X448, so suites **4** (`X448_CHACHA20POLY1305_SHA512_Ed448`) and
**6** (`X448_AES256GCM_SHA512_Ed448`) cannot be implemented on this stack at
all — not deferred, not unimplemented, unavailable.

`SwiftCryptoProvider.supportedCipherSuites` is suites 1, 2, 3, 5, 7. Upstream
vector files carry all seven in equal proportion, so the filter drops exactly
**2/7 of every suite-keyed file**, uniformly. Nothing else is filtered: no
sampling, no truncation, no fetch-time trimming of suite-keyed files.

| upstream | consumed | dropped |
|---|---|---|
| suites 1, 2, 3, 5, 7 | yes | — |
| suite 4, suite 6 | no | X448 — no swift-crypto support |

`hpke-base-mode.json` is the one file trimmed at fetch time (to the KEM/KDF
pairings MLS actually uses, and to 3 encryptions/exports per case). That is
recorded in `Tests/MLSVectorSupport/Vectors/README.md`, which is authoritative
for provenance; this document is authoritative for *what is asserted*.

---

## 2. Official vectors: what each one actually proves

"Structural" means decode/re-encode byte-identity — the bytes agree, no
cryptographic claim is checked. "Semantic" means the code recomputes a value
and matches the vector's own. The distinction matters: a file can be fully
consumed and still prove much less than its name suggests.

| vector | records (of upstream) | depth | what is asserted |
|---|---|---|---|
| `deserialization.json` | 14 / 14 | semantic | Each varint header decodes to its stated length **and** re-encodes to exactly those bytes. Accept path only — see §4. |
| `tree-math.json` | 10 / 10 | semantic | `nodeCount`, `root`, and every node's `left`/`right`/`parent`/`sibling`; `directPath` cross-checked against the vector's own `parent` chain. |
| `crypto-basics.json` | 5 / 7 | semantic | All seven `RefHash`/`ExpandWithLabel`/`DeriveSecret`/`DeriveTreeSecret`/sign/verify/HPKE operations. |
| `hpke-base-mode.json` | 24 (trimmed) | semantic | RFC 9180 base-mode seal/open/export against the CFRG's own vectors. |
| `key-schedule.json` | 5 / 7 | semantic | Every epoch secret, the exporter, and each epoch's derived keys. |
| `psk_secret.json` | 55 / 77 | semantic | §8.4 PSK-secret accumulation across 0–10 external PSKs. |
| `secret-tree.json` | 15 / 21 | semantic | Secret-tree derivation and per-generation ratchet keys/nonces. |
| `transcript-hashes.json` | 5 / 7 | semantic | Confirmed→interim transcript-hash chaining. |
| `message-protection.json` | 5 / 7 | semantic | Public/private protect+unprotect round trip, membership tag, sender-data seal. |
| `messages.json` | 300 / 300 | **structural only** | Decode/re-encode byte-identity for every top-level structure. **No signature, tag, or hash in this file is verified** — it is a codec test with realistic data, and reading it as protocol verification is the single easiest mistake to make about this suite. |
| `welcome.json` | 5 / 7 | semantic | Full decrypt-and-verify: HPKE-decrypt `GroupSecrets`, AEAD-decrypt `GroupInfo`, verify its signature, recompute `confirmation_tag`. No tree in this file. |
| `tree-validation.json` | 70 / 98 | semantic | Per-node `resolutions` (§4.2.2) and `tree_hashes` (§7.8). |
| `tree-operations.json` | 5 / 5 | semantic | Applies one proposal to `tree_before`, checks `tree_after` **byte-identical** plus both tree hashes. |
| `treekem.json` | 55 / 77 | semantic | Real HPKE encap/decap: decrypts each `update_paths` entry, checks `commit_secret`, then re-derives a fresh `UpdatePath` and checks every other leaf recovers the same secret. |
| `passive-client-welcome.json` | 40 / 56 | semantic | The full `Group.join` path — both tree-delivery modes, both PSK modes, own-leaf find, path-secret install — against the vector's `initial_epoch_authenticator`. |
| `passive-client-handling-commit.json` | 65 / 91 | semantic | Join, then apply every commit and match each `epoch_authenticator`. By-value and by-reference proposals, all proposal types, pathless and path commits. |
| `passive-client-random.json` | 1 / 1 | semantic | One record, 200 consecutive epochs. The only test exercising held-key staleness over a long chain. |

Five supplementary non-official files (`mls-rs-signatures.json`,
`mls-rs-sender-data-key.json`, `key_package_ref.json`, `proposal_ref.json`,
`reuse_guard.json`) are also consumed; they are mls-rs fixtures, cross-checks
rather than normative, and marked as such in the provenance README.

**No vendored vector file is unconsumed.** That was not true before this
document existed: `deserialization.json` had been vendored since phase 0 and
described as "consumed by `MLSCodecTests`" while no test referenced it. The
audit that produced this file found it; it is now genuinely consumed.

---

## 3. Scope deliberately not implemented

These are not gaps in conformance so much as a stated subset. Each is refused
explicitly rather than silently mishandled — the distinction that matters is
that a caller gets an error, not a plausible-looking result.

| deferred | how it fails |
|---|---|
| External commits / external senders | `GroupError.unsupportedSender` |
| ReInit | `GroupError.unsupportedReInit` — rejected rather than applied, because ReInit uniquely does not perturb the key schedule, so applying it would *succeed* and hand back a live-looking `Group` the caller must not send from |
| Branching, resumption PSKs with `reinit`/`branch` usage | `GroupError.unsupportedResumptionUsage` |
| X.509 credentials | Credentials stay opaque on the wire; interpretation is the application's |
| Commit *construction*, proposal *validation* | Phase 6. This profile is a **passive** client today: it joins and applies, it does not commit |

§7.3 leaf validation is split, and only half is implemented. The
**authenticity** half — every leaf's own signature — runs on every non-blank
leaf at join and on every `UpdatePath` leaf at commit. The **policy** half —
lifetime bounds, capability/extension consistency, `required_capabilities`
satisfaction, and §5.3.1 credential validation — is phase 6's, because it needs
the group's current extensions and a clock, which are not this layer's to
adjudicate.

---

## 4. What no vector can catch

The official suite contains no malformed input. Every rejection path in this
codebase is therefore pinned by tests written here, and an adversarial review
during phase 5b demonstrated the cost of assuming otherwise: **both**
`checkUpdatePathKeysAreFresh` and the path-required check were deleted, and all
330 commit epochs still passed (130 from
`passive-client-handling-commit.json`, 200 from `passive-client-random.json`).

Two consequences worth stating plainly.

**Rejection coverage is partial, and mostly bounded by a signing oracle.**
`Group.processing` verifies the commit's framing signature at step 5, so a test
that *mutates* a commit can only reach checks running before that point. Seven
of fifteen commit rejections are covered: five by mutation
(`wrongEpoch`, `wrongGroup`, `notACommit`, `unsupportedSender`,
`blankSenderLeaf`) and two by *withholding* state rather than altering bytes,
which disturbs no signature at all (`unknownProposalReference`,
`unresolvedPreSharedKey`).

Seven more — `pathRequired`, `removeOfNonMember`,
`updatePathLeafNotCommitSource`, `updatePathReusesEncryptionKey`,
`removedFromGroup`, `unsupportedReInit`, and the UpdatePath key-freshness check
— sit *after* signature verification and need a commit that is both malformed
and validly signed by the committer. The vectors supply the joiner's secrets,
never a committer's signing key. Those rest on reading, and
`CommitRejectionTests` records the limit in its own header.

**One is a real hole rather than an inherent limit:** `confirmationTagMismatch`
has no test on either the join or the commit path, and unlike the seven above
it needs no committer secret to exercise — a wrong tag can simply be written
in. It should be covered; it currently is not.

**Zeroization is unimplemented, and no vector will ever notice.** Open since
phase 1 and corroborated by three independent peer reviews as the one real
standing gap. Phase 5 deepened it: `Group` now retains HPKE secret keys and an
unbounded resumption-PSK history in plain `Data`. Swift gives no reliable
guarantee that a `Data`'s bytes are erased, and value semantics mean copies
propagate. This is a real weakness against an attacker with memory access, it
is not a conformance failure, and it needs a design decision — not more tests.

**One planned hardening item did not ship.** GER-2352's two own-leaf guards in
`Protect.swift` (reject decrypting your own message; verify the sender is the
self leaf) are not implemented. Neither is spec-mandated — they are properties
mls-rs has that this profile does not — but the deferral reason ("whichever
phase owns group-membership state") has been discharged since `Group` landed,
so this is now an open item rather than a pending dependency.

---

## 5. What phase 7 must add before "conformant" is claimable

The gRPC interop harness (`mls-interop-server` implementing `MLSClient`,
out-of-scope RPCs answering `UNIMPLEMENTED`), run under the mlswg Go runner
across swift-mls ↔ mls-rs ↔ OpenMLS. Passing vectors proves agreement with
implementations that have already agreed with each other on *chosen* inputs;
interop proves agreement on inputs neither side chose, including this profile's
own commits — which today no vector exercises at all, because it cannot yet
build one.

Until that runs, `MLSProfileRFC9420` ships as a product whose own specification
directory declines to give it the badge.
