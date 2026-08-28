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
exposes no X448, so suites **4** (`MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`)
and **6** (`MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`) cannot be
implemented on this stack at all — not deferred, not unimplemented,
unavailable.

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
| External commits and external senders | Deferred project-wide; a regular commit refuses to construct or apply either |

§7.3 leaf validation runs in full — the authenticity half (every leaf's own
signature) and the policy half (capability/extension consistency, mutual
credential support, `required_capabilities`) at join, on every proposal leaf,
and on every `UpdatePath` leaf. The two deliberate carve-outs: lifetime
bounds are caller opt-ins (the receive-side check is RECOMMENDED-not-
mandatory and hundreds of official-vector leaves are already expired; the
maximum-total-lifetime is an application MUST), and §5.3.1 credential
validation stays the application's — credentials are opaque here by design.

---

## 4. What no vector can catch

The official suite contains no malformed input. Every rejection path in this
codebase is therefore pinned by tests written here, and an adversarial review
during phase 5b demonstrated the cost of assuming otherwise: **both**
`checkUpdatePathKeysAreFresh` and the path-required check were deleted, and all
330 commit epochs still passed — 65 records x 2 epochs from
`passive-client-handling-commit.json` after the suite filter (the file
carries 91 records, but suites 4 and 6 are X448 and never run; a "corrected"
revision of this document briefly said 382 by counting records the tests
never execute), plus 200 from `passive-client-random.json`.

Two consequences worth stating plainly.

**Rejection coverage is complete, and now counted per phase.** The
commit-processing and commit-construction paths together throw **38**
distinct `GroupError` cases (35 at the end of 6a; the phase-6 review split
`updatePathReusesCommitterKey` from the whole-tree freshness sweep so each
is separately mutation-testable, and added `welcomeCoverageIncomplete` for
§12.4.3.1's every-member MUST — plus §7.3's encryption-key uniqueness,
which throws the tree component's own `duplicateEncryptionKey`). Every one
is exercised: by commit mutation, by supplying or withholding crafted
`ProposalStore` state, as direct §7.3 policy units, on the join path, or —
since 6b supplied the committer signing key — by constructed commits
validly signed and malformed in exactly one way. The former standing holes
(`confirmationTagMismatch`, `unsupportedResumptionUsage`) are closed, and
the phase-6 review's additions (the §12.1.7 membership sweep, UpdatePath
leaf policy, post-application encryption-key uniqueness, the pathless
committer-key fix) each landed with a regression test that its own
mutation run fails.

The self-interop gate is the other thing 6b adds to this document's
evidence: constructed commits and Welcomes are processed by the
vector-proven receive path across five epochs (full, pathless, PSK, and
remove commits), with cross-member convergence asserted on the group
context, the tree, both transcript hashes, the epoch authenticator, and
every jointly-held private key. Construction and processing share the
§12.3 application code (`applyProposals`) by design, so "the two sides
agree" is partly structural — the mutation tests are what prove the parts
that are not (transcript binding in the provisional context, old-epoch
membership keys, the GroupSecrets-to-encrypted-GroupInfo binding).

The store-supplied route is worth naming on its own, because it is where the
one real defect this audit found lived. `processing` reads a by-reference
proposal's *sender* out of the caller-supplied store, with no signature of its
own to check. An Update naming a leaf beyond the tree used to grow the ratchet
tree's backing array toward 2²⁵ entries and then abort the process on a `try!` —
the guard and its test came first, and the structural fix followed: the tree's
setters now throw on any index beyond the padded tree, so the spec-shaped
rejection sits in front of a bounds guard rather than being the only defense.

**Retention is now bounded; erasure still is not.** §9.2's deletion schedule
is partially in effect: the Welcome-processing secrets and the confirmation
key are consumed at epoch establishment and are no longer retained at all —
`Group` keeps a narrowed six-field epoch state, so retaining them does not
compile — and the resumption-PSK history is bounded (default: the current
epoch plus three past, matching mls-rs; every official-vector reference is to
the immediately preceding epoch, so the default is peer parity, not an
empirically validated bound). §7.5's held-key pruning has a direct test. Two
honest limits remain. First, "not retained" is not "deleted": Swift gives no
reliable guarantee that a released `Data`'s bytes are erased, value semantics
mean copies propagate, and that erasure question — open since phase 1 and
corroborated by three independent peer reviews — still needs a design
decision, not more tests. Second, §9.2's per-message MUSTs (delete the
`encryption_secret` and ratchet secrets as messages are consumed) await
phase 6, which is where message consumption itself arrives.

**One planned hardening item did not ship.** Two own-leaf guards in
`Protect.swift` (reject decrypting your own message; verify the sender is the
self leaf) are not implemented. Neither is spec-mandated — they are properties
mls-rs has that this profile does not — but the deferral reason ("whichever
phase owns group-membership state") has been discharged since `Group` landed,
so this is now an open item rather than a pending dependency.

---

## 5. Interop harness — what runs today, and what "conformant" still waits on

`mls-interop-server` implements the mlswg `MLSClient` gRPC service over
`MLS.RFC9420` (out-of-scope RPCs answer `ABORTED "unsupported"`, matching
mls-rs). It runs under the **real mlswg Go test-runner** — the same driver
the reference implementations use — over the runner's own scenario configs.
`Scripts/run-interop.sh` reproduces the matrix.

**swift ↔ swift, every supported cipher suite (1, 2, 3, 5, 7):**

| config | scripts | result |
|---|---|---|
| `application` | in-order, out-of-order within epoch, out-of-order across epochs | **pass, all 5 suites** |
| `welcome_join` | force-path and external-tree join variants | **pass, all 5 suites** |
| `commit` | add, empty, remove, external_psk, group_context_extensions | **pass, all 5 suites** |
| `commit` | update, resumption_psk, all_together_{alice,bob}_proposes | ABORTED — deferred features (the updater key-handoff, and reinit/branch resumption PSKs) |

This proves the harness end to end and the runner-driven scenario semantics
on every implemented feature and every suite the stack supports — group
creation, key packages, welcome/join in both tree-delivery modes, the four
implemented proposal types, path and pathless commits, and the full
application-message ratchet with cross-epoch out-of-order delivery. It is a
materially stronger signal than the self-interop gate, because the *runner*
chose the call sequence, not us.

**swift ↔ mls-rs — the independent-implementation half, now run.** The same
harness, a second `-client` pointed at mls-rs's own `harness_client` (Wickr
MLS), suite 1, both handshake-public. Under `ClientModeAll` the runner runs
every actor→client assignment, so each scenario runs with swift creating and
mls-rs joining, mls-rs creating and swift joining, and each same-stack pair —
the same wire bytes leaving one implementation and consumed by the other:

| config | cross-impl result |
|---|---|
| `application` (all 3 scripts) | **pass, both directions** |
| `welcome_join` (path, no-path, external-tree, with-psk) | **pass, both directions** |
| `commit`: add, empty, remove, external_psk, group_context_extensions | **pass, both directions** |
| `commit`: `update` with mls-rs proposing, swift committing | **pass** — our commit-of-a-peer's-Update path agrees with mls-rs |
| `commit`: `update` with swift proposing | swift-side deferred (the updater key-handoff, GER-2368) |
| `commit`: `resumption_psk`, `all_together_*` | swift-side deferred (reinit/branch resumption PSKs) |

Every failure is a swift-side **documented deferred feature** being invoked,
never a wire disagreement: when both stacks use only implemented paths, they
agree byte-for-byte on every group operation — create, key package, welcome
and join in both tree-delivery modes and with PSKs, add, remove,
group-context-extensions, path and pathless commits, and the full
application-message ratchet across epochs and out of order.

This satisfies both halves of `spec/README.md`'s **conformant** definition —
the official test vectors (all 16 consumed, phases 0–6) *and* an independent
implementation (mls-rs, here). The one honest caveat on the badge is scope,
not correctness: `MLS.RFC9420` defers the updater self-proposal (GER-2368)
and, project-wide, ReInit and branching — so it is conformant over a feature
set that is complete for the core group lifecycle but not yet for those. The
maturity marker should read *conformant (core lifecycle; ReInit/branch and
self-Update deferred)* rather than an unqualified badge, until those land.

**Agreement was proven without a public `Export` or `StateAuth` surface.**
Across all three configs the runner never calls either RPC — every
convergence check runs through `epoch_authenticator` alone, already public on
`Group.epoch`. `mls-interop-server`'s `Export` answers `unsupported`, and
`MLS.KeySchedule.exportSecret` stays `package`-scoped. That was a deliberate
bet recorded when the harness was built (no forward secrecy on that path,
recent drafts favor safe-export, "not as an adopter-facing API"); this run is
the first real evidence for it — nothing exercised needed more than the
authenticator to settle whether two independent implementations derived the
identical key schedule. Revisit only if a future scenario config genuinely
requires it; neither the mlswg nor the mls-rs config sets do today.
