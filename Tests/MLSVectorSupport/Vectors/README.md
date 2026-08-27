# Vendored test vectors

Committed, not fetched at test time — `swift test` never needs network access.
Refresh with `Scripts/fetch-vectors.sh` and commit the diff.

| file | source | official? |
|---|---|---|
| `crypto-basics.json` | `mlswg/mls-implementations` `test-vectors/crypto-basics.json` | yes |
| `hpke-base-mode.json` | `cfrg/draft-irtf-cfrg-hpke` `test-vectors.json`, filtered to `mode=0`, `kem_id ∈ {16 P-256, 18 P-521, 32 X25519}` (the KEMs we implement — no Ed448/X448 support exists in swift-crypto, so kem_id 33/X448 is excluded), `kdf_id ∈ {1, 3}`; `encryptions`/`exports` capped at 3 entries per case | yes, trimmed |
| `mls-rs-signatures.json` | mirrored from `mls-rs-pq/mls-rs/test_data/signatures.json` | **no** — not published under `mlswg/mls-implementations`; kept because it exercises `sign_with_label`/`verify_with_label` per cipher suite and cross-checks against an independent implementation, but treat it as supplementary, not normative |
| `tree-math.json` | `mlswg/mls-implementations` `test-vectors/tree-math.json` | yes |
| `key-schedule.json` | `mlswg/mls-implementations` `test-vectors/key-schedule.json` | yes |
| `secret-tree.json` | `mlswg/mls-implementations` `test-vectors/secret-tree.json` | yes |
| `mls-rs-sender-data-key.json` | mirrored from `mls-rs-pq/mls-rs/test_data/sender_data_key_test_vector.json` | **no** — exercises §6.3.2's sender-data key/nonce derivation and the AEAD seal built on it, at three ciphertext-sample-boundary sizes per suite |
| `psk_secret.json` | `mlswg/mls-implementations` `test-vectors/psk_secret.json` | yes — exercises PSK-secret accumulation (`§8.4`) across 0–10 external PSKs per suite; `key-schedule.json`'s own `psk_secret` field is a plain opaque input, not something it derives itself |
| `message-protection.json` | `mlswg/mls-implementations` `test-vectors/message-protection.json` | yes — public/private message protect+unprotect round trip, membership tag, sender-data seal; **not** the same file as `mls-rs-pq/mls-rs/test_data/framing.json`, which carries an extra `confirmation_tag` key and different data — that mirror file is not used here |
| `transcript-hashes.json` | `mlswg/mls-implementations` `test-vectors/transcript-hashes.json` | yes |
| `messages.json` | `mlswg/mls-implementations` `test-vectors/messages.json` | yes — decode/re-encode byte-identity for every top-level RFC 9420 structure (Welcome, GroupInfo, KeyPackage, ratchet_tree, GroupSecrets, all seven proposal bodies, Commit, three PublicMessage shapes, PrivateMessage); vendored in full (2.7 MB) rather than trimmed like `hpke-base-mode.json` — that file's trim removed genuinely redundant KEM/KDF/AEAD combinations, this one's 300 records don't have an equivalent redundant axis to filter on, and 2.7 MB is not large enough to be worth losing coverage over |
| `welcome.json` | `mlswg/mls-implementations` `test-vectors/welcome.json` | yes — full decrypt-and-verify (phase 5): HPKE-decrypt `GroupSecrets`, AEAD-decrypt `GroupInfo` via `MLSKeySchedule.welcomeKeyNonce`, verify the signature, recompute `confirmation_tag`. No tree in this file at all — `passive-client-welcome.json` covers that half |
| `passive-client-welcome.json` | `mlswg/mls-implementations` `test-vectors/passive-client-welcome.json` | yes — 56 records × up to 7 suites; the full `Group.join` path (tree decode/validate, both tree-delivery modes — external field vs. `GroupInfo` extension — both PSK modes, own-leaf-find, path-secret install), checked against the vector's own `initial_epoch_authenticator`. `epochs` is empty in every record here — commit application is the other two files' job |
| `passive-client-random.json` | `mlswg/mls-implementations` `test-vectors/passive-client-random.json` | yes — 1 record, suite 1 only, 200 epochs — the held-key-staleness stress test for commit application (phase 5b) |
| `passive-client-handling-commit.json` | `mlswg/mls-implementations` `test-vectors/passive-client-handling-commit.json` | yes — 91 records × up to 7 suites, 2 epochs each — by-value and by-reference proposals, add/update/remove/psk/group-context-extensions, external and resumption PSKs, pathless and path commits (phase 5b) |
| `deserialization.json` | `mlswg/mls-implementations` `test-vectors/deserialization.json` | yes — 14 varint length headers and the lengths they denote; consumed by `MLSCodecTests` rather than a phase-3 target. All 14 are well-formed minimum-length encodings, so it covers the accept path only — reserved prefixes, non-minimal encodings and truncation are `VarintTests`'/`CodecTests`' own cases, which the working group publishes no vectors for |
| `key_package_ref.json` | mirrored from `mls-rs-pq/mls-rs/test_data/key_package_ref.json` | **no** — self-contained (`input` is a serialized `KeyPackage`, `output` its `RefHash`); doubles as a `HashReference` test before any wire structure exists and a `KeyPackage` round-trip test once one does |
| `proposal_ref.json` | mirrored from `mls-rs-pq/mls-rs/test_data/proposal_ref.json` | **no** — self-contained (`input` is a serialized `AuthenticatedContent`), same dual use as `key_package_ref.json` |
| `reuse_guard.json` | mirrored from `mls-rs-pq/mls-rs/test_data/reuse_guard.json` | **no** — self-contained; schema gotcha: `nonce`/`guard`/`result` are JSON arrays of integers, not hex strings |
| `tree-validation.json` | `mlswg/mls-implementations` `test-vectors/tree-validation.json` | yes — 98 records × up to 7 suites; per-node-index `resolutions` (§4.2.2) and `tree_hashes` (§7.8) arrays, `2 * paddedLeafCount - 1` long — **not** the length of the (possibly trimmed) serialized `tree` field itself, see `tree-validation.json`'s own `tree` vs. these arrays' lengths. Vendored whole (1.3 MB), not suite-filtered at fetch time — filtered to `provider.supportedCipherSuites` at test-load time instead, matching `message-protection.json`'s own pattern; a fetch-time filter would permanently diverge the vendored bytes from upstream for a ~30% size saving smaller than what `messages.json` already declined to trim for |
| `tree-operations.json` | `mlswg/mls-implementations` `test-vectors/tree-operations.json` | yes — 5 records, suite 1 only; the cheapest real (non-structural) signal in phase 4: applies one proposal to `tree_before` and checks `tree_after` byte-identical plus both tree hashes — trimming trailing blanks after every edit is load-bearing for this, not incidental |
| `treekem.json` | `mlswg/mls-implementations` `test-vectors/treekem.json` | yes — 77 records × up to 7 suites; the strongest signal in phase 4 and the only one exercising real HPKE (decrypts each `update_paths` entry's path secrets, checks `commit_secret`, then re-derives a fresh `UpdatePath` from the same tree and checks every other leaf still recovers the same secret — the actual encap/decap round-trip). Vendored whole, same rationale as `tree-validation.json` above |

**Correction (phase 5 conformance audit):** the `deserialization.json` row said
"consumed by `MLSCodecTests`" from phase 0 onward and **no test referenced the
file** — `MLSCodecTests` did not even link `MLSVectorSupport`. The audit that
produced `spec/conformance.md` found it. Now genuinely consumed, by
`DeserializationVectorTests`; the target links `MLSVectorSupport`, which declares
no dependencies of its own, so the isolation property that kept this unwired
(a component test target reaching only its own component) still holds.

**Correction (this phase):** the PSK-secret vector was previously vendored as
`mls-rs-psk-secret.json`, mislabeled non-official — `psk_secret.json` is in fact
published under `mlswg/mls-implementations` (77 records, `psk_id`/`psk_nonce` field
names, vs. the mirror's 70 records and `id`/`nonce`). Swapped in the official file
under its upstream name; `PskSecretVector`'s `CodingKeys` updated to match.

**Not vendored, and not just omitted — actively wrong to use for this phase's proof
gate**, despite appearing as vectors of similar names in the `mls-rs-pq` mirror or an
earlier version of this project's plan:
- `framing.json` / `interop_transcript_hashes.json` — neither exists upstream under
  those names; `message-protection.json` and `transcript-hashes.json` are the real
  official files, and `framing.json` specifically is not even the same *data* as
  `message-protection.json` (see the row above).
- `membership_tag.json` — carries only `{cipher_suite, tag}`, unusable without
  hand-reconstructing mls-rs's private test fixture; `message-protection.json` covers
  membership tags with self-contained data instead.
- `message_padding_test_vector.json` — tests `PaddingMode::StepFunction`
  (`mls-rs/src/group/padding.rs`), which is mls-rs's own padding policy, not an RFC
  9420 requirement. RFC 9420 only specifies "append zero bytes; reject non-zero
  padding on decode" — this vector is non-normative, not merely non-official.
- `interop_passive_client_welcome.json` / `interop_passive_client_random.json` /
  `interop_passive_client_handle_commit.json` — do not exist upstream under those
  names (phase 5/GER-2296). The real files are `passive-client-welcome.json`,
  `passive-client-random.json`, `passive-client-handling-commit.json`, listed
  above. The likely source of the wrong names: `mlswg/mls-implementations` also
  has an `interop/passive/` directory, but that holds gRPC-harness *configs*
  (phase 7's job, not test vectors) — a plausible mix-up, not a real vector set
  to reach for instead.

Verified byte-identical to the local `mls-rs-pq` checkout's copy at fetch time
(2026-08-18): `crypto-basics.json` ≡ `basic_crypto.json`, `tree-math.json` ⊇ `tree_math.json`
(official has more leaf-count cases), `key-schedule.json` ≡ `key_schedule_test_vector.json`,
`secret-tree.json` ≡ `secret_tree_interop.json` (the file literally named `secret_tree.json`
in that checkout is an older, non-standard mls-rs-internal fixture — not vendored here),
`transcript-hashes.json` ≡ `interop_transcript_hashes.json`.

`epoch_secret_exporter_test_vector.json`, present in the `mls-rs-pq` checkout, is
**not** vendored here: it is referenced by no test anywhere in mls-rs's own current
source, and has no official mlswg counterpart either — there is no ground truth for
what it is even testing. `key-schedule.json`'s own per-epoch `exporter` field already
covers the MLS-Exporter computation with a documented, executable consumer.
