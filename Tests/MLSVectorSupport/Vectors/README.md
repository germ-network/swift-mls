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
| `mls-rs-psk-secret.json` | mirrored from `mls-rs-pq/mls-rs/test_data/psk_secret.json` | **no** — exercises the PSK-secret accumulation (`§9.1`) across 1–10 external PSKs per suite; independently useful because `key-schedule.json`'s own `psk_secret` field is a plain opaque input, not something it derives itself |
| `mls-rs-sender-data-key.json` | mirrored from `mls-rs-pq/mls-rs/test_data/sender_data_key_test_vector.json` | **no** — exercises §6.3.2's sender-data key/nonce derivation and the AEAD seal built on it, at three ciphertext-sample-boundary sizes per suite |

Verified byte-identical to the local `mls-rs-pq` checkout's copy at fetch time
(2026-08-18): `crypto-basics.json` ≡ `basic_crypto.json`, `tree-math.json` ⊇ `tree_math.json`
(official has more leaf-count cases), `key-schedule.json` ≡ `key_schedule_test_vector.json`,
`secret-tree.json` ≡ `secret_tree_interop.json` (the file literally named `secret_tree.json`
in that checkout is an older, non-standard mls-rs-internal fixture — not vendored here).

`epoch_secret_exporter_test_vector.json`, present in the `mls-rs-pq` checkout, is
**not** vendored here: it is referenced by no test anywhere in mls-rs's own current
source, and has no official mlswg counterpart either — there is no ground truth for
what it is even testing. `key-schedule.json`'s own per-epoch `exporter` field already
covers the MLS-Exporter computation with a documented, executable consumer.
