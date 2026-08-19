# Vendored test vectors

Committed, not fetched at test time — `swift test` never needs network access.
Refresh with `Scripts/fetch-vectors.sh` and commit the diff.

| file | source | official? |
|---|---|---|
| `crypto-basics.json` | `mlswg/mls-implementations` `test-vectors/crypto-basics.json` | yes |
| `hpke-base-mode.json` | `cfrg/draft-irtf-cfrg-hpke` `test-vectors.json`, filtered to `mode=0`, `kem_id ∈ {16 P-256, 18 P-521, 32 X25519}` (the KEMs we implement — no Ed448/X448 support exists in swift-crypto, so kem_id 33/X448 is excluded), `kdf_id ∈ {1, 3}`; `encryptions`/`exports` capped at 3 entries per case | yes, trimmed |
| `mls-rs-signatures.json` | mirrored from `mls-rs-pq/mls-rs/test_data/signatures.json` | **no** — not published under `mlswg/mls-implementations`; kept because it exercises `sign_with_label`/`verify_with_label` per cipher suite and cross-checks against an independent implementation, but treat it as supplementary, not normative |

Verified byte-identical to the local `mls-rs-pq` checkout's copy at fetch time
(2026-08-18): `crypto-basics.json` ≡ `mls-rs-pq/mls-rs/test_data/basic_crypto.json`.
