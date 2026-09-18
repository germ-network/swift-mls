---
"swift-mls": minor
---

Add `MLS.Combiner.CombinerBlob` — a self-contained pure-Swift reader for the deployed Germ opaque combiner-blob framing (`[version byte][opaque t_key_package][opaque pq_key_package]`, each half a full RFC 9420 `MLSMessage`), so a consumer that only reads published offers (no Rust slice linked — the reduced Android build) can parse peers' key packages without the Rust engine. Read-only: the Rust parse remains authoritative for minting and full validation. Tests frame mls-rs's own `key_package_ref` vectors through the layout.
