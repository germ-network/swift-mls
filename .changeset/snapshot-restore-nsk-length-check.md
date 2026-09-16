---
"@germ-network/swift-mls": patch
---

Snapshot restore length-checks `tree_secret_keys` and `pending_update.secret` against the provider's HPKE secret-key size (`Nsk`, spec/snapshot.md §3.1/§4.1.2) instead of accepting any non-empty byte string.
