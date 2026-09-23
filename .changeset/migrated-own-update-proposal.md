---
"@germ-network/swift-mls": patch
---

Adds `Group.insertMigratedOwnUpdate` (`@_spi(Migration)`), a narrow, migration-only way to restore a member's own outstanding Update proposal when it was carried over from another implementation without the signed framing bytes `ProposalStore.insert` normally requires.
