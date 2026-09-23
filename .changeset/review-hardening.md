---
"@germ-network/swift-mls": patch
---

`CombinerGroup.establish` rejects a classical GroupContext extension list that repeats a type (RFC 9420 §13.4), and `establish`/`join` forget the founding `apq_psk` once it is folded. `verifyFullCommitAttestation`/`verifyFullCommit` decode a wrapped attestation at the `Codepoints`' own wire width, so they can be called outside that scope. `Group.exportSecret` throws `exportLengthOutOfRange` instead of trapping on a length outside `1...255·Nh`. `ProposalStore.insert` no longer overwrites a migration-restored entry: a matching verified proposal leaves it in place, and a mismatched one throws `migratedUpdateRefAlreadyStored`.
