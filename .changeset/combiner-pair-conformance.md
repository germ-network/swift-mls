---
"@germ-network/swift-mls": minor
---

`MLSCombiner`: `establish` and `verifyPair` now reject halves that share a cipher suite or group id (`halvesNotDistinct`) and an `APQInfo` whose suite fields differ from the groups' own; `establish` rejects halves with different members. New `CombinerGroup.joining` returns a `PendingJoinPair` reporting both halves' roster, signer, consumed KeyPackage, context and own leaf before adoption; `join` is now `joining(...).apply()`.
