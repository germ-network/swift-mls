---
"@germ-network/swift-mls": minor
---

`MLSCombiner`: `establish` now rejects halves that share a cipher suite or group id (new `Error.halvesNotDistinct`) or have different members; `verifyPair`, and so `join`, reject the same shared suite or id and an `APQInfo` whose suite fields differ from the groups' own. New `CombinerGroup.joining` returns a `PendingJoinPair` reporting both halves' roster, signer, consumed KeyPackage, context and own leaf before adoption; `join` is now `joining(...).apply()`.
