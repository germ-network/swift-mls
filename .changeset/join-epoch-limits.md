---
"@germ-network/swift-mls": minor
---

Epoch limits at join and restore. `Group.joining` rejects a GroupInfo at epoch 2^62 or above, and snapshot restore rejects a group context at epoch 2^63 or above, each with the new `GroupError.epochOutOfRange`. The limits are this library's choice, exposed as `GroupContext.joinEpochLimit` and `GroupContext.restoreEpochLimit`.

Tree validation checks `unmerged_leaves` (sortedness and reachability) before any parent-hash computation, and `RatchetTree.validateParentHashChain` now includes that check. A tree invalid on both counts reports the `unmerged_leaves` error first.
