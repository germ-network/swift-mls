---
"@germ-network/swift-mls": minor
---

Epoch limits at join and restore. `Group.joining` rejects a GroupInfo at epoch 2^62 or above, and snapshot restore rejects a group context at epoch 2^63 or above, each with the new `GroupError.epochOutOfRange`. The limits are this library's choice, exposed as `GroupContext.joinEpochLimit` and `GroupContext.restoreEpochLimit`.

Tree validation checks `unmerged_leaves` (sortedness and reachability) before any parent-hash computation, and `RatchetTree.validateParentHashChain` now includes that check. A tree invalid on both counts reports the `unmerged_leaves` error first.

`RatchetTree.validateParentHashChain` makes at most `nodeCount × (depth + 1) + 2 × (non-blank parents)` hash calls on any tree, and at most `3 × nodeCount` when no parent lists an unmerged leaf. Its verdicts and errors are unchanged for any tree that passes the `unmerged_leaves` check, and `treeHash(at:filteredUnmergedLeaves:_:)` is byte-identical.
