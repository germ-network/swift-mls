---
"@germ-network/swift-mls": patch
---

Fixes an undefined-symbol link error in optimized Xcode builds of apps that drop a `SentCommit` or `PendingCommit`. The internal `Group.MessageSecrets` type now has public linkage. Its source visibility is unchanged.
