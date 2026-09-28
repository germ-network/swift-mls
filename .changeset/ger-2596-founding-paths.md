---
"@germ-network/swift-mls": patch
---

`CombinerGroup.establish` no longer puts an `UpdatePath` on its founding commits. It creates a one-member group and adds the peer in the immediately-following commit, so there is no gap for a path to cover.
