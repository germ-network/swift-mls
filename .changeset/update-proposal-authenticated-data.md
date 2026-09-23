---
"@germ-network/swift-mls": patch
---

Self-Update proposals can carry authenticated data: `proposeUpdate`/`proposingUpdate(as:)` now take a trailing `authenticatedData: Data = Data()` parameter.
