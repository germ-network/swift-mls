---
"@germ-network/swift-mls": minor
---

Close RFC 9420 MUST gaps in tree and commit processing.

- §7.5: building and merging an `UpdatePath` blanks every node on the sender's direct path, including filtered ones.
- §13.4: an extension list that repeats a type fails to decode and refuses to encode (`WireError.duplicateExtensionType`); `Group.create` refuses one too. A snapshot or live group already holding a duplicate can no longer restore, commit or sign.
- §7.3: `committing` rejects an Add whose KeyPackage lifetime excludes the caller's time (`GroupError.leafNodeLifetimeOutOfRange`); `Group.create` applies the same range to a `key_package` creator leaf. `validating` can opt into the receive-side check.
- `committing` runs the receive side's §12.4.2 key checks before signing, and every commit's final tree is rejected if two nodes share an encryption key (`TreeError.duplicateEncryptionKey`). A tree that already holds a duplicate fails every later commit.
- The epoch increment throws `GroupError.epochExhausted` instead of trapping.

Source-breaking:

- New `lifetimeCheck: MLS.RFC9420.LifetimeCheck` (`.at(unixSeconds:)` or `.unchecked`) is required on `Group.create`, all `committing` overloads and `CombinerGroup.establish`, and defaults to `.unchecked` on `validating`. `CombinerGroup.establish` takes it after `pqProvider:`, which breaks twomlspq-swift's `establishFull`.
- `CommitEffect.membershipRemoved` gains `committer:`, and now names the commit's sender, including on a full eviction.
- `KeyPackage.validate` gains `currentTime:`, defaulting to nil.
