---
"@germ-network/swift-mls": minor
---

Close RFC 9420 MUST gaps in tree and commit processing, and harden commit construction.

RFC 9420 MUSTs:

- §7.5: building and merging an `UpdatePath` blanks every node on the sender's direct path, including filtered ones.
- §13.4: an extension list that repeats a type fails to decode and refuses to encode (`WireError.duplicateExtensionType`); `Group.create` refuses one too. A snapshot or live group already holding a duplicate can no longer restore, commit or sign.
- §7.3: `committing` rejects an Add whose KeyPackage lifetime excludes the caller's time (`GroupError.leafNodeLifetimeOutOfRange`). The receive-side check is RECOMMENDED; `validating` can opt into it.

This implementation's choices, beyond what the RFC requires:

- By-reference Adds and a `key_package` creator leaf in `Group.create` get the same lifetime check.
- `committing` runs the receive side's §12.4.2 key checks before requesting any signature, and a key repeated within one path is refused. Every commit's final tree is rejected if two nodes share an encryption key (`TreeError.duplicateEncryptionKey`); a tree that already holds a duplicate fails every later commit.
- The epoch increment throws `GroupError.epochExhausted` instead of trapping.
- `CommitEffect.membershipRemoved` names the committing leaf, including on a full eviction.

Source-breaking:

- New required parameter `lifetimeCheck: MLS.RFC9420.LifetimeCheck` (`.at(unixSeconds:)` or `.unchecked`) on `Group.create`, all `committing` overloads and `CombinerGroup.establish`; it defaults to `.unchecked` on `validating`. `establish` takes it after `pqProvider:`, which breaks twomlspq-swift's `establishFull`.
- `CommitEffect.membershipRemoved` gains `committer:`.
- New cases `WireError.duplicateExtensionType` and `GroupError.epochExhausted` break exhaustive `switch`es over those enums.

Additive: `KeyPackage.validate(currentTime:)`, defaulting to nil.
