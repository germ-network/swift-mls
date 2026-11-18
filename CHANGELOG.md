# @germ-network/swift-mls

## 0.2.0

### Minor Changes

- [#119](https://github.com/germ-network/swift-mls/pull/119) [`ddb3b68`](https://github.com/germ-network/swift-mls/commit/ddb3b6801cc8e5cdd745e68527438d65aa91b39b) Thanks [@germ-mark](https://github.com/germ-mark)! - `MLSCombiner`: `establish` now rejects halves that share a cipher suite or group id (new `Error.halvesNotDistinct`) or have different members; `verifyPair`, and so `join`, reject the same shared suite or id and an `APQInfo` whose suite fields differ from the groups' own. New `CombinerGroup.joining` returns a `PendingJoinPair` reporting both halves' roster, signer, consumed KeyPackage, context and own leaf before adoption; `join` is now `joining(...).apply()`.

- [#123](https://github.com/germ-network/swift-mls/pull/123) [`c4968cd`](https://github.com/germ-network/swift-mls/commit/c4968cd67ea43ca4a783bba9ff3d94e692879850) Thanks [@germ-mark](https://github.com/germ-mark)! - Epoch limits at join and restore. `Group.joining` rejects a GroupInfo at epoch 2^62 or above, and snapshot restore rejects a group context at epoch 2^63 or above, each with the new `GroupError.epochOutOfRange`. The limits are this library's choice, exposed as `GroupContext.joinEpochLimit` and `GroupContext.restoreEpochLimit`.

  Tree validation checks `unmerged_leaves` (sortedness and reachability) before any parent-hash computation, and `RatchetTree.validateParentHashChain` now includes that check. A tree invalid on both counts reports the `unmerged_leaves` error first.

  `RatchetTree.validateParentHashChain` makes at most `nodeCount × (depth + 1) + 2 × (non-blank parents)` hash calls on any tree, and at most `3 × nodeCount` when no parent lists an unmerged leaf. Its verdicts and errors are unchanged for any tree that passes the `unmerged_leaves` check, and `treeHash(at:filteredUnmergedLeaves:_:)` is byte-identical.

  Ratchet-tree decoding is capped. `MLS.RFC9420.decodeRatchetTree(_:)` (new) throws the new `CodecError.vectorElementLimitExceeded(limit:)` at the first node past `MLS.RFC9420.maxRatchetTreeNodeCount` (2^24 − 1) and is used by `GroupInfo.ratchetTreeExtension()` and snapshot restore; `Reader.decodeVector(_:maxCount:)` (new) is the underlying bounded decode. `RatchetTree.init(_:)` rejects an over-long node array with `invalidLeafCount` before converting any node. `MLS.RFC9420.Node` and `MLS.TreeKEM.TreeNode` are now `indirect`, so an optional node is one machine word wide.

- [#121](https://github.com/germ-network/swift-mls/pull/121) [`8f05525`](https://github.com/germ-network/swift-mls/commit/8f0552569fd57e4568983173408b0e6069c845d5) Thanks [@germ-mark](https://github.com/germ-mark)! - Close RFC 9420 MUST gaps in tree and commit processing, and harden commit construction.

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

- [#122](https://github.com/germ-network/swift-mls/pull/122) [`d670c35`](https://github.com/germ-network/swift-mls/commit/d670c35b0b7ba0796b86dc91597a0f9a92ff70ac) Thanks [@germ-mark](https://github.com/germ-mark)! - `CipherSuiteProvider` gains `validateHpkePublicKey(_:)`, with a default that probe-seals the key. `SwiftCryptoProvider` rejects malformed and small-order HPKE public keys, and `hpkeSeal` now reports an invalid key as `CryptoError.invalidPublicKey`. Ed25519 `verify` throws `CryptoError.invalidPublicKey` for non-canonical or small-order public keys, and returns false for a signature whose R is small-order.

## 0.1.8

### Patch Changes

- [#116](https://github.com/germ-network/swift-mls/pull/116) [`336f7ae`](https://github.com/germ-network/swift-mls/commit/336f7ae70a08364726ef24021a690d0a2e7e9658) Thanks [@germ-mark](https://github.com/germ-mark)! - Fixes an undefined-symbol link error in optimized Xcode builds of apps that drop a `SentCommit` or `PendingCommit`. The internal `Group.MessageSecrets` type now has public linkage. Its source visibility is unchanged.

## 0.1.7

### Patch Changes

- [#115](https://github.com/germ-network/swift-mls/pull/115) [`6987d17`](https://github.com/germ-network/swift-mls/commit/6987d17b2fb7f2984502e4275f625fa2186d1458) Thanks [@germ-mark](https://github.com/germ-mark)! - `CombinerGroup.establish` no longer puts an `UpdatePath` on its founding commits. It creates a one-member group and adds the peer in the immediately-following commit, so there is no gap for a path to cover.

- [#113](https://github.com/germ-network/swift-mls/pull/113) [`4acf84c`](https://github.com/germ-network/swift-mls/commit/4acf84c24bd6346039d27cf9635a4c5a3b714a36) Thanks [@germ-mark](https://github.com/germ-mark)! - `CombinerGroup.establish` rejects a classical GroupContext extension list that repeats a type (RFC 9420 §13.4), and `establish`/`join` forget the founding `apq_psk` once it is folded. `verifyFullCommitAttestation`/`verifyFullCommit` decode a wrapped attestation at the `Codepoints`' own wire width, so they can be called outside that scope. `Group.exportSecret` throws `exportLengthOutOfRange` instead of trapping on a length outside `1...255·Nh`. `ProposalStore.insert` no longer overwrites a migration-restored entry: a matching verified proposal leaves it in place, and a mismatched one throws `migratedUpdateRefAlreadyStored`.

## 0.1.6

### Patch Changes

- [#111](https://github.com/germ-network/swift-mls/pull/111) [`42a9682`](https://github.com/germ-network/swift-mls/commit/42a968286289d6152f7b4f60a2b1252d78e57718) Thanks [@germ-mark](https://github.com/germ-mark)! - The migration-only own-Update insert (`@_spi(Migration) Group.insertMigratedOwnUpdate`) can now take the Update's leaf secret directly instead of requiring it in the group state.

## 0.1.5

### Patch Changes

- [#109](https://github.com/germ-network/swift-mls/pull/109) [`66ba6c4`](https://github.com/germ-network/swift-mls/commit/66ba6c40e6848134abdcfc885a9c630a4870fa74) Thanks [@germ-mark](https://github.com/germ-mark)! - Adds `Group.insertMigratedOwnUpdate` (`@_spi(Migration)`), a narrow, migration-only way to restore a member's own outstanding Update proposal when it was carried over from another implementation without the signed framing bytes `ProposalStore.insert` normally requires.

- [#107](https://github.com/germ-network/swift-mls/pull/107) [`472bd86`](https://github.com/germ-network/swift-mls/commit/472bd8688e5b82d4c95a3103d13ecae8578009a5) Thanks [@germ-mark](https://github.com/germ-mark)! - Self-Update proposals can carry authenticated data: `proposeUpdate`/`proposingUpdate(as:)` now take a trailing `authenticatedData: Data = Data()` parameter.

## 0.1.4

### Patch Changes

- [#105](https://github.com/germ-network/swift-mls/pull/105) [`49b4465`](https://github.com/germ-network/swift-mls/commit/49b4465edf81a6ce586db66c0b22db7330194057) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-secret-bytes` pin from `.upToNextMinor(from: "0.5.0")` to
  `from: "0.5.0"`.

  `.upToNextMinor` on a 0.x version fences the range at `0.5.x`, so this package
  capped the whole graph below swift-secret-bytes 0.6.0 — the release that carries
  the shared `SecretBytes`↔`String` text bridge. `from:` keeps the 0.5.0 floor and
  admits 0.6.0 when it cuts. No source changes.

## 0.1.3

### Patch Changes

- [#103](https://github.com/germ-network/swift-mls/pull/103) [`9182f87`](https://github.com/germ-network/swift-mls/commit/9182f8755690c2129b57f8ba5b8ef549c57cb9ab) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
  `swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
  org-wide swift-crypto 5 migration.

  Note — the platform floor rises to macOS 15 / iOS 18 / tvOS 18 / watchOS 11.
  swift-secret-bytes 0.5.0, the swift-crypto-5 release this package now rides,
  declares iOS 18 / macOS 15; the new floor is the higher of that and the
  existing CryptoKit-HPKE floor.

  No source changes were required — the library targets compiled and tested
  unchanged against swift-crypto 5. The one non-obvious dependency change is
  `swift-certificates` (pulled in transitively by the interop harness's
  grpc-swift-nio-transport): its released line caps swift-crypto at `..<5.0.0`,
  so it is pinned to the upstream main commit that widened the cap to `..<6.0.0`,
  to be replaced with the released version once it cuts.

  Secret custody is already complete: `HpkeSecretKey`/`SignatureSecretKey` hold
  their `data` as `SecretBytes`, and the retained KDF outputs use the
  `kdfExtractSecret`/`kdfExpandSecret` SecretBytes seams; the remaining
  `Data`-returning paths are non-secret outputs (MACs, AEAD tags, ciphertext) or
  the documented P-521 fixed-width padding hop.

## 0.1.2

### Patch Changes

- [#100](https://github.com/germ-network/swift-mls/pull/100) [`c55fb15`](https://github.com/germ-network/swift-mls/commit/c55fb1544f2a1742e3260bcf2dadb9703c83c6cd) Thanks [@germ-mark](https://github.com/germ-mark)! - Opt `MLS.Combiner`'s founding-commit orchestration out of optimization: a Swift 6.4.0 optimizer bug (SIL ownership verifier, Android cross-compilation only) crashed `-c release` builds of `MLSCombiner`.

## 0.1.1

### Patch Changes

- [#97](https://github.com/germ-network/swift-mls/pull/97) [`5ccb0af`](https://github.com/germ-network/swift-mls/commit/5ccb0afffc5370d64c3234bbe01716b7c5f4ad95) Thanks [@germ-mark](https://github.com/germ-mark)! - Snapshot restore length-checks `tree_secret_keys` and `pending_update.secret` against the provider's HPKE secret-key size (`Nsk`, spec/snapshot.md §3.1/§4.1.2) instead of accepting any non-empty byte string.

## 0.1.0

### Minor Changes

- [#96](https://github.com/germ-network/swift-mls/pull/96) [`3a26c4d`](https://github.com/germ-network/swift-mls/commit/3a26c4de2b9455ab12be570df927fec8d8626054) Thanks [@germ-mark](https://github.com/germ-mark)! - First pre-release.

  swift-mls is a construction kit for [MLS](https://datatracker.ietf.org/doc/rfc9420/)-family
  protocols in Swift, built on [swift-crypto](https://github.com/apple/swift-crypto). RFC 9420
  is implemented as a **profile** on top of separated mechanisms — ratchet tree, epoch key
  schedule, and wire format — so that a protocol which changes one of them can reuse the
  other two.

  This release includes a complete RFC 9420 profile implementation, a modular cipher-suite
  provider seam, and the combiner infrastructure for building non-RFC-9420 profiles on the
  same underlying mechanisms.
