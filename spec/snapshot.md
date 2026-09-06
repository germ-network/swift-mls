# Snapshot — persisted group state for `MLS.RFC9420`

**Status: draft.** This document is normative for the `MLS.RFC9420` profile's
persisted state once it leaves draft. Where this document and the code
disagree, this document is right and the code has a bug.

MLS specifies a protocol but not its persistence: RFC 9420 §9.2 mandates what
must be *deleted*, and no document in the family says how surviving state is
serialized. mls-rs's snapshot, for instance, is an unspecified implementation
detail. This document exists so that the persisted artifact is held to the
same standard as the wire format: specified, vectorable, and strictly decoded.

## 1. Definitions

A **Snapshot** is a profile's persisted group state at a point in time —
complete and replaceable, never appended to. A **Transition** is the paired
result of a state-advancing operation: the outputs plus the Snapshot that
must be persisted with them.

Each profile owns its snapshot format. This document specifies the
`MLS.RFC9420` snapshot only; other profiles specify theirs beside it, reusing
sections of this layout where their state genuinely coincides. There is
deliberately no shared abstract snapshot schema: profiles differ in
precisely the state they retain, and that is a policy decision each profile
owns.

## 2. Scope: what a Snapshot contains, and does not

A Snapshot contains **only group-resident state** — state that belongs to
exactly one group and cannot be shared with another.

Normatively excluded, and the consumer's responsibility to persist:

- **Signature private keys.** The signing identity is a per-operation input,
  never group state. A member may share one signing identity across many
  groups; embedding it per-snapshot would duplicate a private key N ways and
  make its rotation incoherent.
- **Proposal stores.** By-reference proposals are resolved from a
  caller-held store; its lifetime and scope are the application's.
- **Pre-published key packages** and their init/encryption private keys.
  These exist before any group does.

Also absent, by consumption rather than exclusion: `joiner_secret`,
`welcome_secret`, `confirmation_key`, `external_secret`, and `external_pub`
do not survive into retained state, so no snapshot field exists for them.
`joiner_secret` and `welcome_secret` are consumed by Welcome processing and
`confirmation_key` once the epoch-establishing confirmation tag is verified,
all three under §9.2's delete-on-consumption mandate; `external_secret` and
`external_pub` power only external commits, which this profile rejects, so
dropping them is a choice rather than a mandate. The `encryption_secret`
appears only transformed, inside the consuming secret tree of its epoch's
message-secret store.

## 3. Encoding

A Snapshot is one deterministic CBOR item (RFC 8949 §4.2.1):

- definite lengths only; no tags; no indefinite-length items;
- integer map keys, **strictly increasing** in bytewise order of their
  encoded form — equal keys sort adjacently rather than failing an ordering
  test, so duplicate keys are a separate and explicit decode error;
- shortest-form heads throughout;
- no floating-point values appear anywhere in this format;
- exactly one top-level item: any byte after it is a decode error;
- decoding is strict: any violation of this section, any violation of a MUST
  in §4, any unknown map key, and any unknown `format` value is an error.
  There is exactly one wire form for a given state. Forward compatibility
  comes from the `format` version, never from ignoring fields.

Empty maps encode as the empty CBOR map (`0xa0`) wherever the schema permits
them; they are never omitted. Optional fields — marked `?` in §4 — are absent
entirely when they do not apply, and absence is their only encoding.

Structures that already have a canonical MLS wire encoding are embedded as
CBOR byte strings containing exactly that encoding, decoded by the profile's
strict MLS reader. This format never re-models a structure that RFC 9420
already encodes: one structure, one encoding, one vector suite.

Fields marked **secret** below are key material. A conforming implementation
holds them in zeroizing storage from decode to consumption and never
materializes them as unmanaged heap values; see §7. This requirement is
outside the vector-based conformance of §8 — no test vector can observe it —
and is stated here as an implementation obligation, in the same spirit as
`conformance.md`'s accounting of what the vectors do and do not reach.

### 3.1 Cryptographic lengths

`Nh`, `Nk`, `Nn`, and `Nsk` below are the cipher suite's parameters, resolved
from the suite named in `group_context`:

- `Nh` — the suite's KDF output length (RFC 9420 §5.1).
- `Nk`, `Nn` — the suite's AEAD key and nonce lengths (RFC 9180 §7.3, as
  selected by RFC 9420 §5.1).
- `Nsk` — the suite's KEM private key length (RFC 9180 §7.1).

Every byte string annotated with a length below MUST be exactly that length;
a wrong-length value is a decode error. The canonical key ordering places
`group_context` first within `core` (§4.1.1) — ahead of every
length-constrained field — so a decoder reading keys in order always knows the
suite before it needs a length.

## 4. Schema

Integer bounds below are normative: a value outside its stated range is a
decode error, not a value to be clamped or reinterpreted.

### 4.1 Top level

Format 2 splits what a device holds for a group into a client-agnostic `core`
— one copy per group, identical across the device's memberships in it — and
one `Membership` per local membership, keyed by leaf index:

```
Snapshot = {
    0: format          ; uint, format 2
    1: core            ; Core (§4.1.1)
    2: memberships     ; { + uint => Membership }  key: leaf index (§4.1.2)
}
```

- `memberships` is never empty: a group with no local membership is not a
  thing a device persists (the N ≥ 1 construction invariant). Each key MUST
  index a non-blank leaf of `core.ratchet_tree`, and the map is the sole
  carrier of leaf identity — a duplicate leaf is structurally impossible,
  since it would be a duplicate map key, already a §3 decode error. A decoder
  orders memberships ascending by key so `memberships[0]` is deterministic.

#### 4.1.1 Core

The client-agnostic state. `group_context` (key 0) is the single source of
truth for the cipher suite, `group_id`, and current epoch, and precedes every
length-constrained field so a decoder always knows the suite before it needs a
length (§3.1). No core field duplicates those three; the per-epoch stores of
§4.3 each carry their own `group_context`, constrained there.

```
Core = {
    0: group_context           ; bstr, MLS GroupContext (RFC 9420 §8.1)
    1: ratchet_tree            ; bstr, MLS ratchet_tree extension content
                               ;   (RFC 9420 §12.4.3.3: optional<Node> vector)
    2: interim_transcript_hash ; bstr, length Nh
    3: epoch_secrets           ; EpochSecrets (§4.2)
    4: resumption_psks         ; { + uint => bstr }  SECRET values (Nh)
    5: message_secrets         ; { + uint => MessageSecretStore (§4.3) }
    6: retention               ; Retention (§4.4)
  ? 7: config                  ; Config (§4.5) — always absent
  ? 8: exporter_tree           ; SecretTreeState (§4.6), the current epoch's
                               ;   Exporter Tree frontier — absent only from a
                               ;   producer that predates it (a migration source)
}
```

- `ratchet_tree` uses the same encoding the `ratchet_tree` extension carries
  on the wire. At decode, an implementation MUST perform the structural parse
  and the tree-integrity checks that need no cryptographic provider:
  well-formed node vector, consistent leaf/parent placement, and every
  `memberships` key naming a non-blank leaf. Signature and parent-hash
  verification are **not** decode-time obligations — they run when the tree is
  used, exactly as on the wire path — so snapshot decode does not require a
  `CipherSuiteProvider`.
- `resumption_psks` maps epoch → that epoch's resumption PSK (length `Nh`).
  Retained epochs MUST fall within the window `retention` describes, relative
  to `group_context.epoch`. Never empty: the current epoch's PSK is always
  retained.
- `message_secrets` maps epoch → that epoch's store. Every key MUST be
  ≤ `group_context.epoch` and MUST fall within `message_secrets_depth` of it.
  Never empty: the current epoch always has a store.

#### 4.1.2 Membership

One local membership's per-client state, keyed in `memberships` by its leaf
index (D18 makes the leaf index the membership identity), so the index is not
repeated inside the entry.

```
Membership = {
    0: tree_secret_keys   ; { + uint => bstr }  SECRET values (Nsk)
  ? 1: pending_updates    ; { + uint => PendingUpdateEntry }  absent when none
  ? 2: own_send           ; OwnSend  absent when nothing sent this epoch
}

PendingUpdateEntry = {
    0: public_key         ; bstr, the proposed leaf's HPKE public key
    1: secret             ; bstr  SECRET (Nsk), its HPKE private key
}

OwnSend = {
    0: handshake_chain    ; Chain (§4.3)
    1: application_chain  ; Chain (§4.3)
}
```

- `tree_secret_keys` maps node index (< 2^32) → the node's KEM private key, in
  the raw serialized form the suite's KEM accepts for key reconstruction
  (length `Nsk`). Keys MUST lie on this membership's own direct path (its own
  leaf included) and reference non-blank nodes. Never empty: a member always
  holds at least its own leaf key.
- `pending_updates` is this membership's outstanding self-Update — the set of
  proposed new leaf key pairs (a set: the committer, not the proposer, picks
  which lands), keyed by dense index `0..<count` in proposal order. Absent when
  none is outstanding, never empty when present (§3's one-wire-form rule). The
  epoch and own-leaf node the live value also carries are not stored: the epoch
  can only be `group_context.epoch` (a pending Update is cleared on every
  advance), and the node is the membership's own leaf.
- `own_send` is this membership's two send ratchets for the current epoch
  (sending happens only in the current epoch). Absent when the membership has
  not sent this epoch — restore re-seeds it lazily from the consuming secret
  tree; present ⟹ both ratchets seeded. Each chain's next generation is not
  stored: it equals that chain's `head_generation` by construction (own chains
  never retire), so a separate counter would be a second wire form for one
  state.

### 4.2 EpochSecrets

The subset of the current epoch's key-schedule fan-out this profile retains
between operations — exactly the unconsumed values. `init_secret` is
unconsumed until the next commit's key-schedule advance; `membership_key`
verifies every incoming `PublicMessage` this epoch; `exporter_secret` backs
the exporter for the epoch's lifetime; `epoch_authenticator` is the value RFC
9420 exposes to applications. The draft §4.4 Exporter Tree is **not** here: its
root (`application_export_secret`) must not be retained past the first export
(RFC 9420 §9.2), so §4.6 persists the tree's consuming frontier instead.

```
EpochSecrets = {
    0: init_secret                ; bstr  SECRET  (Nh)
    1: exporter_secret            ; bstr  SECRET  (Nh)
    2: epoch_authenticator        ; bstr  (Nh)   — public, not SECRET
    3: membership_key             ; bstr  SECRET  (Nh)
}
```

`epoch_authenticator` is **not** secret-marked. RFC 9420 §8.7 designs it as an
out-of-band comparison value — members read it and confirm it against each
other (face-to-face, say) to detect impersonation — so it is non-confidential
by construction and is persisted as a plain byte string. A conforming
implementation need not hold it in zeroizing storage; the other three fields
are key material and remain secret-marked.

### 4.3 MessageSecretStore

One retained epoch's `PrivateMessage` decryption state. It is deliberately
not sufficient to verify that epoch's `PublicMessage` traffic: no per-epoch
`membership_key` is retained, so only the current epoch — whose
`membership_key` lives in §4.2 — can verify a `PublicMessage`. `chains` holds
**remote** senders' ratchets only; a local membership's own send ratchets live
in its `Membership.own_send` (§4.1.2), so no own-send counter appears here.

```
MessageSecretStore = {
    0: group_context         ; bstr, that epoch's own MLS GroupContext
    1: sender_data_secret    ; bstr  SECRET  (Nh)
    2: signature_keys        ; { + uint => bstr }   leaf index => public key
    3: secret_tree           ; SecretTreeState
    4: chains                ; { * uint => Chain }  key: (leaf << 1) | kind
                             ;   kind bit: 0 = handshake, 1 = application
}

SecretTreeState = {
    0: leaf_count            ; uint, a power of two, 1 <= leaf_count < 2^24
    1: node_secrets          ; { * uint => bstr }   SECRET values (Nh)
}

Chain = {
    0: head_generation       ; uint, 0 <= head_generation <= 2^32
  ? 1: head_secret           ; bstr  SECRET  (Nh) — absent once retired
    2: skipped               ; { * uint => SkippedKey }  generation => pair
}

SkippedKey = {
    0: key                   ; bstr  SECRET  (Nk)
    1: nonce                 ; bstr  (Nn)   — not secret
}
```

`nonce` is **not** secret-marked: an AEAD nonce's security requirement is
uniqueness per key, not secrecy. Only `key` is key material. §9.2's
delete-on-consume still applies to the whole `SkippedKey` — it is removed when
its generation is consumed — independent of the per-field marking.

Cross-consistency requirements, all decode errors when violated:

- Each store's `group_context` MUST name the same cipher suite and
  `group_id` as `core.group_context` (§4.1.1), and its epoch MUST equal the
  store's map key. The store for `core.group_context.epoch` MUST carry a
  `group_context` byte-identical to `core`'s.
- `signature_keys` leaf indices MUST be < the store's `leaf_count`. Never
  empty: a group always has at least one non-blank leaf.
- `chains` keys pack sender leaf index and ratchet kind as
  `(leaf << 1) | kind`, so a key is < 2^33; the encoded `leaf` MUST be <
  `leaf_count`. May be empty — a freshly entered epoch has no chains until
  its first message.
- `node_secrets` keys MUST be valid node indices for `leaf_count`
  (< `2 * leaf_count - 1`). May be empty — a fully consumed secret tree
  retains none.
- `skipped` keys MUST be < `head_generation`. May be empty — an in-order
  chain skips nothing.
- **Retirement.** `head_secret` is absent exactly when the chain is retired,
  and `head_generation` MUST then be `2^32` — one past the last valid
  generation, so the invariant "every generation at or above
  `head_generation` is consumed" holds and every valid generation remains
  addressable in `skipped`. `head_generation` MUST be < `2^32` whenever
  `head_secret` is present. There is exactly one encoding of a retired
  chain.

### 4.4 Retention

The bounds the group was operating under. Always present, actual values —
this format has no notion of a default. Each value MUST be < 2^32:

```
Retention = {
    0: resumption_psk_depth       ; uint
    1: message_secrets_depth      ; uint
    2: max_forward_jump           ; uint
    3: max_skipped_keys_per_sender ; uint
}
```

### 4.5 Config

Profile configuration the group was running under. Neither format defines any
config keys, so the section MUST be absent. When a future format defines
configuration, an unsupported value MUST fail decode — a group is never
silently restored under different rules than it was persisted under.

### 4.6 Exporter Tree

The current epoch's draft-ietf-mls-extensions-08 §4.4 Exporter Tree — an RFC
9420 §9 Secret Tree fixed at 2^16 leaves, rooted at `application_export_secret`
(`DeriveSecret(epoch_secret, "application_export")`) and indexed by a
`ComponentID`. It is persisted as a `SecretTreeState`, the same shape §4.3's
`secret_tree` uses: the surviving node-secret **frontier**, never the root.

```
SecretTreeState = {
    0: leaf_count    ; uint, MUST be 2^16 for the Exporter Tree
    1: node_secrets  ; { + uint => bstr }  SECRET values, length Nh
}
```

Persisting the frontier and not the root is what keeps forward secrecy across
the archive. `SafeExportSecret` consumes a component and deletes its
root-to-leaf path (RFC 9420 §9.2, invoked by draft §4.4) — including the root,
which the first export splits and deletes — so a component consumed before
archiving has no surviving node on its path and cannot be re-derived after
restore. The root, from which every component (consumed or not) could be
re-derived, is therefore never persisted; this matches the deployed peer, which
serializes its `ExporterTree(SecretTree)`, not the root. Only the current
epoch's tree is kept. A decoder MUST reject a `leaf_count` other than 2^16 and
a `node_secrets` index outside a 2^16-leaf tree.

`node_secrets` is **sparse**, not 2^16 entries: the tree materializes nodes on
demand, so an unexported tree persists one secret (the root) and each export
adds at most one copath sibling per level (≤ 16, the tree's depth), fewer with
the overlap of nearby `ComponentID`s. A typical archive carries a handful of
`node_secrets`, never one per leaf.

`exporter_tree` is **optional** (`core` key 8, §4.1.1): every live group
installs a tree, so a conforming producer of format 2 emits it. It is absent
only from an archive written by a producer that predates the Exporter Tree — a
migration source such as a peer's cross-implementation export (format 1).
Restoring such an archive yields a group with no exporter tree;
`SafeExportSecret` is unavailable until the group advances an epoch and installs
one, and — since a format-2 producer emits key 8 rather than omitting it — such
a group also cannot be **re-archived** until then. Nothing is re-derivable in the
meantime, so the absence is forward-secrecy-safe.

### 4.7 Format 1 (decode-only)

Format 1 is the flat, single-membership shape emitted before the D18
client-aware split — chiefly the deployed mls-rs `export_for_swift()` migration
source. This profile decodes it and never writes it (§5); its shape is fixed by
that external emitter and does not grow here.

```
SnapshotFormat1 = {
    0: format                  ; uint, format 1
    1: group_context           ; bstr, MLS GroupContext
    2: ratchet_tree            ; bstr, ratchet_tree extension content
    3: interim_transcript_hash ; bstr, length Nh
    4: my_leaf_index           ; uint, < 2^32
    5: epoch_secrets           ; EpochSecrets (§4.2)
    6: tree_secret_keys        ; { + uint => bstr }  SECRET values (Nsk)
    7: resumption_psks         ; { + uint => bstr }  SECRET values (Nh)
    8: message_secrets         ; { + uint => MessageSecretStoreFormat1 }
    9: retention               ; Retention (§4.4)
  ? 10: config                 ; Config (§4.5) — absent
  ? 11: exporter_tree          ; SecretTreeState (§4.6) — absent from a producer
                               ;   that predates it
}

MessageSecretStoreFormat1 = {
    0..4: as MessageSecretStore (§4.3)
    5: own_next_generation   ; { 0: uint, 1: uint }  handshake, application;
                             ;   each ≤ 2^32
}
```

Restore maps the flat fields onto the format-2 shape: `group_context` through
`exporter_tree` become `core` (§4.1.1), and `my_leaf_index` + `tree_secret_keys`
become the sole `Membership` (§4.1.2) — with no `pending_updates` (format 1 has
no such field) and `own_send` reconstructed from the current epoch's own-leaf
chains (below). The cross-consistency MUSTs of §4.1.1 and §4.3 apply unchanged;
`my_leaf_index` MUST index a non-blank leaf, and `tree_secret_keys` MUST lie on
that leaf's direct path.

A format-1 `MessageSecretStore` carries one field format 2's (§4.3) does not:
`own_next_generation` (key 5), a **required** `{ 0: uint, 1: uint }` giving the
sender's own next handshake and application send positions. A decoder MUST parse
it — it is not an unknown key to skip. At restore it is **cross-checked**: for
each kind, `own_next_generation.<kind>` MUST equal the sender's own-leaf chain
`head_generation` when that chain is present in `chains` (the own leaf is
`my_leaf_index`, keyed `(my_leaf_index << 1) | kind`), and MUST be 0 when it is
absent — a mismatch is a decode error. This is the same value by construction for
an honest emitter — a sender's own send position is its own ratchet's generation
— so it turns a field swift does not otherwise carry into a checked one at the
mis-decode-fatal boundary.

The own-leaf chains are then lifted out of `chains` (a format-2 `chains` holds
remote senders only, §4.3) and, **for the current epoch**, become the
membership's `own_send`: those chains *are* the sender's live send ratchets, so a
member that had sent resumes at its recorded position. Reconstructing rather than
discarding is required, not optional: under §9.2 a member that has sent deleted
the leaf secret its own send ratchet derives from, so a discarded `own_send`
could not be re-seeded and that member could not send again until the next epoch
— a silent send loss across migration. A member that had **not** sent has both
own chains absent and `own_send` unseeded; own send then seeds lazily from the
still-present leaf secret. A member seeds both ratchets from one leaf secret, so
an honest emitter carries both own chains or neither; exactly one present is a
decode error. Retained (non-current) epochs cannot be sent in, so their own-leaf
chains are cross-checked and dropped, never reconstructed.

## 5. Versioning and dispatch

`format` (key 0) is required and is the sole version of the whole item;
sections do not self-version. Because §3 orders map keys strictly increasing
and 0 is the least, `format` is always the **first entry** of the top-level
map. A decoder therefore reads that first entry, selects the schema it names,
and decodes the entire item strictly under that schema. Reading only the first
entry to dispatch is **not** an unknown-key exemption: the probe decodes that
one entry and nothing else, and the selected schema then decodes the whole
item, first entry included. An unknown `format` is a decode error. A future
format change is a new `format` value plus an explicit, specified transform
from the previous one — never a silent reinterpretation of existing fields.

Two formats are defined:

- **Format 2** (`format` = 2) is this profile's native persisted shape (§4.1):
  a client-agnostic `core` plus one entry per local membership. This profile
  always writes format 2.
- **Format 1** (`format` = 1) is the flat, single-membership legacy shape
  (§4.7), **decode-only**: the shape a pre-split producer emits, chiefly the
  deployed mls-rs `export_for_swift()` cross-implementation migration source.
  This profile decodes it — restoring a group with exactly one membership and
  no pending self-Update — and never writes it. Its shape is fixed by that
  external emitter and does not grow here.

Format 2 is **not frozen** until the wire cut: while the target is still under
development it may gain required fields in place without a `format` bump, so an
archive written by an earlier build may fail to decode against a later one. There is no persisted archive corpus to preserve
pre-cut. Once the wire is cut, format 2 freezes and this in-place-growth
allowance ends — any later change takes a new `format` value under the rule
above.

## 6. The Transition contract

MLS is a state machine. Operations advance the state *and* produce outputs,
and neither is safe to persist without the other: persisting new state
without its outputs drops messages (their chain keys are consumed and gone);
persisting outputs without the new state retains consumed keys, which is
both a replay window and a forward-secrecy failure.

A **Transition** arises only where state actually advances. Three operation
shapes, three obligations:

- **Application-message decryption** advances the ratchet and yields a
  Transition.
- **Handshake application** — a commit taking effect — yields a Transition
  at the moment it is *applied*. Validating a commit beforehand is itself a
  Transition when the frame is a `PrivateMessage`: the AEAD open spends the
  sender's ratchet generation (§9.2's delete-on-consume), and that
  consumption MUST be persisted so it is not reused after a restart — even
  when the commit is then declined, or turns out invalid. Validating a
  `PublicMessage`-framed commit consumes nothing and yields no Transition
  until apply; receiving and authenticating short of the private AEAD open
  never advance state.
- **Read-only decryption** (decrypting to display without owning the
  persisted state) yields no Transition, and its derived state MUST be
  discarded rather than persisted.

Therefore:

1. Every state-advancing operation yields a Transition — its outputs paired
   with the Snapshot of the resulting state.
2. For inbound processing: the application MUST persist the transition's
   outputs and snapshot in **one atomic write**, and MUST NOT act on the
   outputs before that write commits. Processing a batch of N messages and
   atomically persisting N outputs with only the final snapshot satisfies
   this — intermediate snapshots need never be encoded.
3. **A commit's epoch advance is applied only once it is canonical.** RFC
   9420 gives the Delivery Service the role of determining which commit
   begins the next epoch; a member MUST NOT apply a commit's epoch advance —
   its own included — before establishing that it is that commit. Applying a
   non-canonical advance is unrecoverable: the previous epoch's state is
   destroyed by design, and the member must rejoin by Welcome. Constructing
   a commit does not advance the epoch — but sealing it under `PrivateMessage`
   framing spends the committer's own next handshake-ratchet generation
   (§9.1: a key/nonce pair MUST NOT encrypt two messages), a consumption that
   rides on the returned transition and MUST be persisted before the commit
   is transmitted, exactly as an outbound message's is (rule 4); the epoch
   advance is the separate pending part, applied later. A `PublicMessage`-framed
   commit consumes nothing and yields no state to persist until it is applied.
   Two further consequences for a committer awaiting confirmation: the
   Welcome produced alongside a commit cannot be regenerated later and MUST
   be retained across the wait if the commit adds members; and the inputs
   needed to reproduce the commit deterministically MUST be retained if the
   implementation intends to recover its own accepted commit after a crash.
4. For outbound `PrivateMessage`s — application and handshake alike: the
   application MUST durably persist the snapshot **before** transmitting.
   The consumed generation is gone from the sender's own chain the moment
   the message is produced; transmitting first and crashing before the
   persist leaves the sender able to reuse that generation, and an AEAD
   key–nonce pair reused across two plaintexts is a confidentiality break.
   A privately-framed commit is one such outbound message (rule 3).
5. Snapshot supersession MUST be replace-not-append: at most one live
   snapshot exists per group. A superseded snapshot is retained key
   material and MUST be destroyed to the storage's ability.
6. On a failed persist, the application MUST discard the new state and MUST
   NOT transmit or deliver. Implementations MUST keep the pre-operation
   state recoverable until the persist commits.
7. **One writer per group.** At most one execution context may advance and
   persist a group's state at a time. Where a platform runs several
   processes against the same stored group — an application and a
   notification extension, say — all but one MUST treat the group as
   read-only and discard any state they derive. Two contexts each performing
   a well-formed atomic write still lose one context's consumptions to the
   other's, which re-arms consumed keys exactly as a rollback would (§7),
   without any storage-level rollback having occurred.

An implementation may offer **in-place** send and receive conveniences that
apply their ratchet consumption to the live group directly, without a deferred
pending — a mutating `protect` on the send side, a mutating `unprotect` for the
application-message receive path. Each is a consumption point: it carries rule 4
(send) or rule 2 (receive) in full — persist before transmitting or before
acting on the plaintext — and a security review treats both as such, exactly as
it treats the two-step forms.

## 7. Security considerations

**A Snapshot is key material.** It MUST NOT reach durable storage
unencrypted. Sealing is deliberately outside this specification — the
profile never holds an encryption key for its own state; the application
owns the key hierarchy and the seal. What this specification fixes is the
plaintext: its schema, and the requirement that secret-marked fields live in
zeroizing storage on both sides of the encoder.

**A stale snapshot is retained keys.** Restoring any snapshot other than
the latest re-arms consumed chain keys: messages already delivered become
decryptable again, and RFC 9420 §9.2's deletion guarantee is silently void
for the rollback window. Applications SHOULD prefer storage that resists
rollback, MUST replace rather than version snapshots, and MUST treat
snapshot restore as the security-relevant operation it is. §6.7's
single-writer requirement is the same hazard reached by a different route.

**Retention bounds the §9.2 tension.** A snapshot inherently persists
values §9.2 will eventually require deleted (unconsumed skipped keys,
retained epochs' stores). The `retention` section is the audit record of
that window: the persisted bounds are the group's actual exposure, not the
code's current defaults.

**Key custody is seed-first.** Private keys in this format are stored as
the raw bytes their suite reconstructs a key from. Conforming
implementations generate those bytes *into* zeroizing storage and construct
platform key objects from them — never the reverse; extracting a serialized
form from a platform key object mints an unscrubbable copy. See
[ADR 0001](../docs/adr/0001-seed-first-key-custody.md).

## 8. Conformance

Planned, held to the same bar as the wire format:

- **Golden vectors**: fixed state → exact snapshot bytes, byte-compared.
  The encoding is deterministic, so vectors pin the format, not an
  implementation. Coverage MUST include the empty-map cases of §4.3 and a
  retired chain, since both are ordinary states with exactly one legal
  encoding.
- **Hostile decode suite**: every strictness rule in §3 and every MUST in
  §4 violated one at a time — including out-of-range integers, wrong-length
  byte strings, duplicate map keys, trailing bytes, and each
  cross-consistency requirement of §4.3. Each MUST fail, none may trap.
- **Round-trip stability**: decode → encode reproduces identical bytes for
  every vector.

The zeroizing-storage requirement of §3 is deliberately outside this
suite: no vector can observe it, and `conformance.md`'s discipline is to say
so rather than imply coverage that does not exist.

A snapshot implementation is not conformant until this section's vectors
exist and pass; until then this document's status line says draft, and the
profile's maturity note does not cover persistence.
