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
`welcome_secret`, `confirmation_key`, `external_secret`, and
`external_pub` do not survive into retained state (see the profile's
retention rationale), so no snapshot field exists for them. The
`encryption_secret` appears only transformed, inside the consuming secret
tree of its epoch's message-secret store.

## 3. Encoding

A Snapshot is one deterministic CBOR item (RFC 8949 §4.2.1):

- definite lengths only; no tags; no indefinite-length items;
- integer map keys, sorted bytewise on their encoded form;
- shortest-form heads throughout;
- no floating-point values appear anywhere in this format;
- decoding is strict: any violation of this section, any unknown map key,
  and any unknown `format` value is an error. There is exactly one wire
  form for a given state. Forward compatibility comes from the `format`
  version, never from ignoring fields.

Structures that already have a canonical MLS wire encoding are embedded as
CBOR byte strings containing exactly that encoding, decoded by the profile's
strict MLS reader. This format never re-models a structure that RFC 9420
already encodes: one structure, one encoding, one vector suite.

Fields marked **secret** below are key material. A conforming implementation
holds them in zeroizing storage from decode to consumption and never
materializes them as unmanaged heap values; see §7.

## 4. Schema

### 4.1 Top level

```
Snapshot = {
    0: format                ; uint, this document: 1
    1: group_context         ; bstr, MLS GroupContext (RFC 9420 §8.1)
    2: ratchet_tree          ; bstr, MLS ratchet_tree extension content
                             ;   (RFC 9420 §12.4.3.3: optional<Node> vector)
    3: interim_transcript_hash ; bstr
    4: my_leaf_index         ; uint
    5: epoch_secrets         ; EpochSecrets
    6: tree_secret_keys      ; { + uint => bstr }        SECRET values
    7: resumption_psks       ; { + uint => bstr }        SECRET values
    8: message_secrets       ; { + uint => MessageSecretStore }
    9: retention             ; Retention
  ? 10: config               ; Config — absent when empty
}
```

- `group_context` is the single source of truth for the cipher suite,
  `group_id`, and current epoch. No field in this format duplicates them.
- `ratchet_tree` uses the same encoding the `ratchet_tree` extension carries
  on the wire; its vectors and validation rules apply unchanged.
- `my_leaf_index` MUST index a non-blank leaf of `ratchet_tree`.
- `tree_secret_keys` maps node index → the node's KEM private key, in the
  raw serialized form the suite's KEM accepts for key reconstruction
  (length `Nsk` for the suite). Keys MUST lie on the member's direct path
  (own leaf included) and reference non-blank nodes.
- `resumption_psks` maps epoch → that epoch's resumption PSK (length `Nh`).
  Retained epochs MUST fall within the window `retention` describes,
  relative to `group_context.epoch`.

### 4.2 EpochSecrets

The subset of the current epoch's key-schedule fan-out this profile retains
between operations:

```
EpochSecrets = {
    0: init_secret           ; bstr  SECRET  (Nh)
    1: exporter_secret       ; bstr  SECRET  (Nh)
    2: epoch_authenticator   ; bstr  SECRET  (Nh)
    3: membership_key        ; bstr  SECRET  (Nh)
}
```

### 4.3 MessageSecretStore

One retained epoch's message-decryption state — everything unprotecting that
epoch's messages needs, and deliberately nothing more:

```
MessageSecretStore = {
    0: group_context         ; bstr, that epoch's own MLS GroupContext
    1: sender_data_secret    ; bstr  SECRET  (Nh)
    2: signature_keys        ; { + uint => bstr }   leaf index => public key
    3: secret_tree           ; SecretTreeState
    4: chains                ; { + uint => Chain }  key: (leaf << 1) | kind
                             ;   kind bit: 0 = handshake, 1 = application
    5: own_next_generation   ; { 0: uint, 1: uint } handshake, application
}

SecretTreeState = {
    0: leaf_count            ; uint
    1: node_secrets          ; { + uint => bstr }   SECRET values (Nh)
}

Chain = {
    0: head_generation       ; uint
  ? 1: head_secret           ; bstr  SECRET  (Nh) — absent once retired
    2: skipped               ; { + uint => SkippedKey }  generation => pair
}

SkippedKey = {
    0: key                   ; bstr  SECRET  (Nk for the suite's AEAD)
    1: nonce                 ; bstr  SECRET  (Nn for the suite's AEAD)
}
```

- Epoch keys of `message_secrets` MUST NOT exceed `group_context.epoch` and
  MUST fall within the `message_secrets_depth` window.
- `chains` map keys pack the sender leaf index and ratchet kind into one
  integer, mirroring the tree-math node packing.
- A `Chain` with `head_secret` absent can serve only its `skipped` cache;
  every generation at or above `head_generation` is consumed.

### 4.4 Retention

The bounds the group was operating under. Always present, actual values —
this format has no notion of a default:

```
Retention = {
    0: resumption_psk_depth       ; uint
    1: message_secrets_depth      ; uint
    2: max_forward_jump           ; uint
    3: max_skipped_keys_per_sender ; uint
}
```

### 4.5 Config

Profile configuration the group was running under. `format` 1 defines no
config keys; the section MUST be absent. When a future format defines
configuration, an unsupported value MUST fail decode — a group is never
silently restored under different rules than it was persisted under.

## 5. Versioning

`format` is required and is the only version in this format; sections do not
self-version. An unknown `format` is a decode error. A future format change
is a new `format` value plus an explicit, specified transform from the
previous one — never a silent reinterpretation of existing fields.

## 6. The Transition contract

MLS is a state machine. Operations advance the state *and* produce outputs,
and neither is safe to persist without the other: persisting new state
without its outputs drops messages (their chain keys are consumed and gone);
persisting outputs without the new state retains consumed keys, which is
both a replay window and a forward-secrecy failure.

Therefore:

1. Every state-advancing operation yields a **Transition** — its outputs
   paired with the Snapshot of the resulting state. The outputs are not
   obtainable without the snapshot in hand.
2. For inbound processing: the application MUST persist the transition's
   outputs and snapshot in **one atomic write**, and MUST NOT act on the
   outputs before that write commits. Processing a batch of N messages and
   atomically persisting N outputs with only the final snapshot satisfies
   this — intermediate snapshots need never be encoded.
3. For outbound operations (protecting a message, constructing a commit):
   the application MUST durably persist the snapshot **before**
   transmitting the produced message. Transmitting first risks a fork: a
   crash before persistence leaves the member unable to process the epoch
   it announced.
4. Snapshot supersession MUST be replace-not-append: at most one live
   snapshot exists per group. A superseded snapshot is retained key
   material and MUST be destroyed to the storage's ability.
5. On a failed persist, the application MUST discard the new state and
   MUST NOT transmit or deliver. The prior state remains valid — the
   profile's value semantics guarantee the pre-operation value is intact
   in the caller's hands.

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
snapshot restore as the security-relevant operation it is.

**Retention bounds the §9.2 tension.** A snapshot inherently persists
values §9.2 will eventually require deleted (unconsumed skipped keys,
retained epochs' stores). The `retention` section is the audit record of
that window: the persisted bounds are the group's actual exposure, not the
code's current defaults.

**Key custody is seed-first.** Private keys in this format are stored as
the raw bytes their suite reconstructs a key from. Conforming
implementations generate those bytes *into* zeroizing storage and construct
platform key objects from them — never the reverse; extracting a serialized
form from a platform key object mints an unscrubbable copy. See the
profile's ADR on seed-first custody.

## 8. Conformance

Planned, held to the same bar as the wire format:

- **Golden vectors**: fixed state → exact snapshot bytes, byte-compared.
  The encoding is deterministic, so vectors pin the format, not an
  implementation.
- **Hostile decode suite**: every strictness rule in §3 and every MUST in
  §4 violated one at a time; each MUST fail, none may trap.
- **Round-trip stability**: decode → encode reproduces identical bytes for
  every vector.

A snapshot implementation is not conformant until this section's vectors
exist and pass; until then this document's status line says draft, and the
profile's maturity note does not cover persistence.
