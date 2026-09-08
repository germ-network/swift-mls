---
status: accepted; implementation pending
---

# Identity custody and the signing seam

The signing key is a per-operation input, never group state (`spec/snapshot.md`
§4.3: the snapshot persists only public signature keys; `Group.restore` re-supplies
no secret). This ADR decides how the authoring API must be shaped so that the
external key may be a **stateful, consumable** secret — a usage-limited key, or a
hash-based one-time signature whose leaves are consumed and tombstoned — held by
the application, shared across every group that identity is in.

**This describes the decided target, not the current code.** Today the authoring
entry points take a raw `signingKey: MLS.SignatureSecretKey` and the send ratchet
is seeded lazily on first send — both of which this ADR rules out for a stateful
signer (see Consequences).

## Why the key cannot live in the group

Two facts force the design. First, the signing identity is **shared across
groups**. Second, a private key may carry mutable, security-critical consumption
state whose reuse is catastrophic (a one-time signature reused is identity
compromise, not graceful degradation). A library that stored the key inside the
group — as some peer implementations do, serializing it into per-group state —
would keep one *copy per group*, and advancing a counter in one group's copy
would silently diverge from another's, producing reuse. The external-key
invariant is precisely what lets a single custodian own the one authoritative
consumption state. The invariant is the precondition, not an inconvenience.

## The three tiers, and where the actor goes

Group state divides into three tiers by sharing scope:

- **`GroupCore`** — context, tree, transcript, epoch secrets, PSKs, message
  secrets, exporter — per group.
- **`Membership`** — leaf index, HPKE secret keys, pending self-update, own-send
  ratchets — per (group, membership). Every field is group-specific.
- **Identity** — the signing key and its consumption state — per identity, shared
  across that identity's groups. This tier does not exist in the current model;
  it is the only cross-group state.

`Group` and `Membership` are **values**. The **identity is the one actor**, owned
by the application, serializing access to the shared consumable. Serialized access
is inherent to a shared consumable, so an actor is unavoidable there — but it
belongs on the identity, **not** the group. The library remains actor-free; an
operation runs under the identity's isolation, takes the group and membership
values, and yields new values plus the wire message, while the consumed
identity-state is persisted in the identity's domain.

The join side has the same shape: a reusable last-resort KeyPackage (RFC 9420
§16.8) is `(shared secret + consumption state)` too — its replay-protection map is
the consumable, and the library already reports the consumption as data
(`PendingJoin.consumedKeyPackage`, reported whether or not the app applies). An
application-side custodian owning that map is the join-side twin of the identity
actor. So the identity actor is best understood as the custodian of an identity's
consumable resources generally, not a signer alone.

## The signing seam is a crypto-primitive seam, not a transition-effects seam

A stateful signature is a third kind of consumption, distinct from the two the
library already has. The send-ratchet spend is *performed by the library* and
recorded in the value it returns (`Membership.ownSend`). The KeyPackage
consumption is *performed by the library* with a reference *reported* to an
app-held store. A signature is neither: the library **cannot perform it** (it
holds no key) and **needs the result mid-computation** — the leaf signature feeds
the tree hash, then the provisional context, then the path
(`CommitConstruction.swift` `setLeaf`→`treeHash`→provisional context); the
FramedContent signature feeds the confirmed transcript, then the key schedule,
then the confirmation tag; the GroupInfo signature needs the welcome secret. A
post-hoc "report the new signer state" seam cannot carry a consumption the library
never performed, and the library must never see the advanced state.

**Decision.** The authoring APIs take a **synchronous, non-escaping signer
closure** in place of the raw key, at the one crypto choke point all signing
already funnels through (`MLS.signWithLabel` → `CipherSuiteProvider.sign`):

```
sign: (SigningRequest) throws -> Signature      //  SigningRequest = { label, tbs, role }
role ∈ { leafNode, framedContent, groupInfo }
```

The application calls the operation from inside its identity actor, so the closure
runs on the identity's executor with the consumable in reach; the library names no
application type and stays actor-free. This is the house pattern already used for
secret material — the PSK resolver (`psk:`) is a synchronous secret-resolving
closure of exactly this shape.

**Ticket pool vs. live consumption is an application strategy behind the
closure.** For a one-time signer, the custodian consumes and persists a ticket at
*issuance* and the closure hands the library the next pre-persisted ticket — so the
ordering rule below holds structurally (you cannot sign without a persisted
capability) and the operation stays synchronous even if issuance was async. For a
usage-limited key the closure consumes live and the ordering rule is discharged by
the app before release. The library seam is identical either way; only the
closure's implementation differs. The demonstration test
(`Tests/MLSProfileRFC9420Tests/IdentityCustodianTests.swift`) exercises the
pre-persisted-ticket form against the real API.

**Rotation stays single-actor via a key ring.** A commit that rotates the
committer's signature key signs its own leaf and GroupInfo with the *new* key
while the enclosing FramedContent stays on the *old* key (the credential-rotation
authoring API). Because that is two identities' state in one operation, the actor
is the *principal* holding a ring (`current`, `next`) and the `role` selects the
ring slot; rotation is intra-actor and retires `current` after the commit is
affirmed.

## The two-store ordering contract

An operation advances two independently persisted stores: the identity's
consumption (S_I, in the custodian) and the group value (S_G, adopted and
persisted by the app). Let an *artifact* be anything embedding a signature — the
commit message, the Welcome (transmitted later), an exported GroupInfo, or a
persisted pending-commit slot. The contract:

- **S_I durable before any artifact is persisted or leaves the process.**
- **S_G durable before the message is transmitted** (the existing adopt-before-
  transmit rule).
- The only order that stays safe as persistence grows is **S_I → S_G → transmit**.
  S_G-before-S_I lets a crash-and-rebuild re-sign a *different* transcript under the
  same one-time leaf.
- Recovery after a crash is **rebuild, never re-sign** (signatures are randomized
  on the ECDSA suites, and tickets are consumed); re-transmitting identical bytes
  requires having persisted the message under the first rule.
- The consumption advance is synchronous before any suspension, and the durable
  form is **monotone-merge** (max / append-only tombstones / version-CAS), never
  "write back the returned value" — this is the stale-successor rollback hazard the
  handshake seam already guards, now in the identity store.
- The actor is per **process**; the durable store (a file lock or a version-CAS in
  the app's storage) is the true cross-process serializer. On a platform where a
  main app and an extension both hold the identity, the store — not the actor — is
  what prevents a forked counter.

## Multiple local memberships (N > 1)

`GroupCore` has genuinely shared mutable state at N > 1: the consuming secret tree,
written both by each local membership's send-seed and by remote receives. Two
memberships of one group are two identities (§7.3 requires unique signature keys),
so one `Group` value is written by two identity actors — which no identity actor
serializes.

**Decision.** Keep one shared `GroupCore` and make live sends membership-local by
**seeding each local membership's send ratchet eagerly at epoch install** (beside
the message-secret state, which is already built eagerly there) instead of lazily
on first send. Then sends touch only per-`Membership` state and are conflict-free;
the shared secret tree is written only by the eager seed and by remote receives,
which are processed from an ordered inbound stream. The group's single-writer
obligation reduces to a statable precondition — *one group value ⇒ one writer; N
local memberships funnel their epoch-advancing operations through it* — which
delivery-order already satisfies and the N = 1 case already requires. No group
actor is introduced; the identity remains the only actor.

The consuming secret tree supports this safely: deriving a leaf deletes its path
nodes but caches every copath sibling, so any remaining leaf stays derivable in any
order (`ConsumingSecretTree` — the only failure is re-deriving a consumed leaf).
Eagerly deriving the local leaves at install cannot strand a later remote receive.

The alternative — a private `GroupCore` copy per membership — is **deferred**. Its
only unique payoff is placing two local memberships of the *same* group in
*separate* isolation domains, which is out of scope; it costs N-fold duplication and
loses the cross-membership commit-secret agreement check.

## Peer context

Both key-in-group implementations that persist the signer into per-group state are
structurally unable to host a shared stateful signer; the one peer that keeps the
key external does so through a stateless-shaped signing trait, leaving a stateful
signer to bolt on its own interior mutability and cross-group coordination. The
external-key invariant plus an explicit consumption seam is what this project
gains from keeping the key out of the group.

## Consequences

- The authoring entry points (`committing` and its `as:` form, `proposeUpdate` /
  `proposingUpdate`, `protect`) and the public `sign*`/`protect*` statics take a
  synchronous signer closure with a `role`, in place of `signingKey:`. A stateless
  key becomes a trivial closure; existing callers adapt at the call site.
- A signature is no longer a `SecretBytes`-only affair: a one-time signer's ticket
  (a leaf key + index + auth path) is a distinct shape, so a signer/ticket type is
  introduced rather than widening `SignatureSecretKey`.
- Send-ratchet seeding moves from lazy (first send) to eager (epoch install) for
  every local membership; `own_send` becomes always-present after install in the
  snapshot (already a persisted, optional field).
- Initial-leaf and KeyPackage signing happen outside the library today (`Group.create`
  takes a pre-signed leaf); a stateful signer's counter is only correct if those
  initial signatures also route through the same custodian.
- The library states the two-store ordering contract; it does not own the stores.
  The consumption events it must surface as data already exist on the join side
  (`consumedKeyPackage`) and must be added for the signature side.
- `IdentityCustodianTests.swift` demonstrates the composition against the real API
  with no library change, by observing per-signature consumption through a provider
  wrapper at the `sign` choke point: it pins the signature chain per operation, the
  S_I → S_G → transmit ordering and the harm of reversing it, that a crash-rebuild
  never reuses a ticket, cross-group monotonicity under one identity, that the group
  value round-trips holding no key, and that the last-resort replay map must key on
  the join context rather than the (constant) KeyPackage reference.
