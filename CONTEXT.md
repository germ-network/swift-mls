# swift-mls

A construction kit for MLS-family protocols: profile-independent components
assembled into complete protocols, with RFC 9420 as the conformance reference
rather than a privileged core.

## Language

**Component**:
A profile-independent target owning mechanism, never policy — `MLSCodec`,
`MLSCrypto`, `MLSFraming`, `MLSKeySchedule`, `MLSTreeKEM`, `MLSTreeMath`.
_Avoid_: kit (prose metaphor for the components collectively; not a design
term), module, layer

**Profile**:
A complete protocol assembled from components, owning policy — retention,
configuration, snapshot composition. `MLS.RFC9420` is one; others sit beside
it, not beneath it.
_Avoid_: implementation, variant

**Snapshot**:
A profile's persisted group state at a point in time, complete and
replaceable. Contains only group-resident state — nothing shareable across
groups (signing keys, proposal stores, pre-published key packages are the
consumer's to persist).
_Avoid_: archive (an overloaded term elsewhere; here the container technology
a Snapshot serializes into is not the Snapshot)

**Transition**:
The paired result of a state-advancing operation: the outputs plus the
Snapshot that must be persisted with them. The pairing exists because neither
half is safe to persist without the other.
_Avoid_: result, update
