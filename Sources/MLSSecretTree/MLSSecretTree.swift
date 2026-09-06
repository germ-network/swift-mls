import MLSCodec

/// RFC 9420 §9's deletion-schedule secret tree, as a generic mechanism: a
/// map of live node secrets seeded at a root that *consumes* as it descends
/// (`ConsumingSecretTree`), plus the one-node split (`splitTreeNode`) it walks
/// with. Two unrelated trees compose it — the key schedule's per-member
/// message secret tree (`MLSKeySchedule`/`MLSProfileRFC9420`) and the Safe
/// Extensions exporter tree (`MLSExtensions`) — so it is homed here, below
/// both, rather than in either.
///
/// Depends only on `MLSCodec`, `MLSCrypto`, `MLSTreeMath`, and `SecretBytes`:
/// it is pure tree-index arithmetic plus `ExpandWithLabel`, and knows nothing
/// of epochs, wire formats, or which secret roots it. `MLS.SecretTree` rather
/// than `MLS.KeySchedule.*` because this module sits below the key schedule
/// and cannot extend that namespace.
extension MLS {
	public enum SecretTree {}
}
