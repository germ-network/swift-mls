import MLSCodec

/// RFC 9420, the conformance reference profile: composes `MLSCodec`,
/// `MLSCrypto`, `MLSTreeMath`, and `MLSFraming` into the base spec's own
/// wire structures and closed message dispatch. Nested under `MLS` rather
/// than sitting flat there, unlike `MLSCodec`/`MLSCrypto`'s vocabulary —
/// this is the one place two profiles genuinely collide on the same name
/// (`MLS.RFC9420.Commit` vs. a later `MLS.Slim.Commit`), which is exactly
/// the case the plan's namespace decision (see `germ-swift-mls/docs/plan.md`)
/// reserves the extra nesting for.
extension MLS {
	public enum RFC9420 {}
}
