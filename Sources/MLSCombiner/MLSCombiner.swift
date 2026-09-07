import MLSCodec

/// The generic APQ combiner of `draft-ietf-mls-combiner` (tracked revision:
/// **-02**, dated 2025-10-20). `MLS.Combiner` runs two RFC 9420 groups — a
/// classical (traditional) half and a post-quantum half — and binds the
/// classical half to the PQ half's secrecy via an exported `apq_psk`
/// (draft §6.2), so application messages on the classical half are quantum-safe
/// even though the PQ half ratchets rarely.
///
/// An **above-profile consumer**: it composes `MLSProfileRFC9420` (two `Group`s)
/// and the `MLSExtensions` Safe-Extensions substrate (the exporter tree /
/// `SafeExportSecret`, the application-PSK derivation, and the `AppDataUpdate`
/// proposal envelope). It adds **no crypto** — only the `ExportedPsk` descriptor,
/// the `APQInfo` GroupContext extension (§6), the `ApqInfoUpdate` epoch
/// attestation (§6.1), the `CombinerGroup` establish/join orchestration, and the
/// §7 paired structures.
///
/// Draft-generic only. The Germ deviations — the §A.4/§A.5 PQ ratchets and their
/// injected-secret PSK, the cross-party and attachment PSK domains, `AppBinding`,
/// the 2-party `MlsRules`, the authentication service, the session persistence
/// model, and the Germ tag+length wire framing — live downstream (twomlspq-swift),
/// which consumes this module. Codepoints are parameterized ([`Codepoints`]) and
/// default to the deployed TwoMLSPQ values, so the module is wire-compatible with
/// that deployment out of the box while a future IANA assignment is a one-line
/// change.
///
/// The tracked revision moves only deliberately: there is no wire- or
/// state-stability guarantee across draft revisions, so a bump is a reviewed
/// change, and this module owns its own cross-draft compat.
extension MLS {
	public enum Combiner {}
}
