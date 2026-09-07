import MLSCodec

/// The MLS Safe Extensions substrate — `draft-ietf-mls-extensions` is the
/// normative authority for everything under `MLS.Extensions`. This is the
/// profile-independent core (the Exporter Tree and `SafeExportSecret` of §4.4,
/// the `ComponentID` of §4.1, the application-PSK derivation an APQ combiner
/// layers on the exporter, and the generic `AppDataUpdate` proposal envelope of
/// §4.7); a profile wires it into its own group state. It composes only `MLSCodec`, `MLSCrypto`, `MLSTreeMath`, and the
/// shared `MLSSecretTree` mechanism — deliberately NOT `MLSKeySchedule` or any
/// profile. The exporter tree takes the epoch's exporter root as bytes, so the
/// substrate never reaches back into the key schedule; that one-way dependency
/// is the structural proof the substrate is cleanly separable.
///
/// Tracked revision: **draft-09**. The one revision-sensitive choice in the
/// code is `ComponentID`, which -09 narrowed from `uint32` to `uint16` (§4.1);
/// this module pins that. The tracked revision moves only deliberately — there
/// is no wire- or state-stability guarantee across draft revisions, so a bump
/// is a reviewed change, not a silent one.
extension MLS {
	public enum Extensions {}
}
