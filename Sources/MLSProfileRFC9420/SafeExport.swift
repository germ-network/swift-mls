import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes

extension MLS.RFC9420.Group {
	/// draft-ietf-mls-extensions-08 §4.4 `SafeExportSecret`: the per-component
	/// exported secret for this group's **current epoch**, consumed once — a
	/// second export of the same component in the same epoch throws
	/// (`ExporterTree.ExportError`). `componentID` indexes the 2^16-leaf tree;
	/// ids ≥ 2^16 are rejected.
	///
	/// Forward secrecy (RFC 9420 §9.2, which §4.4 invokes): the group holds the
	/// *consuming* Exporter Tree, built at epoch install and never the raw
	/// `application_export_secret` root — the first export splits and deletes the
	/// root, and each export deletes its component's root-to-leaf path. So a
	/// consumed component cannot be re-derived, live or after an archive: the
	/// snapshot persists the tree's surviving frontier (`spec/snapshot.md`), not
	/// the root. Matches the deployed fork, which holds and serializes
	/// `ExporterTree(SecretTree)`, never the root seed.
	public mutating func safeExportSecret(
		_ provider: any MLS.CipherSuiteProvider, componentID: MLS.KeySchedule.ComponentID
	) throws -> SecretBytes {
		let epochNumber = context.epoch
		// Built by `installMessageSecrets` on every epoch-entry path and by
		// `restore`, so this is present for any live or restored group; absence
		// would be an internal inconsistency, not a caller error.
		guard var tree = exporterTrees[epochNumber] else {
			throw MLS.RFC9420.GroupError.exporterTreeUnavailable
		}
		// Persist the consumed path whether the export succeeds or throws (a
		// re-export/out-of-range leaves the tree unchanged).
		defer { exporterTrees[epochNumber] = tree }
		return try tree.safeExportSecret(provider, componentID: componentID)
	}

	/// draft-ietf-mls-combiner-02 §6.2's application-PSK derivation over the
	/// draft-ietf-mls-extensions-08 §4.5 exporter: exports this component's secret
	/// for the current epoch and derives the pair `(psk_id, psk)` from it —
	/// `psk_id = DeriveSecret(exporter, "psk_id")` (a public identifier),
	/// `psk = DeriveSecret(exporter, "psk")` (the secret). The exporter secret is
	/// consumed (`safeExportSecret`) and dropped after both derivations, per
	/// §6.2's / RFC 9420 §9.2's MUST-delete.
	///
	/// **Single-shot.** The exporter leaf is consumed and its deletion persists
	/// (the snapshot archives the consumed frontier), so a given
	/// `(group, epoch, component)` derives exactly once and the pair is
	/// unrecoverable from group state afterward. Derive immediately before the
	/// commit or Welcome that imports the PSK, or persist the pair yourself; drop
	/// `psk` once that commit consumes it (forward secrecy), keeping only the
	/// public `psk_id` if still needed. Both parties on the same
	/// `(group, epoch, component)` derive an identical pair independently — only
	/// the `PreSharedKeyID` (with its nonce) crosses the wire, inside the proposal
	/// the caller assembles as `.application(componentID:, pskID:, nonce:)`.
	///
	/// The labels `"psk_id"`/`"psk"` are draft-combiner-02 Figure 3; the deployed
	/// fork (`germ-network/mls-rs@b43703f`) applies plain RFC 9420 `DeriveSecret`
	/// with them — the tie-breaker the KAT pins, since the draft's prose is silent.
	public mutating func deriveApplicationPSK(
		_ provider: any MLS.CipherSuiteProvider,
		componentID: MLS.KeySchedule.ComponentID
	) throws -> (pskID: Data, psk: SecretBytes) {
		let exporter = try safeExportSecret(provider, componentID: componentID)
		let pskID = try MLS.deriveSecret(provider, secret: exporter, label: "psk_id")
		let psk = try MLS.deriveSecretSecret(provider, secret: exporter, label: "psk")
		return (pskID, psk)
	}
}
