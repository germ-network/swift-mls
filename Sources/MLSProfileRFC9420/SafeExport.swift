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
}
