import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes

extension MLS.RFC9420.Group {
	/// draft-ietf-mls-extensions-08 §4.4 `SafeExportSecret`: the per-component
	/// exported secret for this group's **current epoch**, derived off the
	/// epoch's Exporter Tree and consumed once — a second export of the same
	/// component in the same epoch throws (`ExporterTree.ExportError`, RFC 9420
	/// §9.2 forward secrecy). `componentID` indexes the 2^16-leaf tree; ids
	/// ≥ 2^16 are rejected.
	///
	/// The tree is built lazily from the retained `application_export_secret` on
	/// first use and cached for the epoch's lifetime, so consume-once holds
	/// across calls within a live session. It is **not persisted**: a group
	/// `restore`d from an archive rebuilds a fresh tree from the same retained
	/// seed, so a component consumed before archiving can be re-exported after
	/// restore. That is a deliberate, bounded forward-secrecy relaxation across
	/// the archive boundary — the seed already lives in the (full-secret)
	/// archive, and unlike the message ratchet this derivation is deterministic
	/// and per-component independent, so re-derivation yields identical bytes
	/// with no shared state to desync.
	public mutating func safeExportSecret(
		_ provider: any MLS.CipherSuiteProvider, componentID: UInt32
	) throws -> SecretBytes {
		let epochNumber = context.epoch
		var tree =
			try exporterTrees[epochNumber]
			?? MLS.KeySchedule.ExporterTree(
				applicationExportSecret: epoch.applicationExportSecret)
		// Persist the consumed leaf, and drop any stale prior-epoch tree, whether
		// the export succeeds or throws (a re-export leaves the tree unchanged).
		defer { exporterTrees = [epochNumber: tree] }
		return try tree.safeExportSecret(provider, componentID: componentID)
	}
}
