import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes

extension MLS.RFC9420.Group {
	/// RFC 9420 §8.5's MLS-Exporter for this group's **current epoch**: a labeled
	/// secret derived from the epoch's `exporter_secret`. A thin, non-consuming
	/// wrapper over `MLS.KeySchedule.exportSecret` — the §8.5 derivation and its
	/// key-schedule KAT live there. That component's own `exportSecret` is
	/// `package`, not adopter-facing, and points applications here; this is that
	/// profile-level entry point.
	///
	/// **Non-consuming and repeatable** — the point of it, versus `safeExportSecret`.
	/// The exported value is a fixed function of `exporter_secret` for the epoch's
	/// entire lifetime, so repeated calls with the same `label`, `context`, and
	/// `length` at the same epoch return the same bytes, and a repeat of a
	/// successful call never throws (the method is non-`mutating` for exactly this
	/// reason). It therefore has **no per-epoch
	/// forward secrecy**: while the epoch's `exporter_secret` is retained, any past
	/// export of the same inputs is re-derivable. Advancing the epoch re-keys
	/// `exporter_secret`, so exports do not carry across epochs.
	///
	/// Use this for key material an application must re-derive deterministically at
	/// the current epoch (per-message rendezvous / header keys and the like). For a
	/// single-shot, forward-secret per-component export, use
	/// `safeExportSecret(_:componentID:)` (draft-ietf-mls-extensions §4.4) instead —
	/// a distinct primitive, unchanged by this method.
	///
	/// On a combined group (e.g. `MLS.Combiner.CombinerGroup`) this is callable
	/// per-half via `.classical` / `.pq`, which are public `Group`s; each half
	/// derives from its own `exporter_secret`.
	///
	/// - Throws: `GroupError.exportLengthOutOfRange` if `length` is outside
	///   `1...255 * Nh` — checked here rather than left to the HKDF backend,
	///   which traps instead of throwing past that bound.
	public func exportSecret(
		_ provider: any MLS.CipherSuiteProvider,
		label: String,
		context: Data,
		length: Int
	) throws -> SecretBytes {
		let maximum = 255 * provider.hashSize
		guard length > 0, length <= maximum else {
			throw MLS.RFC9420.GroupError.exportLengthOutOfRange(
				length: length, maximum: maximum)
		}
		return try MLS.KeySchedule.exportSecret(
			provider, exporterSecret: epoch.exporterSecret,
			label: label, context: context, length: length)
	}
}
