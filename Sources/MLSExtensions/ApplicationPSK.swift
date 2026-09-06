import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes

extension MLS.Extensions {
	/// draft-ietf-mls-combiner-02 §6.2's application-PSK derivation over a
	/// draft-ietf-mls-extensions §4.4 `SafeExportSecret`: from a component's
	/// exported secret, derive the pair `(psk_id, psk)` —
	/// `psk_id = DeriveSecret(exporter, "psk_id")` (a public identifier),
	/// `psk = DeriveSecret(exporter, "psk")` (the secret). combiner-02 §6.2
	/// requires the exporter be dropped once both are derived; this pure helper
	/// takes the exporter by value and derives both here, so the caller can let
	/// it fall out of scope immediately after.
	///
	/// Profile-independent: it consumes nothing and holds no group state — the
	/// single-shot forward secrecy of a `(group, epoch, component)` triple is the
	/// exporter's property (`ExporterTree.safeExportSecret` consumes the leaf),
	/// not this derivation's. Both parties on the same exporter secret derive an
	/// identical pair; only the `PreSharedKeyID` (assembled by a profile) crosses
	/// the wire.
	///
	/// `psk` is returned zeroizing. The labels `"psk_id"`/`"psk"` are combiner-02
	/// Figure 3 (its prose is silent); the deployed fork applies plain RFC 9420
	/// `DeriveSecret` with them — the source tie-breaker.
	public static func deriveApplicationPSK(
		_ provider: any MLS.CipherSuiteProvider,
		exporter: some ContiguousBytes
	) throws -> (pskID: Data, psk: SecretBytes) {
		let pskID = try MLS.deriveSecret(provider, secret: exporter, label: "psk_id")
		let psk = try MLS.deriveSecretSecret(provider, secret: exporter, label: "psk")
		return (pskID, psk)
	}
}
