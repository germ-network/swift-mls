import Foundation
import MLSCodec

// RFC 9180 provider-authoring toolkit.
//
// The labeled KDF and `suite_id` construction a custom `CipherSuiteProvider`
// needs to assemble base-mode HPKE over its own KEM. The swift-crypto-backed
// suites delegate HPKE to CryptoKit's `HPKE.Sender`/`Recipient` and never
// surface these; a provider for a KEM swift-crypto doesn't know — an ML-KEM
// suite, say — builds its key schedule on them instead. Making the seam's
// components reusable this way is the point of the library.

extension MLS {
	/// RFC 9180 §5.1 HPKE `suite_id = "HPKE" ‖ I2OSP(kem_id,2) ‖ I2OSP(kdf_id,2) ‖ I2OSP(aead_id,2)`.
	/// Registry ids are RFC 9180 §7.1–§7.3.
	public static func hpkeSuiteID(kemID: UInt16, kdfID: UInt16, aeadID: UInt16) -> Data {
		Data("HPKE".utf8) + i2osp(kemID) + i2osp(kdfID) + i2osp(aeadID)
	}

	/// RFC 9180 §4.1 KEM `suite_id = "KEM" ‖ I2OSP(kem_id,2)` — the DeriveKeyPair scope,
	/// distinct from the combined HPKE `suite_id` above.
	public static func hpkeKEMSuiteID(kemID: UInt16) -> Data {
		Data("KEM".utf8) + i2osp(kemID)
	}
}

extension MLS.CipherSuiteProvider {
	/// RFC 9180 §4 `LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" ‖ suiteID ‖ label ‖ ikm)`.
	/// `suiteID` is the KEM or HPKE `suite_id` for the construction in hand
	/// (see `MLS.hpkeSuiteID` / `MLS.hpkeKEMSuiteID`).
	public func hpkeLabeledExtract(
		suiteID: Data, salt: some ContiguousBytes, label: String, ikm: Data
	) throws -> Data {
		try kdfExtract(
			salt: salt, ikm: Data("HPKE-v1".utf8) + suiteID + Data(label.utf8) + ikm)
	}

	/// RFC 9180 §4 `LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L,2) ‖ "HPKE-v1" ‖ suiteID ‖ label ‖ info, L)`.
	public func hpkeLabeledExpand(
		suiteID: Data, prk: some ContiguousBytes, label: String, info: Data, length: Int
	) throws -> Data {
		let labeledInfo =
			i2osp(UInt16(length)) + Data("HPKE-v1".utf8) + suiteID + Data(label.utf8)
			+ info
		return try kdfExpand(prk: prk, info: labeledInfo, length: length)
	}
}

/// RFC 9180 §3 `I2OSP(n, w)` with the width pinned to 2 (`UInt16`, big-endian) —
/// every HPKE use of I2OSP here has `w == 2`.
private func i2osp(_ value: UInt16) -> Data {
	var bigEndian = value.bigEndian
	return withUnsafeBytes(of: &bigEndian) { Data($0) }
}
