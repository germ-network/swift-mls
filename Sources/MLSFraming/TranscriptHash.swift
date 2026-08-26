import Foundation
import MLSCodec
import MLSCrypto

extension MLS.Framing {
	/// `ConfirmedTranscriptHash = Hash(InterimTranscriptHash_[n-1] ‖
	/// ConfirmedTranscriptHashInput_[n])`.
	public static func confirmedTranscriptHash(
		_ provider: any MLS.CipherSuiteProvider, interimBefore: Data, input: Data
	) throws -> Data {
		try provider.hash(interimBefore + input)
	}

	/// `InterimTranscriptHash = Hash(ConfirmedTranscriptHash_[n] ‖
	/// InterimTranscriptHashInput_[n])`, where
	/// `InterimTranscriptHashInput` is just `MAC confirmation_tag`,
	/// encoded as `opaque<V>` (RFC 9420 §7.2).
	public static func interimTranscriptHash(
		_ provider: any MLS.CipherSuiteProvider, confirmed: Data,
		confirmationTag: MLS.ConfirmationTag
	) throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(confirmationTag)
		return try provider.hash(confirmed + Data(writer.bytes))
	}
}
