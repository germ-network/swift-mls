import Foundation
import MLSCodec
import MLSCrypto

extension MLS.Framing {
	/// RFC 9420 §6.2: `MAC(membership_key, AuthenticatedContentTBM)`.
	public static func membershipTag(
		_ provider: any MLS.CipherSuiteProvider, membershipKey: some ContiguousBytes,
		signedContent: SignedContent, encodedAuthData: Data
	) throws -> MLS.MembershipTag {
		let tbm = try signedContent.toBeMACed(encodedAuthData: encodedAuthData)
		return MLS.MembershipTag(try provider.mac(key: membershipKey, data: tbm))
	}

	/// `MAC(confirmation_key, confirmed_transcript_hash)`.
	public static func confirmationTag(
		_ provider: any MLS.CipherSuiteProvider, confirmationKey: Data,
		confirmedTranscriptHash: Data
	) throws -> MLS.ConfirmationTag {
		MLS.ConfirmationTag(
			try provider.mac(key: confirmationKey, data: confirmedTranscriptHash))
	}
}
