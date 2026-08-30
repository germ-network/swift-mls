import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSFraming

// Proves MLSFraming's mechanisms work against content bytes it cannot
// parse — this target links no profile, only MLSCodec/MLSCrypto, so
// `encodedContent` below is never anything but opaque Data. That is the
// actual test of the target boundary, not a claim about it.
@Suite("SignedContent: TBS/TBM/transcript-hash assembly, no profile linked")
struct SignedContentTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	@Test("TBS is version ‖ wire_format ‖ content, with the context appended only when present")
	func tbsShape() throws {
		let content = Data("synthetic framed content, opaque to this target".utf8)
		let withContext = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: content,
			encodedGroupContext: Data("group context bytes".utf8))
		let withoutContext = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: content, encodedGroupContext: nil)

		let tbsWith = try withContext.toBeSigned()
		let tbsWithout = try withoutContext.toBeSigned()

		// version(2) ‖ wire_format(2) ‖ content — identical prefix either way.
		let prefixLength = 2 + 2 + content.count
		#expect(tbsWith.prefix(prefixLength) == tbsWithout)
		#expect(tbsWith.count == tbsWithout.count + "group context bytes".utf8.count)
	}

	@Test("TBM = TBS ‖ auth data, byte-exact concatenation")
	func tbmShape() throws {
		let signed = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .privateMessage,
			encodedContent: Data([1, 2, 3]), encodedGroupContext: nil)
		let auth = Data([9, 9, 9, 9])
		let tbs = try signed.toBeSigned()
		#expect(try signed.toBeMACed(encodedAuthData: auth) == tbs + auth)
	}

	@Test("membership tag and confirmation tag round-trip through MAC ≡ HKDF-Extract")
	func tagsRoundTrip() throws {
		let signed = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: Data("commit content".utf8),
			encodedGroupContext: Data("ctx".utf8))
		let membershipKey = Data("membership_key".utf8)
		let tag = try MLS.Framing.membershipTag(
			Self.provider, membershipKey: membershipKey, signedContent: signed,
			encodedAuthData: Data([1, 2]))
		let recomputed = try MLS.Framing.membershipTag(
			Self.provider, membershipKey: membershipKey, signedContent: signed,
			encodedAuthData: Data([1, 2]))
		#expect(tag == recomputed)

		let differentKey = try MLS.Framing.membershipTag(
			Self.provider, membershipKey: Data("different".utf8), signedContent: signed,
			encodedAuthData: Data([1, 2]))
		#expect(tag != differentKey)
	}

	@Test("transcript hash chains: confirmed then interim, deterministic")
	func transcriptHashChains() throws {
		let interim0 = Data(repeating: 0, count: 32)
		let input = Data("ConfirmedTranscriptHashInput bytes".utf8)
		let confirmed = try MLS.Framing.confirmedTranscriptHash(
			Self.provider, interimBefore: interim0, input: input)
		let tag = MLS.ConfirmationTag(Data("a confirmation tag".utf8))
		let interim1 = try MLS.Framing.interimTranscriptHash(
			Self.provider, confirmed: confirmed, confirmationTag: tag)

		#expect(confirmed.count == Self.provider.hashSize)
		#expect(interim1.count == Self.provider.hashSize)
		#expect(confirmed != interim1)
	}
}
