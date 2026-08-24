import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

@Suite("transcript-hashes.json (mlswg/mls-implementations, official)")
struct TranscriptHashesTests {
	static let provider = SwiftCryptoProvider()

	static let records =
		(try! VectorFile.load("transcript-hashes", as: [TranscriptHashesVector].self))
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test(
		"decodes a real AuthenticatedContent and reproduces the confirmed/interim transcript-hash chain",
		arguments: records
	)
	func matchesVector(_ record: TranscriptHashesVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var reader = MLS.Reader(record.authenticatedContent.bytes)
		let authenticated = try MLS.RFC9420.AuthenticatedContent(from: &reader)
		try reader.finish()

		// Also proves AuthenticatedContent round-trips byte-identically —
		// a structural upgrade over decoding alone.
		#expect(try authenticated.mlsEncoded() == record.authenticatedContent.bytes)

		let confirmationTag = try #require(authenticated.auth.confirmationTag)
		let signature = try #require(authenticated.auth.signature)

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: authenticated.wireFormat,
			encodedContent: try authenticated.content.mlsEncoded(),
			encodedGroupContext: nil)
		let input = try signedContent.confirmedTranscriptHashInput(
			encodedSignature: try signature.mlsEncoded())

		let confirmed = try MLS.Framing.confirmedTranscriptHash(
			provider, interimBefore: record.interimTranscriptHashBefore.bytes,
			input: input)
		#expect(confirmed == record.confirmedTranscriptHashAfter.bytes)

		let interim = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmed, confirmationTag: confirmationTag)
		#expect(interim == record.interimTranscriptHashAfter.bytes)

		// The confirmation tag itself, independently: MAC(confirmation_key, confirmed).
		let recomputedTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: record.confirmationKey.bytes,
			confirmedTranscriptHash: confirmed)
		#expect(recomputedTag == confirmationTag)
	}
}
