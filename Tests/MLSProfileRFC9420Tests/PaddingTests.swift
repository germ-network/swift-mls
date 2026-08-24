import Foundation
import MLSCodec
import MLSFraming
import Testing

@testable import MLSProfileRFC9420

/// `message-protection.json`'s own `priv` fields carry no padding (RFC
/// 9420 leaves the target-length policy unspecified, and the vector fixes
/// one), so `MessageProtectionTests`' round-trips never exercise §6.3.1's
/// padding rules at all. These are synthetic, direct against
/// `PrivateMessageContent` rather than the full protect/unprotect pipeline
/// — no secret tree or AEAD needed to prove padding itself is correct.
@Suite("PrivateMessageContent padding (RFC 9420 §6.3.1)")
struct PaddingTests {
	private static let content = MLS.RFC9420.Content.application(Data([1, 2, 3]))
	private static let auth = MLS.FramedContentAuthData(
		signature: MLS.Signature(Data(repeating: 9, count: 64)), confirmationTag: nil)

	@Test("paddingLength adds exactly that many trailing zero bytes, and decode strips them")
	func roundTrips() throws {
		let unpadded = try MLS.RFC9420.PrivateMessageContent(
			content: Self.content, auth: Self.auth
		).encode(paddingLength: 0)
		let padded = try MLS.RFC9420.PrivateMessageContent(
			content: Self.content, auth: Self.auth
		).encode(paddingLength: 16)

		#expect(padded.count == unpadded.count + 16)
		#expect(padded.suffix(16).allSatisfy { $0 == 0 })

		let decoded = try MLS.RFC9420.PrivateMessageContent.decode(
			padded, contentType: .application)
		#expect(decoded.content == Self.content)
	}

	@Test("a non-zero padding byte is rejected, not silently accepted")
	func rejectsNonZeroPadding() throws {
		var padded = try MLS.RFC9420.PrivateMessageContent(
			content: Self.content, auth: Self.auth
		).encode(paddingLength: 4)
		padded[padded.count - 1] = 1

		#expect(throws: MLS.FramingError.paddingNotZero) {
			_ = try MLS.RFC9420.PrivateMessageContent.decode(
				padded, contentType: .application)
		}
	}
}
