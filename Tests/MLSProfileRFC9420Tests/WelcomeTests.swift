import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Structural coverage only, per this phase's scope: `key_package` and
/// `welcome` are both `MLSMessage`-wrapped, decoded here via
/// `MLS.RFC9420.Message` the same way `messages.json` exercises those two
/// cases. The vector's full verification (test-vectors.md, "Welcome") goes
/// further — HPKE-decrypt `GroupSecrets` with `init_priv`, AEAD-decrypt the
/// embedded `GroupInfo`, verify its signature with `signer_pub`, then derive
/// a key-schedule epoch from the decrypted `joiner_secret` and recompute
/// `confirmation_tag` — which is genuinely join-flow logic (`MLS.RFC9420`
/// passive-client work), not framing/wire-structure work, so it belongs to
/// that later phase rather than this one.
@Suite("welcome.json (mlswg/mls-implementations, official), structural")
struct WelcomeTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("welcome", as: [WelcomeVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("key_package and welcome decode and re-encode byte-identically", arguments: records)
	func structural(_ record: WelcomeVector) throws {
		var keyPackageReader = MLS.Reader(record.keyPackage.bytes)
		let keyPackageMessage = try MLS.RFC9420.Message(from: &keyPackageReader)
		try keyPackageReader.finish()
		guard case .keyPackage = keyPackageMessage else {
			Issue.record("expected wire_format == mls_key_package")
			return
		}
		#expect(try keyPackageMessage.mlsEncoded() == record.keyPackage.bytes)

		var welcomeReader = MLS.Reader(record.welcome.bytes)
		let welcomeMessage = try MLS.RFC9420.Message(from: &welcomeReader)
		try welcomeReader.finish()
		guard case .welcome = welcomeMessage else {
			Issue.record("expected wire_format == mls_welcome")
			return
		}
		#expect(try welcomeMessage.mlsEncoded() == record.welcome.bytes)
	}
}
