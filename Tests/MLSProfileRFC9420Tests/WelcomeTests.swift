import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `key_package`/`welcome` structural round-trip, plus (GER-2296) the full
/// join-flow crypto chain this vector was originally deferred for: HPKE-
/// decrypt `GroupSecrets` with `init_priv`, AEAD-decrypt the embedded
/// `GroupInfo`, verify its signature with `signer_pub`, derive the epoch
/// from `joiner_secret`, recompute `confirmation_tag`. No tree in this
/// vector at all (`ratchet_tree`/`epochs` aren't fields here) — that half
/// is `passive-client-welcome.json`'s job.
@Suite("welcome.json (mlswg/mls-implementations, official)")
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

	@Test(
		"full join-flow crypto chain: decrypt GroupSecrets, decrypt GroupInfo, verify signature, recompute confirmation_tag",
		arguments: records
	)
	func fullVerification(_ record: WelcomeVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var keyPackageReader = MLS.Reader(record.keyPackage.bytes)
		guard
			case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(
				from: &keyPackageReader)
		else {
			Issue.record("expected wire_format == mls_key_package")
			return
		}
		try keyPackageReader.finish()

		var welcomeReader = MLS.Reader(record.welcome.bytes)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(from: &welcomeReader)
		else {
			Issue.record("expected wire_format == mls_welcome")
			return
		}
		try welcomeReader.finish()

		let keyPackageRef = try keyPackage.reference(provider)
		let groupSecrets = try welcome.decryptGroupSecrets(
			provider, keyPackageRef: keyPackageRef,
			initKey: MLS.HpkeSecretKey(record.initPriv.bytes))

		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: [])
		let (groupInfo, epoch) = try welcome.decryptGroupInfo(
			provider, joinerSecret: groupSecrets.joinerSecret, pskSecret: pskSecret)

		try groupInfo.verifySignature(
			provider, signatureKey: MLS.SignaturePublicKey(record.signerPub.bytes))

		let expectedTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: epoch.confirmationKey,
			confirmedTranscriptHash: groupInfo.groupContext.confirmedTranscriptHash)
		#expect(expectedTag == groupInfo.confirmationTag)
	}
}
