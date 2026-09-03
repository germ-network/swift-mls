import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import SecretBytes
import Testing

@testable import MLSKeySchedule

/// Compares a derived `SecretBytes` to a vector's expected bytes with
/// `SecretBytes`'s own constant-time `==` (never unwrapping the secret to a
/// `Data` the test could then leak). `SecretBytes.description` is redacted, so
/// a bare `#expect` prints two identical `"SecretBytes(N bytes)"` strings on
/// failure; this reports the byte counts and a SHA-256 prefix of each side so a
/// mismatch is diagnosable without exposing the secrets themselves.
private func expectSecret(
	_ actual: SecretBytes, equals expected: some ContiguousBytes, _ label: String,
	sourceLocation: SourceLocation = #_sourceLocation
) throws {
	let expectedSecret = try SecretBytes(bytes: expected)
	func digest(_ s: SecretBytes) -> String {
		s.withUnsafeBytes { SHA256.hash(data: Data($0)) }
			.prefix(4).map { String(format: "%02x", $0) }.joined()
	}
	#expect(
		actual == expectedSecret,
		"\(label): actual \(actual.byteCount)B/\(digest(actual)) != expected \(expectedSecret.byteCount)B/\(digest(expectedSecret))",
		sourceLocation: sourceLocation)
}

@Suite("key-schedule.json (mlswg/mls-implementations)")
struct KeyScheduleTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("key-schedule", as: [KeyScheduleVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("advancing epoch to epoch matches every field the vector expects", arguments: records)
	func advancesCorrectly(_ record: KeyScheduleVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var initSecret = try SecretBytes(bytes: record.initialInitSecret.bytes)
		for epoch in record.epochs {
			let result = try MLS.KeySchedule.advance(
				provider,
				initSecret: initSecret,
				commitSecret: epoch.commitSecret.bytes,
				pskSecret: epoch.pskSecret.bytes,
				groupContext: epoch.groupContext.bytes
			)

			try expectSecret(
				result.joinerSecret, equals: epoch.joinerSecret.bytes,
				"joinerSecret")
			try expectSecret(
				result.welcomeSecret, equals: epoch.welcomeSecret.bytes,
				"welcomeSecret")
			try expectSecret(
				result.initSecret, equals: epoch.initSecret.bytes, "initSecret")
			try expectSecret(
				result.senderDataSecret, equals: epoch.senderDataSecret.bytes,
				"senderDataSecret")
			try expectSecret(
				result.encryptionSecret, equals: epoch.encryptionSecret.bytes,
				"encryptionSecret")
			try expectSecret(
				result.exporterSecret, equals: epoch.exporterSecret.bytes,
				"exporterSecret")
			// `epochAuthenticator` stays `Data` -- a public §8.6 authenticator.
			#expect(result.epochAuthenticator == epoch.epochAuthenticator.bytes)
			try expectSecret(
				result.externalSecret, equals: epoch.externalSecret.bytes,
				"externalSecret")
			#expect(result.externalPublicKey.data == epoch.externalPub.bytes)
			try expectSecret(
				result.confirmationKey, equals: epoch.confirmationKey.bytes,
				"confirmationKey")
			try expectSecret(
				result.membershipKey, equals: epoch.membershipKey.bytes,
				"membershipKey")
			try expectSecret(
				result.resumptionPsk, equals: epoch.resumptionPsk.bytes,
				"resumptionPsk")

			let exported = try MLS.KeySchedule.exportSecret(
				provider, exporterSecret: result.exporterSecret,
				label: epoch.exporter.label,
				context: epoch.exporter.context.bytes, length: epoch.exporter.length
			)
			#expect(exported == epoch.exporter.secret.bytes)

			initSecret = result.initSecret
		}
	}
}
