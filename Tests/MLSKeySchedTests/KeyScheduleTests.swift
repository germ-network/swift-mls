import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSKeySchedule

@Suite("key-schedule.json (mlswg/mls-implementations)")
struct KeyScheduleTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("key-schedule", as: [KeyScheduleVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("advancing epoch to epoch matches every field the vector expects", arguments: records)
	func advancesCorrectly(_ record: KeyScheduleVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var initSecret = record.initialInitSecret.bytes
		for epoch in record.epochs {
			let result = try MLS.KeySchedule.advance(
				provider,
				initSecret: initSecret,
				commitSecret: epoch.commitSecret.bytes,
				pskSecret: epoch.pskSecret.bytes,
				groupContext: epoch.groupContext.bytes
			)

			#expect(result.joinerSecret == epoch.joinerSecret.bytes)
			#expect(result.welcomeSecret == epoch.welcomeSecret.bytes)
			#expect(result.initSecret == epoch.initSecret.bytes)
			#expect(result.senderDataSecret == epoch.senderDataSecret.bytes)
			#expect(result.encryptionSecret == epoch.encryptionSecret.bytes)
			#expect(result.exporterSecret == epoch.exporterSecret.bytes)
			#expect(result.epochAuthenticator == epoch.epochAuthenticator.bytes)
			#expect(result.externalSecret == epoch.externalSecret.bytes)
			#expect(result.externalPublicKey.data == epoch.externalPub.bytes)
			#expect(result.confirmationKey == epoch.confirmationKey.bytes)
			#expect(result.membershipKey == epoch.membershipKey.bytes)
			#expect(result.resumptionPsk == epoch.resumptionPsk.bytes)

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
