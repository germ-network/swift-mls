import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `passive-client-welcome.json`: the full `Group.join` path, both
/// tree-delivery modes (external `ratchet_tree` field vs. the `GroupInfo`
/// extension) and both PSK modes (0 or 1 external PSKs), all with zero
/// `epochs` -- this vector is join-only, `passive-client-handling-commit
/// .json`/`passive-client-random.json` cover commit application.
@Suite("passive-client-welcome.json (mlswg/mls-implementations, official)")
struct PassiveClientJoinTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"passive-client-welcome", as: [PassiveClientVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	private static func decodeExternalTree(_ record: PassiveClientVector) throws
		-> [MLS.RFC9420.Node?]?
	{
		guard let ratchetTree = record.ratchetTree else { return nil }
		var reader = MLS.Reader(ratchetTree.bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return nodes
	}

	@Test(
		"join recovers the vector's own initial_epoch_authenticator", arguments: records)
	func joinMatchesInitialEpochAuthenticator(_ record: PassiveClientVector) throws {
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

		let externalPsks = Dictionary(
			uniqueKeysWithValues: record.externalPsks.map {
				($0.pskID.bytes, $0.psk.bytes)
			})

		let credentials = MLS.RFC9420.Group.JoinerCredentials(
			keyPackage: keyPackage,
			initKey: MLS.HpkeSecretKey(record.initPriv.bytes),
			encryptionKey: MLS.HpkeSecretKey(record.encryptionPriv.bytes))

		let group = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: credentials,
			externalTree: try Self.decodeExternalTree(record),
			psk: { id in
				guard case .external(let pskID, _) = id else { return nil }
				return externalPsks[pskID]
			})

		#expect(group.epoch.epochAuthenticator == record.initialEpochAuthenticator.bytes)
	}
}
