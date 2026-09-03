import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

// The official vectors exercise resumption PSKs only shallowly: every
// reference in `passive-client-handling-commit.json` is application-usage
// at gap 1 (the immediately preceding epoch), and
// `passive-client-random.json` carries no PSKs at all -- measured during
// the phase-5 retention work, correcting this header's earlier claim that
// no vector exercises them. What still needs self-verification is the
// class this component's own doc comment says it stopped hardcoding
// (Sources/MLSKeySchedule/Labels.swift): that derivation actually
// distinguishes the two PSK kinds, which a gap-1 happy path never probes.
@Suite("resumption PSKs (vector coverage shallow; self-verified)")
struct ResumptionPskTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	private func encoded(_ id: MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data {
		var writer = MLS.Writer()
		try id.encode(to: &writer)
		return writer.data
	}

	@Test("a resumption PSK computes a deterministic secret of the right length")
	func deterministic() throws {
		let id = MLS.RFC9420.PreSharedKeyIdentifier.resumption(
			.init(usage: .application, groupID: Data("group".utf8), epoch: 3),
			nonce: Data(repeating: 7, count: 16))
		let psk = Data(repeating: 0xAB, count: 32)

		let a = try MLS.KeySchedule.pskSecret(
			Self.provider,
			psks: [(encodedID: try encoded(id), psk: SecretBytes(bytes: psk))])
		let b = try MLS.KeySchedule.pskSecret(
			Self.provider,
			psks: [(encodedID: try encoded(id), psk: SecretBytes(bytes: psk))])
		#expect(a == b)
		#expect(a.count == Self.provider.hashSize)
	}

	@Test("resumption and external PSKs with the same nonce/psk bytes derive different secrets")
	func distinguishesFromExternal() throws {
		let nonce = Data(repeating: 7, count: 16)
		let psk = Data(repeating: 0xAB, count: 32)

		let resumption = MLS.RFC9420.PreSharedKeyIdentifier.resumption(
			.init(usage: .application, groupID: Data("group".utf8), epoch: 3),
			nonce: nonce)
		// An external PSK whose id happens to equal the resumption PSK's
		// encoded body (usage ‖ group_id ‖ epoch) -- the strongest version
		// of this test, since it isn't merely "different bytes in, different
		// bytes out": it proves the psktype tag itself, not just the payload,
		// participates in the derivation.
		var groupIDWriter = MLS.Writer()
		try MLS.RFC9420.ResumptionPSKUsage.application.encode(to: &groupIDWriter)
		try groupIDWriter.writeOpaque(Data("group".utf8))
		groupIDWriter.writeUInt64(3)
		let external = MLS.RFC9420.PreSharedKeyIdentifier.external(
			pskID: groupIDWriter.data, nonce: nonce)

		let resumptionSecret = try MLS.KeySchedule.pskSecret(
			Self.provider,
			psks: [(encodedID: try encoded(resumption), psk: SecretBytes(bytes: psk))])
		let externalSecret = try MLS.KeySchedule.pskSecret(
			Self.provider,
			psks: [(encodedID: try encoded(external), psk: SecretBytes(bytes: psk))])

		#expect(resumptionSecret != externalSecret)
	}
}
