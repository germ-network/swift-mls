import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import Testing

@testable import MLSProfileRFC9420

// No official or mls-rs vector exercises a resumption PSK (finding 1.7 in
// the GER-2294 plan) -- self-verified here instead. This is exactly the
// class this component's own doc comment says it stopped hardcoding
// (Sources/MLSKeySchedule/Labels.swift): a real regression test, not
// vector coverage, is what stands between "compiles" and "actually
// distinguishes the two PSK kinds during derivation."
@Suite("resumption PSKs (no vector; self-verified)")
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
			Self.provider, psks: [(encodedID: try encoded(id), psk: psk)])
		let b = try MLS.KeySchedule.pskSecret(
			Self.provider, psks: [(encodedID: try encoded(id), psk: psk)])
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
			Self.provider, psks: [(encodedID: try encoded(resumption), psk: psk)])
		let externalSecret = try MLS.KeySchedule.pskSecret(
			Self.provider, psks: [(encodedID: try encoded(external), psk: psk)])

		#expect(resumptionSecret != externalSecret)
	}
}
