import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSFraming
import SecretBytes
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// Byte-exact wire vectors and differential checks against the `apq` Rust reference's
/// deployed layout: the `APQInfo` extension body, the `AppDataUpdate` envelope (vs apq's
/// `AppDataUpdateWire`), the application storage id, and the §7 paired-structure codec.
/// The differential targets are the shared-wire values only — NOT the AppDataUpdate
/// *proposal-in-commit* framing, where the deployed mls-rs fork wraps a registered
/// proposal as a custom `opaque<V>` and swift-mls encodes it inline (a spec-vs-deployed
/// divergence recorded outside this module).
@Suite struct WireTests {
	typealias Support = CombinerTestSupport

	/// `APQInfo` body = `opaque t_gid<V> ‖ opaque pq_gid<V> ‖ mode(u8) ‖
	/// t_cs(u16) ‖ pq_cs(u16) ‖ t_epoch(u64) ‖ pq_epoch(u64)`, matching apq's
	/// `ApqInfo` field order (`component.rs`).
	@Test func apqInfoBodyBytes() throws {
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: Data([1, 2, 3]),
			pqSessionGroupID: Data([4, 5, 6, 7]),
			mode: 0,
			tCipherSuite: MLS.CipherSuite(id: 1),
			pqCipherSuite: MLS.CipherSuite(id: 2),
			tEpoch: 1,
			pqEpoch: 1)
		#expect(
			try info.mlsEncoded()
				== Data([
					0x03, 1, 2, 3,  // t_session_group_id<V>
					0x04, 4, 5, 6, 7,  // pq_session_group_id<V>
					0x00,  // mode
					0x00, 0x01,  // t_cipher_suite
					0x00, 0x02,  // pq_cipher_suite
					0, 0, 0, 0, 0, 0, 0, 1,  // t_epoch
					0, 0, 0, 0, 0, 0, 0, 1,  // pq_epoch
				]))
	}

	/// The `AppDataUpdate` envelope under the deployed `.uint32` width is byte-identical
	/// to apq's `AppDataUpdateWire { u32 component_id; u8 op; opaque update<V>; }` with an
	/// `ApqInfoUpdate { u64 t_epoch; u64 pq_epoch; }` payload:
	/// `00 00 FF 01 | 01 | 10 | <16-byte ApqInfoUpdate>`.
	@Test func appDataUpdateEnvelopeMatchesDeployedWire() throws {
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let update = MLS.Combiner.ApqInfoUpdate(tEpoch: 7, pqEpoch: 3)
			let envelope = try update.appDataUpdate(
				componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
			#expect(
				try envelope.mlsEncoded()
					== Data([
						0x00, 0x00, 0xFF, 0x01,  // component_id (u32 BE)
						0x01,  // op = update
						0x10,  // opaque update<V> length = 16
						0, 0, 0, 0, 0, 0, 0, 7,  // t_epoch
						0, 0, 0, 0, 0, 0, 0, 3,  // pq_epoch
					]))
		}
	}

	/// The application storage id is `0x03 ‖ component_id(u16) ‖ psk_id<V>`, width-pinned
	/// to `uint16` regardless of the wire width (a local key) — same recipe/shape as
	/// apq's `ApplicationPsk::storage_id`, but pinned to `uint16` locally (apq's uses
	/// u32; the storage id is a local key, never on the wire, so this does not affect
	/// interop).
	@Test func exportedPskStorageID() throws {
		let exported = try MLS.Combiner.ExportedPsk.fromParts(
			componentID: MLS.Extensions.ComponentID(rawValue: 0xFF01),
			pskID: Data([7, 8, 9]),
			psk: try SecretBytesFixture.make())
		#expect(exported.storageID == Data([0x03, 0xFF, 0x01, 0x03, 7, 8, 9]))

		// Same under the u32 wire width — the store key does not shift with the session.
		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let underU32 = try MLS.Combiner.ExportedPsk.fromParts(
				componentID: MLS.Extensions.ComponentID(rawValue: 0xFF01),
				pskID: Data([7, 8, 9]), psk: try SecretBytesFixture.make())
			#expect(underU32.storageID == Data([0x03, 0xFF, 0x01, 0x03, 7, 8, 9]))
		}
	}

	/// The §7 `APQKeyPackage { KeyPackage t; KeyPackage pq; }` codec is `encode(t) ‖
	/// encode(pq)` and round-trips.
	@Test func apqKeyPackageRoundTrips() throws {
		let a = try Support.member("alice")
		let b = try Support.member("bob")
		let pair = MLS.Combiner.APQKeyPackage(
			tKeyPackage: a.keyPackage, pqKeyPackage: b.keyPackage)
		var reader = MLS.Reader(try pair.mlsEncoded())
		let decoded = try MLS.Combiner.APQKeyPackage(from: &reader)
		try reader.finish()
		#expect(decoded == pair)
	}

	/// The §7 `APQWelcome { Welcome t; Welcome pq; }` codec round-trips a real
	/// establishment welcome.
	@Test func apqWelcomeRoundTrips() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (_, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: try Support.halfCreation(founder: alice, peer: bob),
			pq: try Support.halfCreation(founder: alice, peer: bob),
			mode: 0, classicalProvider: Support.provider, pqProvider: Support.provider)

		var reader = MLS.Reader(try welcome.mlsEncoded())
		let decoded = try MLS.Combiner.APQWelcome(from: &reader)
		try reader.finish()
		#expect(decoded == welcome)
	}

	/// §7's `APQPrivateMessage` validity rule: neither half may be `application`
	/// content. A pair of commit-typed messages passes; an application-typed half is
	/// rejected.
	@Test func apqPrivateMessageContentTypeRule() throws {
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, _) = try Support.establishedPair(founder: alice, peer: bob)

		// A commit-framed private message (content type `commit`) on each half.
		let commit = try commitMessage(founder.classical, signingKey: alice.signingKey)
		let commitPair = MLS.Combiner.APQPrivateMessage(tMessage: commit, pqMessage: commit)
		var reader = MLS.Reader(try commitPair.mlsEncoded())
		#expect(try MLS.Combiner.APQPrivateMessage(from: &reader) == commitPair)
		try reader.finish()
		try commitPair.validate()  // commit content — allowed

		// An application-framed private message is rejected by the §7 rule.
		let application = try applicationMessage(
			founder.classical, signingKey: alice.signingKey)
		let badPair = MLS.Combiner.APQPrivateMessage(
			tMessage: application, pqMessage: commit)
		#expect(throws: MLS.Combiner.Error.commitShapeMismatch) { try badPair.validate() }
	}

	// MARK: helpers

	private func commitMessage(
		_ group: MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey
	) throws -> MLS.RFC9420.PrivateMessage {
		let transition = try group.committing(
			Support.provider, proposals: [], signingKey: signingKey,
			randomness: .generate(Support.provider))
		let sent = transition.takeOutput()
		guard case .privateMessage(let privateMessage) = sent.message else {
			throw MLS.Combiner.Error.commitShapeMismatch
		}
		return privateMessage
	}

	private func applicationMessage(
		_ group: MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey
	) throws -> MLS.RFC9420.PrivateMessage {
		var group = group
		return try group.protectContent(
			membershipIndex: 0, Support.provider,
			content: .application(Data("hi".utf8)),
			authenticatedData: Data(), signingKey: signingKey,
			reuseGuard: MLS.Framing.ReuseGuard(Support.provider.randomBytes(4)),
			paddingLength: 0
		).message
	}
}

/// A small non-zero `SecretBytes` for descriptor tests where the value is irrelevant.
enum SecretBytesFixture {
	static func make() throws -> SecretBytes { try SecretBytes(bytes: Data([1, 2, 3, 4])) }
}
