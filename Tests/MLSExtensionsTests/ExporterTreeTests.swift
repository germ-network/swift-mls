import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSKeySchedule
import SecretBytes
import Testing

/// draft-ietf-mls-extensions-08 §4.4 (Exported Secrets) — the Exporter Tree and
/// `SafeExportSecret`, the mechanism the deployed TwoMLSPQ APQ combiner derives
/// its binding PSKs through. Wire-compatibility is load-bearing, so the two
/// known-answer tests below are lifted verbatim from the deployed fork
/// (`germ-network/mls-rs@b43703f`, `group/exporter_tree.rs` and
/// `group/key_schedule.rs`) — no official mlswg vectors exist for this yet.
@Suite("Exporter Tree / SafeExportSecret (draft-ietf-mls-extensions-08 §4.4)")
struct ExporterTreeTests {
	static let provider = SwiftCryptoProvider()

	static func suite1() throws -> any MLS.CipherSuiteProvider {
		try #require(provider.cipherSuiteProvider(for: .curve25519Aes128))
	}

	static func bytes(_ s: SecretBytes) -> Data { s.withUnsafeBytes { Data($0) } }

	/// Fork KAT (`exporter_tree.rs::safe_export_secret_known_answer`): on cipher
	/// suite 1 with the root fixed to `[42; 32]`, `SafeExportSecret(0x8000)` is a
	/// frozen value. Proves the tree walk is bit-identical to the deployed
	/// implementation.
	@Test("SafeExportSecret matches the deployed fork's known-answer vector")
	func exporterTreeKnownAnswer() throws {
		let cs = try Self.suite1()
		var tree = try MLS.Extensions.ExporterTree(
			applicationExportSecret: Data(repeating: 42, count: 32))
		let secret = try tree.safeExportSecret(cs, componentID: 0x8000)
		#expect(
			Self.bytes(secret).map { String(format: "%02x", $0) }.joined()
				== "ea8c3bd72ab7adcf2cc5a6aebe06ea77ef48001a695ec15eaf6a801f8573d853"
		)
	}

	/// Fork KAT (`key_schedule.rs::application_export_secret_known_answer`): the
	/// full path from a fixed `epoch_secret` through the `"application_export"`
	/// root label to `SafeExportSecret(0)`. Member-agreement tests cannot catch a
	/// wrong root label (all members would agree on the same wrong value), so
	/// this freezes it end to end.
	@Test("the application_export root label is correct end to end")
	func applicationExportRootKnownAnswer() throws {
		let cs = try Self.suite1()
		let fanOut = try MLS.KeySchedule.fromEpochSecret(
			cs, epochSecret: Data(repeating: 42, count: 32))
		var tree = try MLS.Extensions.ExporterTree(
			applicationExportSecret: fanOut.applicationExportSecret)
		let secret = try tree.safeExportSecret(cs, componentID: 0)
		#expect(
			Self.bytes(secret).map { String(format: "%02x", $0) }.joined()
				== "e3f6a68ab2fc8e48033a5c3588a5f31f77de464674a0636a935a74064a9ac170"
		)
	}

	/// The descent to component 0 is sixteen `ExpandWithLabel(., "tree", "left",
	/// Nh)` from the root — the leftmost leaf of a 2^16-leaf tree.
	@Test("component 0 is sixteen left expansions from the root")
	func componentZeroIsSixteenLeftExpansions() throws {
		let cs = try Self.suite1()
		let root = Data(repeating: 42, count: 32)
		var expected = try SecretBytes(bytes: root)
		for _ in 0..<16 {
			expected = try MLS.expandWithLabelSecret(
				cs, secret: expected, label: "tree", context: Data("left".utf8),
				length: cs.hashSize)
		}
		var tree = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		let derived = try tree.safeExportSecret(cs, componentID: 0)
		#expect(derived == expected)
	}

	/// A component's secret is consumed on export: re-exporting it this epoch is
	/// a replay signal, not a fresh derivation.
	@Test("exporting the same component twice fails as consumed")
	func exportConsumesTheComponent() throws {
		let cs = try Self.suite1()
		var tree = try MLS.Extensions.ExporterTree(
			applicationExportSecret: cs.randomBytes(cs.hashSize))
		_ = try tree.safeExportSecret(cs, componentID: 3)
		#expect(throws: MLS.Extensions.ExporterTree.ExportError.componentSecretConsumed(3))
		{
			try tree.safeExportSecret(cs, componentID: 3)
		}
	}

	/// Consuming one component leaves every other independently exportable and
	/// unchanged — the deletion schedule caches copath siblings rather than
	/// stranding subtrees.
	@Test("other components survive a component's consumption, unchanged")
	func siblingSurvivesConsumption() throws {
		let cs = try Self.suite1()
		let root = cs.randomBytes(cs.hashSize)

		var reference = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		let expected = try reference.safeExportSecret(cs, componentID: 0x8000)

		var tree = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		// Sibling leaf, far leaf, a leaf sharing most of the path, then the target.
		for id: UInt32 in [0x8001, 0x0000, 0xFFFF, 0x8002] {
			_ = try tree.safeExportSecret(cs, componentID: .init(UInt16(id)))
		}
		let after = try tree.safeExportSecret(cs, componentID: 0x8000)
		#expect(after == expected)
	}

	/// Export is deterministic (a fixed function of the root and component) and
	/// domain-separated across components; every secret is `KDF.Nh` long.
	@Test("export is deterministic, domain-separated, and Nh long")
	func exportDeterministicAndDomainSeparated() throws {
		let cs = try Self.suite1()
		let root = cs.randomBytes(cs.hashSize)

		var t1 = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		var t2 = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		let a = try t1.safeExportSecret(cs, componentID: 0x8000)
		let b = try t2.safeExportSecret(cs, componentID: 0x8000)
		let c = try t1.safeExportSecret(cs, componentID: 0x8001)

		#expect(a == b)
		#expect(a != c)
		#expect(a.byteCount == cs.hashSize)
	}

	/// The consuming walk cross-checked against the stateless `leafSecret` oracle
	/// (which re-derives from the root every time — the vector-pinned reference
	/// `SecretTree` documents itself as) across a spread of bit patterns: the
	/// all-left `0`, all-right `0xFFFF`, and mixed ids. Only `0`/`0x8000` are
	/// pinned to a hex KAT; every other id in the suite is otherwise compared
	/// only against itself, so a walk error on an un-exercised bit pattern would
	/// pass silently. Consuming all ids in one tree also exercises order-
	/// independent sibling survival with exact bytes.
	@Test("SafeExportSecret matches the stateless leafSecret oracle across bit patterns")
	func matchesStatelessOracleAcrossComponents() throws {
		let cs = try Self.suite1()
		let root = cs.randomBytes(cs.hashSize)
		var tree = try MLS.Extensions.ExporterTree(applicationExportSecret: root)
		for id: UInt32 in [
			0, 1, 2, 3, 0x00FF, 0x0100, 0x5555, 0xAAAA, 0xBEEF, 0x7FFF, 0x8000,
			0x8001, 0xC000, 0xFFFE, 0xFFFF,
		] {
			let consumed = try tree.safeExportSecret(cs, componentID: .init(UInt16(id)))
			let oracle = try MLS.KeySchedule.leafSecret(
				cs, encryptionSecret: root, leafIndex: id,
				numLeaves: MLS.Extensions.ExporterTree.leafCount)
			#expect(Self.bytes(consumed) == oracle, "component \(id)")
		}
	}

	/// `ComponentID` is a `UInt16` identifier: integer-literal ergonomics, a
	/// `rawValue`, and value equality. The exporter API takes this, not a raw int.
	@Test("ComponentID wraps a UInt16 with literal and rawValue access")
	func componentIDContract() {
		let id: MLS.Extensions.ComponentID = 0xFF01
		#expect(id.rawValue == 0xFF01)
		#expect(id == MLS.Extensions.ComponentID(0xFF01))
		#expect(id == MLS.Extensions.ComponentID(rawValue: 0xFF01))
		#expect(id != 0xFF02)
		#expect(MLS.Extensions.ComponentID(rawValue: .max).rawValue == UInt16.max)
	}
}
