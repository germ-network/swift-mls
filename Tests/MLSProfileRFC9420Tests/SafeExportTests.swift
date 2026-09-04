import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// `Group.safeExportSecret` — the profile wiring over the #46 Exporter Tree
/// mechanism (draft-ietf-mls-extensions-08 §4.4). Each test bridges the group
/// API back to a fresh `ExporterTree` built from the group's own retained
/// `application_export_secret`, so a wiring error (wrong seed, stale epoch,
/// lost consumption) is caught against an independent derivation.
@Suite("Group.safeExportSecret (mls-extensions §4.4 wiring)")
struct SafeExportTests {
	static let provider = SelfInteropTests.provider

	/// The independent oracle: a fresh tree from the group's retained seed.
	static func oracle(_ group: MLS.RFC9420.Group, _ componentID: UInt32) throws
		-> SecretBytes
	{
		var tree = try MLS.KeySchedule.ExporterTree(
			applicationExportSecret: group.epoch.applicationExportSecret)
		return try tree.safeExportSecret(provider, componentID: componentID)
	}

	@Test("a group's export equals a fresh tree built from its retained seed")
	func groupExportMatchesSeedOracle() throws {
		let provider = Self.provider
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		for id: UInt32 in [0, 1, 0x00FF, 0x5555, 0xAAAA, 0xBEEF, 0x8000, 0xFFFF] {
			let expected = try Self.oracle(group, id)
			#expect(try group.safeExportSecret(provider, componentID: id) == expected)
		}
	}

	@Test("exporting the same component twice in one epoch throws")
	func groupExportConsumesOnce() throws {
		let provider = Self.provider
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		_ = try group.safeExportSecret(provider, componentID: 7)
		#expect(
			throws: MLS.KeySchedule.ExporterTree.ExportError.componentSecretConsumed(7)
		) {
			try group.safeExportSecret(provider, componentID: 7)
		}
	}

	@Test("an out-of-range component id is rejected at the group level")
	func groupExportRejectsOutOfRange() throws {
		let provider = Self.provider
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		#expect(
			throws: MLS.KeySchedule.ExporterTree.ExportError.invalidComponentID(1 << 16)
		) {
			try group.safeExportSecret(provider, componentID: 1 << 16)
		}
	}

	/// create → commit-construct + join → process: every path that installs an
	/// epoch exposes a fresh exporter, committer and joiner agree on it, and each
	/// epoch's tree is distinct from the last.
	@Test("every epoch path exposes a fresh exporter; committer and joiner agree")
	func exportAcrossEpochPaths() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		// create (epoch 0)
		var groupA = try SelfInteropTests.createGroup(alice)
		let e0 = try groupA.safeExportSecret(provider, componentID: 1)

		// commit-construct + join (epoch 1)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })
		let e1a = try groupA.safeExportSecret(provider, componentID: 1)
		let e1b = try groupB.safeExportSecret(provider, componentID: 1)
		#expect(e1a == e1b)
		#expect(e1a != e0)

		// process (epoch 2)
		let pcs = try groupB.committing(
			provider, proposals: [], signingKey: bob.signingKey,
			randomness: .generate(provider))
		groupB = pcs.group
		try SelfInteropTests.processPrivate(&groupA, provider, pcs.commit)
		let e2a = try groupA.safeExportSecret(provider, componentID: 1)
		let e2b = try groupB.safeExportSecret(provider, componentID: 1)
		#expect(e2a == e2b)
		#expect(e2a != e1a)
	}

	/// A prior epoch's exporter tree is scrubbed on advance: its seed is dropped
	/// with the old `EpochSecrets`, so a lingering cached tree would be the only
	/// surviving copy of that epoch's not-yet-exported component material.
	@Test("a prior epoch's exporter tree is pruned on epoch advance")
	func staleExporterTreePrunedOnAdvance() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		_ = try groupA.safeExportSecret(provider, componentID: 3)
		#expect(groupA.exporterTrees.keys.contains(0))

		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		#expect(groupA.exporterTrees[0] == nil)
		#expect(groupA.exporterTrees.isEmpty)
	}

	/// The retained seed round-trips through archive/restore, so a restored group
	/// exports the same bytes a fresh tree from the pre-archive seed would.
	@Test("export survives an archive/restore round-trip")
	func exportSurvivesRestore() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		let expected = try Self.oracle(groupB, 9)
		var restored = try MLS.RFC9420.Group.restore(from: try groupB.archive(), provider)
		#expect(try restored.safeExportSecret(provider, componentID: 9) == expected)
	}
}
