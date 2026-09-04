import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// `Group.safeExportSecret` — the profile wiring over the #46 Exporter Tree
/// mechanism (draft-ietf-mls-extensions-08 §4.4). The group holds the
/// *consuming* tree, never the `application_export_secret` root, so a consumed
/// component cannot be re-derived (RFC 9420 §9.2 forward secrecy) — live or
/// across an archive. The independent oracle re-derives from a known
/// `epoch_secret` via the public component API, since the group keeps no seed.
@Suite("Group.safeExportSecret (mls-extensions §4.4 wiring)")
struct SafeExportTests {
	static let provider = SelfInteropTests.provider

	/// A solo group created from a *known* epoch secret, so an independent
	/// derivation can be compared against it.
	static func soloGroup(epochSecret: Data) throws -> MLS.RFC9420.Group {
		let founder = try SelfInteropTests.member("solo")
		return try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: founder.keyPackage.leafNode,
			leafSecretKey: founder.leafSecretKey, epochSecret: epochSecret)
	}

	/// The independent oracle: derive the exporter root from `epochSecret` via
	/// the public `fromEpochSecret`, build a fresh tree, export the component.
	static func independentExport(epochSecret: Data, _ componentID: UInt32) throws
		-> SecretBytes
	{
		let fanOut = try MLS.KeySchedule.fromEpochSecret(provider, epochSecret: epochSecret)
		var tree = try MLS.KeySchedule.ExporterTree(
			applicationExportSecret: fanOut.applicationExportSecret)
		return try tree.safeExportSecret(provider, componentID: componentID)
	}

	@Test("a group's export matches an independent derivation from the same epoch secret")
	func groupExportMatchesIndependentDerivation() throws {
		let provider = Self.provider
		let seed = Data(repeating: 0x5A, count: provider.hashSize)
		var group = try Self.soloGroup(epochSecret: seed)
		for id: UInt32 in [0, 1, 0x00FF, 0x5555, 0xAAAA, 0xBEEF, 0x8000, 0xFFFF] {
			#expect(
				try group.safeExportSecret(provider, componentID: id)
					== Self.independentExport(epochSecret: seed, id))
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

	/// The exporter tree is built at install and reset to the current epoch on
	/// every advance, so a past epoch's tree — which would be the only surviving
	/// copy of that epoch's not-yet-exported component material — never lingers.
	@Test("the exporter tree is reset to the current epoch on advance")
	func exporterTreeResetOnAdvance() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		#expect(groupA.exporterTrees[0] != nil)  // built at create's install
		_ = try groupA.safeExportSecret(provider, componentID: 3)

		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		#expect(groupA.exporterTrees[0] == nil)  // prior epoch dropped
		#expect(groupA.exporterTrees[1] != nil)  // current epoch built
		#expect(groupA.exporterTrees.count == 1)
	}

	/// A restored group exports exactly what an independent derivation from the
	/// same epoch secret would — restore rebuilds the tree from its persisted
	/// frontier, functionally intact, with no wiring drift.
	@Test("a restored group exports the same as an independent derivation")
	func restoredExportMatchesIndependentDerivation() throws {
		let provider = Self.provider
		let seed = Data(repeating: 0x2B, count: provider.hashSize)
		let group = try Self.soloGroup(epochSecret: seed)
		var restored = try MLS.RFC9420.Group.restore(from: try group.archive(), provider)
		#expect(
			try restored.safeExportSecret(provider, componentID: 0x1234)
				== Self.independentExport(epochSecret: seed, 0x1234))
	}

	/// Forward secrecy across the archive boundary: a component consumed before
	/// archiving cannot be re-derived after restore. The snapshot persists the
	/// tree's surviving frontier — the consumed component's path (and the root)
	/// are gone — so restore cannot re-derive it, while an unconsumed component
	/// still exports. Retaining the root would break both halves.
	@Test("a consumed component stays consumed across archive/restore")
	func consumedComponentStaysConsumedAcrossRestore() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Consume 0xFF01, then archive + restore.
		_ = try groupB.safeExportSecret(provider, componentID: 0xFF01)
		var restored = try MLS.RFC9420.Group.restore(from: try groupB.archive(), provider)

		// FS: the consumed component is unrecoverable after restore.
		#expect(
			throws: MLS.KeySchedule.ExporterTree.ExportError.componentSecretConsumed(
				0xFF01)
		) {
			try restored.safeExportSecret(provider, componentID: 0xFF01)
		}
		// An unconsumed component still exports, and matches the pre-archive tree.
		let restoredFF02 = try restored.safeExportSecret(provider, componentID: 0xFF02)
		#expect(restoredFF02.byteCount == provider.hashSize)
		#expect(try groupB.safeExportSecret(provider, componentID: 0xFF02) == restoredFF02)
	}

	/// A migration source that predates the exporter tree (e.g. the deployed
	/// `export_for_swift()`) persists no `exporter_tree`. Such a snapshot still
	/// restores, but the group has no tree, so `safeExportSecret` reports it
	/// unavailable until the group advances an epoch and installs one.
	@Test("a snapshot without an exporter tree restores; export is unavailable")
	func restoreWithoutExporterTree() throws {
		let provider = Self.provider
		var snapshot = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
			.makeSnapshot()
		snapshot.exporterTree = nil
		var restored = try MLS.RFC9420.Group.restore(from: snapshot, provider)
		#expect(throws: MLS.RFC9420.GroupError.exporterTreeUnavailable) {
			try restored.safeExportSecret(provider, componentID: 0xFF01)
		}
	}
}
