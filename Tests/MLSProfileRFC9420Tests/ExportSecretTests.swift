import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// `Group.exportSecret` — RFC 9420 §8.5's MLS-Exporter, a thin non-consuming
/// wrapper over `MLS.KeySchedule.exportSecret(exporterSecret:...)`. Distinct
/// from `safeExportSecret` (draft-ietf-mls-extensions §4.4): this one never
/// mutates the group and is repeatable at a given epoch.
@Suite("Group.exportSecret (RFC 9420 §8.5)")
struct ExportSecretTests {
	static let provider = SelfInteropTests.provider

	/// A solo group created from a *known* epoch secret, so an independent
	/// derivation can be compared against it.
	static func soloGroup(epochSecret: SecretBytes) throws -> MLS.RFC9420.Group {
		let founder = try SelfInteropTests.member("solo")
		return try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: founder.keyPackage.leafNode,
			leafSecretKey: founder.leafSecretKey, epochSecret: epochSecret)
	}

	/// `group.exportSecret` is declared on a `let` group below: a non-consuming,
	/// non-`mutating` method must be callable there, which is the compile-time
	/// proof this method neither mutates nor consumes group state.
	@Test("matches a direct call to the key-schedule export over the same exporter secret")
	func delegatesToKeySchedule() throws {
		let provider = Self.provider
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))

		let labels = ["rendezvous", "header key", ""]
		let contexts = [Data(), Data("ctx".utf8), Data(repeating: 0x42, count: 16)]
		let lengths = [16, 32, 48]

		for label in labels {
			for context in contexts {
				for length in lengths {
					#expect(
						try group.exportSecret(
							provider, label: label, context: context,
							length: length)
							== MLS.KeySchedule.exportSecret(
								provider,
								exporterSecret: group.epoch
									.exporterSecret,
								label: label, context: context,
								length: length))
				}
			}
		}
	}

	/// Anchors the group's retained exporter to the key schedule independent of
	/// reading `group.epoch`: derive `exporterSecret` from a known seed via the
	/// public component API, and confirm the group's export matches.
	@Test("matches an independent derivation from a known epoch secret")
	func matchesIndependentDerivationFromKnownSeed() throws {
		let provider = Self.provider
		let seed = try SecretBytes(bytes: Data(repeating: 0x5A, count: provider.hashSize))
		let group = try Self.soloGroup(epochSecret: seed)
		let independentExporter = try MLS.KeySchedule.fromEpochSecret(
			provider, epochSecret: seed
		).exporterSecret

		for (label, context, length) in [
			("rendezvous", Data("alpha".utf8), 32),
			("header key", Data(), 16),
		] {
			#expect(
				try group.exportSecret(
					provider, label: label, context: context, length: length)
					== MLS.KeySchedule.exportSecret(
						provider, exporterSecret: independentExporter,
						label: label, context: context, length: length))
		}
	}

	@Test("repeatable: identical inputs return equal bytes and never throw")
	func repeatableAndCorrectLength() throws {
		let provider = Self.provider
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))

		let first = try group.exportSecret(
			provider, label: "rendezvous", context: Data(), length: 32)
		let second = try group.exportSecret(
			provider, label: "rendezvous", context: Data(), length: 32)
		#expect(first == second)
		#expect(first.byteCount == 32)
	}

	@Test("differing label, context, or length change the output")
	func inputsMatter() throws {
		let provider = Self.provider
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))

		let base = try group.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)

		let differentLabel = try group.exportSecret(
			provider, label: "header key", context: Data("ctx".utf8), length: 32)
		#expect(differentLabel != base)

		let differentContext = try group.exportSecret(
			provider, label: "rendezvous", context: Data("other".utf8), length: 32)
		#expect(differentContext != base)

		// `length` is bound into RFC 9420's ExpandWithLabel KDFLabel, so a longer
		// export differs even on the shared-length prefix — not merely in byteCount.
		let differentLength = try group.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 48)
		#expect(differentLength.byteCount == 48)
		let basePrefix = base.withUnsafeBytes { Data($0) }
		let longerPrefix = differentLength.withUnsafeBytes {
			Data($0.prefix(base.byteCount))
		}
		#expect(longerPrefix != basePrefix)
	}

	/// Advancing the epoch re-keys `exporter_secret`, so the same inputs export
	/// different bytes at the next epoch.
	@Test("does not cross epochs")
	func doesNotCrossEpochs() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let atEpoch0 = try groupA.exportSecret(
			provider, label: "rendezvous", context: Data(), length: 32)

		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let atEpoch1 = try groupA.exportSecret(
			provider, label: "rendezvous", context: Data(), length: 32)

		#expect(atEpoch1 != atEpoch0)
	}

	/// RFC 5869 §2.3 caps HKDF-Expand's output length at `255*HashLen`; the
	/// bound is inclusive, so `length == maximum` still succeeds and exports
	/// exactly that many bytes.
	@Test("length == maximum succeeds and exports exactly maximum bytes")
	func maximumLengthSucceeds() throws {
		let provider = Self.provider
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let maximum = 255 * provider.hashSize

		let exported = try group.exportSecret(
			provider, label: "rendezvous", context: Data(), length: maximum)
		#expect(exported.byteCount == maximum)
	}

	/// `0`, a negative length, one past the maximum, and `Int.max` are all
	/// rejected by the same guard before ever reaching the HKDF backend, which
	/// traps rather than throws past `255*HashLen`.
	@Test("length outside 1...maximum throws exportLengthOutOfRange")
	func outOfRangeLengthThrows() throws {
		let provider = Self.provider
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		let maximum = 255 * provider.hashSize

		for length in [0, -1, maximum + 1, Int.max] {
			#expect(
				throws: MLS.RFC9420.GroupError.exportLengthOutOfRange(
					length: length, maximum: maximum)
			) {
				_ = try group.exportSecret(
					provider, label: "rendezvous", context: Data(),
					length: length)
			}
		}
	}
}
