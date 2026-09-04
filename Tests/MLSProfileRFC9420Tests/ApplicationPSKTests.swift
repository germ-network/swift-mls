import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// draft-ietf-mls-extensions §4.5 application PSKs and draft-ietf-mls-combiner-02
/// §6.2's derivation over the Exporter Tree — the mechanism the deployed TwoMLSPQ
/// APQ combiner binds its groups with. swift-mls emits the -09 `uint16`
/// `component_id` by default; the `.uint32` `componentIDWireWidth` reproduces the
/// deployed fork's layout (`germ-network/mls-rs@b43703f`, `psk.rs`).
@Suite("Application PSKs (mls-extensions §4.5 / combiner §6.2)")
struct ApplicationPSKTests {
	static let provider = SelfInteropTests.provider

	static func bytes(_ s: SecretBytes) -> Data { s.withUnsafeBytes { Data($0) } }

	/// Default (draft-09) wire: `PSKType(3) ‖ component_id(u16 BE) ‖ psk_id<V> ‖
	/// psk_nonce<V>`, storage id dropping the nonce. Component `0xFF01`, psk_id
	/// `[7,8,9]`, nonce `[AA,BB]`.
	@Test("an application PreSharedKeyID encodes and round-trips at the default u16 width")
	func applicationPreSharedKeyIDWireDefault() throws {
		let id = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: 0xFF01, pskID: Data([7, 8, 9]), nonce: Data([0xAA, 0xBB]))

		#expect(
			try id.mlsEncoded() == Data([3, 0xFF, 0x01, 3, 7, 8, 9, 2, 0xAA, 0xBB]))
		#expect(try id.applicationStorageID() == Data([3, 0xFF, 0x01, 3, 7, 8, 9]))

		var reader = MLS.Reader(try id.mlsEncoded())
		#expect(try MLS.RFC9420.PreSharedKeyIdentifier(from: &reader) == id)
		try reader.finish()
	}

	/// Under the `.uint32` compat width (deployed fork / draft-08), the same
	/// `component_id` widens to four big-endian bytes — encode and decode must run
	/// under the same ambient width. The fork's own published vector uses a
	/// `u32`-range component (`0x01020304`) that -09's `uint16` can't hold, so this
	/// pins the u32 *encoding* of a valid component instead.
	@Test("the uint32 compat width widens component_id to four bytes, both directions")
	func applicationPreSharedKeyIDWireUInt32() throws {
		try MLS.RFC9420.PreSharedKeyIdentifier.$componentIDWireWidth.withValue(.uint32) {
			let id = MLS.RFC9420.PreSharedKeyIdentifier.application(
				componentID: 0xFF01, pskID: Data([7, 8, 9]),
				nonce: Data([0xAA, 0xBB]))
			#expect(
				try id.mlsEncoded()
					== Data([
						3, 0x00, 0x00, 0xFF, 0x01, 3, 7, 8, 9, 2, 0xAA,
						0xBB,
					]))
			// The storage id is a *local* key, pinned to the canonical u16 even
			// under the u32 wire width — so it doesn't shift with the session.
			#expect(
				try id.applicationStorageID()
					== Data([3, 0xFF, 0x01, 3, 7, 8, 9]))

			var reader = MLS.Reader(try id.mlsEncoded())
			#expect(try MLS.RFC9420.PreSharedKeyIdentifier(from: &reader) == id)
			try reader.finish()
		}
	}

	/// `applicationStorageID` is a local lookup key that never crosses the wire, so
	/// it must be width-independent: a PSK derived and stored outside a `.uint32`
	/// scope has to resolve against a fork commit processed *inside* one. Both
	/// widths yield the same canonical (u16) key.
	@Test("applicationStorageID is stable across the wire width")
	func storageIDWidthIndependent() throws {
		let id = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: 0xFF01, pskID: Data([7, 8, 9]), nonce: Data([0xAA, 0xBB]))
		let canonical = Data([3, 0xFF, 0x01, 3, 7, 8, 9])

		#expect(try id.applicationStorageID() == canonical)
		let underU32 = try MLS.RFC9420.PreSharedKeyIdentifier.$componentIDWireWidth
			.withValue(.uint32) { try id.applicationStorageID() }
		#expect(underU32 == canonical)
	}

	/// A `uint32`-form component_id ≥ 2^16 has no leaf and cannot fit -09's
	/// `uint16`, so decode rejects it rather than truncating.
	@Test("a uint32 component_id at or above 2^16 is rejected on decode")
	func applicationPreSharedKeyIDUInt32Overflow() throws {
		try MLS.RFC9420.PreSharedKeyIdentifier.$componentIDWireWidth.withValue(.uint32) {
			// PSKType 3, component_id 0x00010000 (= 2^16), psk_id [], nonce [].
			var reader = MLS.Reader(Data([3, 0x00, 0x01, 0x00, 0x00, 0, 0]))
			#expect(
				throws: MLS.RFC9420.WireError.componentIDOverflowsUInt16(
					0x0001_0000)
			) {
				try MLS.RFC9420.PreSharedKeyIdentifier(from: &reader)
			}
		}
	}

	@Test("applicationStorageID is nil for non-application ids")
	func storageIDNilForOthers() throws {
		#expect(
			try MLS.RFC9420.PreSharedKeyIdentifier.external(
				pskID: Data([1]), nonce: Data([2])
			).applicationStorageID() == nil)
	}

	/// `deriveApplicationPSK` derives `(psk_id, psk)` with the combiner §6.2 labels
	/// `"psk_id"`/`"psk"` off the component's exported secret. Checked against an
	/// independent derivation from a known epoch secret — a wrong label in the
	/// helper diverges here.
	@Test("deriveApplicationPSK uses the psk_id/psk labels over the exported secret")
	func deriveApplicationPSKLabels() throws {
		let provider = Self.provider
		let seed = Data(repeating: 0x11, count: provider.hashSize)
		var group = try SafeExportTests.soloGroup(epochSecret: seed)
		let (pskID, psk) = try group.deriveApplicationPSK(provider, componentID: 0x8000)

		// Independent exporter secret for the same component + epoch.
		let fanOut = try MLS.KeySchedule.fromEpochSecret(provider, epochSecret: seed)
		var tree = try MLS.KeySchedule.ExporterTree(
			applicationExportSecret: fanOut.applicationExportSecret)
		let exporter = try tree.safeExportSecret(provider, componentID: 0x8000)

		#expect(
			pskID == (try MLS.deriveSecret(provider, secret: exporter, label: "psk_id"))
		)
		#expect(
			Self.bytes(psk)
				== Self.bytes(
					try MLS.deriveSecretSecret(
						provider, secret: exporter, label: "psk")))
		// psk_id is public and distinct from the secret psk.
		#expect(pskID != Self.bytes(psk))
	}

	/// The exporter leaf is consumed, so a component's PSK derives at most once per
	/// epoch — a second derivation is a replay signal.
	@Test("deriveApplicationPSK for the same component twice throws")
	func deriveApplicationPSKConsumesOnce() throws {
		let provider = Self.provider
		var group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		_ = try group.deriveApplicationPSK(provider, componentID: 0xFF01)
		#expect(
			throws: MLS.KeySchedule.ExporterTree.ExportError.componentSecretConsumed(
				0xFF01)
		) {
			try group.deriveApplicationPSK(provider, componentID: 0xFF01)
		}
	}

	/// Both members of a group derive an identical `(psk_id, psk)` for the same
	/// component and epoch, independently — and a commit importing that PSK
	/// converges. Only the `PreSharedKeyID` crosses the wire, in the proposal.
	@Test("both parties derive the same application PSK and a commit importing it converges")
	func applicationPSKRoundTripsThroughACommit() throws {
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

		// Both derive the epoch's APQ component independently, before the commit.
		let (pskIDA, pskA) = try groupA.deriveApplicationPSK(provider, componentID: 0xFF01)
		let (pskIDB, pskB) = try groupB.deriveApplicationPSK(provider, componentID: 0xFF01)
		#expect(pskIDA == pskIDB)
		#expect(Self.bytes(pskA) == Self.bytes(pskB))

		let nonce = provider.randomBytes(provider.hashSize)
		let appID = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: 0xFF01, pskID: pskIDA, nonce: nonce)
		// Resolve by the wire id (its `applicationStorageID`) rather than blindly,
		// so the closure proves it received the `.application` id it expects.
		let storageID = try #require(try appID.applicationStorageID())
		let resolveA: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			(try id.applicationStorageID()) == storageID ? Self.bytes(pskA) : nil
		}
		let commit = try groupA.committing(
			provider, proposals: [.proposal(.preSharedKey(appID))],
			signingKey: alice.signingKey, randomness: .generate(provider), psk: resolveA
		)
		groupA = commit.group

		let resolveB: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			(try id.applicationStorageID()) == storageID ? Self.bytes(pskB) : nil
		}
		try SelfInteropTests.processPrivate(
			&groupB, provider, commit.commit, psk: resolveB)
		SelfInteropTests.assertConverged(groupA, groupB)
	}

	/// §12.1.4: the `psk_nonce` MUST be KDF.Nh long — for the application arm too.
	/// Pre-fix, the length check covered only external/resumption, so a wrong-length
	/// application nonce would be accepted where the fork rejects it.
	@Test("an application PSK with a wrong-length nonce is rejected")
	func applicationPSKWrongNonceLength() throws {
		let provider = Self.provider
		let solo = try SelfInteropTests.member("solo")
		let group = try SelfInteropTests.createGroup(solo)
		let badID = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: 0xFF01, pskID: Data([1, 2, 3]), nonce: Data([0x00]))
		#expect(
			throws: MLS.RFC9420.GroupError.wrongPskNonceLength(
				expected: provider.hashSize, actual: 1)
		) {
			try group.committing(
				provider, proposals: [.proposal(.preSharedKey(badID))],
				signingKey: solo.signingKey, randomness: .generate(provider))
		}
	}
}
