import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// ADR 0002's signer-closure seam: every authoring entry point routes through
/// `MLS.RFC9420.SigningClosure` instead of a raw key, with `signingKey:` kept
/// as sugar over a trivial adapter. These tests exercise the real public API
/// (`SelfInteropTests.member`/`createGroup`, `GroupMutationTests.signingKeyPair`
/// underneath) — no library change backs the tests themselves, only the seam
/// they pin.
@Suite("Signer-closure seam (ADR 0002)")
struct SignerSeamTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	/// A plain, hand-written closure — not the library's own `signingClosure`
	/// adapter — so equivalence/round-trip tests exercise the seam at the
	/// boundary an application actually sees, not the library's internal
	/// wiring reflected back at itself.
	static func plainClosure(
		_ provider: any MLS.CipherSuiteProvider, _ key: MLS.SignatureSecretKey
	)
		-> MLS.RFC9420.SigningClosure
	{
		{ request in try provider.sign(privateKey: key, content: request.signContent) }
	}

	/// Records the `role` of every signature it is asked to produce, in
	/// order, while still answering with a real signature (a class, not a
	/// struct: the closure it hands out must mutate shared state across
	/// calls, exactly the stateful-custodian shape ADR 0002 is for).
	final class RoleRecorder {
		private(set) var roles: [MLS.RFC9420.SignatureRole] = []
		private let provider: any MLS.CipherSuiteProvider
		private let key: MLS.SignatureSecretKey

		init(provider: any MLS.CipherSuiteProvider, key: MLS.SignatureSecretKey) {
			self.provider = provider
			self.key = key
		}

		func sign(_ request: MLS.RFC9420.SigningRequest) throws -> Data {
			roles.append(request.role)
			return try provider.sign(privateKey: key, content: request.signContent)
		}
	}

	// MARK: - equivalenceLeafDeterministic

	/// A closure-authored leaf signature (for both `committing`'s path leaf
	/// and `proposeUpdate`'s leaf) is checked against a `signWithLabel`-shaped
	/// recompute.
	///
	/// **Deviation from the plan, verified empirically.** The plan expected
	/// Ed25519 (`.curve25519Aes128`) to be deterministic and planned to
	/// recompute a leaf's signature byte-for-byte via a second
	/// `signWithLabel` call. A scratch check against `SwiftCryptoProvider`
	/// (`provider.sign` on the identical key and content, twice) showed two
	/// *different*, both-valid signatures: swift-crypto's Ed25519 is hedged
	/// (randomized), not the plain RFC 8032 deterministic scheme, at least
	/// via CryptoKit on Apple platforms. (Linux's swift-crypto, backed by
	/// BoringSSL rather than CryptoKit, signs Ed25519 deterministically per
	/// RFC 8032 — so this suite must not assert equality OR inequality of
	/// two independently-produced signatures; only the encoding-layer bytes
	/// handed to the signer are compared byte-for-byte.) A leaf's signature
	/// is itself encoded into the tree hash, which then feeds the provisional
	/// context, the path, the transcript, and the key schedule — so this
	/// isn't limited to the leaf signature; it rules out byte-comparing
	/// *any* two independently-authored commits, including the plan's
	/// fold-in idea of comparing `message`/`welcome.encryptedGroupInfo`
	/// across a `sign:` run and a `signingKey:` run under shared explicit
	/// randomness. What IS genuinely deterministic — pure encoding, no
	/// cryptographic randomness — is the bytes an authoring site hands its
	/// signer: `MLS.signContentBytes`, the M1 encoder this seam is built on.
	/// This test pins that directly (via a capturing closure) and confirms
	/// the resulting signature verifies against those same bytes — the
	/// achievable, honest form of "the closure signs exactly what
	/// `signWithLabel` would".
	@Test func equivalenceLeafDeterministic() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		final class CapturingSigner {
			private(set) var captured: [MLS.RFC9420.SignatureRole: Data] = [:]
			private let provider: any MLS.CipherSuiteProvider
			private let key: MLS.SignatureSecretKey

			init(provider: any MLS.CipherSuiteProvider, key: MLS.SignatureSecretKey) {
				self.provider = provider
				self.key = key
			}

			func sign(_ request: MLS.RFC9420.SigningRequest) throws -> Data {
				captured[request.role] = request.signContent
				return try provider.sign(
					privateKey: key, content: request.signContent)
			}

			func content(for role: MLS.RFC9420.SignatureRole) -> Data? {
				captured[role]
			}
		}

		// The commit's path leaf.
		let commitSigner = CapturingSigner(provider: provider, key: alice.signingKey)
		let transition = try SelfInteropTests.createGroup(alice).committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			sign: commitSigner.sign, randomness: .generate(provider),
			framing: .publicMessage)

		guard case .publicMessage(let pub) = transition.output.message else {
			Issue.record("expected a public commit")
			return
		}
		guard case .commit(let commit) = pub.content.content else {
			Issue.record("expected commit content")
			return
		}
		let emittedLeaf = try #require(commit.path?.leafNode)
		let expectedLeafContent = try MLS.signContentBytes(
			label: "LeafNodeTBS",
			content: try emittedLeaf.toBeSigned(
				placement: .inGroup(
					groupID: pub.content.groupID,
					leafIndex: MLS.LeafIndex(value: 0))))
		#expect(commitSigner.content(for: .leafNode) == expectedLeafContent)
		#expect(
			try provider.verify(
				publicKey: alice.signatureKey, content: expectedLeafContent,
				signature: emittedLeaf.signature))

		// The same check for `proposeUpdate`'s leaf, on a separate group.
		let updateSigner = CapturingSigner(provider: provider, key: alice.signingKey)
		var updateGroup = try SelfInteropTests.createGroup(alice)
		let (updateMessage, _) = try updateGroup.proposeUpdate(
			provider, sign: updateSigner.sign, framing: .publicMessage)
		guard case .publicMessage(let updatePub) = updateMessage else {
			Issue.record("expected a public proposal")
			return
		}
		guard case .proposal(.update(let updateLeaf)) = updatePub.content.content else {
			Issue.record("expected an update proposal")
			return
		}
		let expectedUpdateContent = try MLS.signContentBytes(
			label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: updatePub.content.groupID,
					leafIndex: MLS.LeafIndex(value: 0))))
		#expect(updateSigner.content(for: .leafNode) == expectedUpdateContent)
		#expect(
			try provider.verify(
				publicKey: alice.signatureKey, content: expectedUpdateContent,
				signature: updateLeaf.signature))
	}

	// MARK: - roundTripViaClosure

	/// A commit and a `protect`, each authored via a plain closure (not the
	/// library's own `signingClosure` adapter), are validated/decrypted by a
	/// peer through the ordinary receive path — the seam changes nothing
	/// about what a peer can do with the result.
	@Test func roundTripViaClosure() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		let transition = try SelfInteropTests.createGroup(alice).committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			sign: Self.plainClosure(provider, alice.signingKey),
			randomness: .generate(provider))
		let welcomeOption: MLS.RFC9420.Welcome? = transition.output.welcome
		let welcome = try #require(welcomeOption)
		var groupB = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: bob.joinCredentials,
			psk: { _ in nil })
		// Read the `Copyable` field first; `takeOutput()`/`takePending()` consume
		// the `~Copyable` chain, so they cannot share an expression with `.group`.
		let sealedGroup = transition.group
		let pending = transition.takeOutput().takePending()
		var groupA = try pending.apply(onto: sealedGroup).group

		SelfInteropTests.assertConverged(groupA, groupB)

		let message = try groupA.protect(
			provider, applicationData: Data("hello via closure".utf8),
			sign: Self.plainClosure(provider, alice.signingKey),
			reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)))
		let opened = try groupB.unprotect(provider, message: message)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("hello via closure".utf8))
	}

	// MARK: - rolesObservedInOrder

	/// Every authoring site tags its `SigningRequest` with the right role, in
	/// the right order: a pathless commit consumes no leaf ticket, a
	/// path-only commit produces no `GroupInfo`, and each of `proposeUpdate`
	/// / `protect` signs exactly what its doc comments claim.
	@Test func rolesObservedInOrder() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		// Add + path (the default `includePath: true`): leaf, then
		// framedContent, then groupInfo for the Welcome.
		do {
			let group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.committing(
				provider, proposals: [.proposal(.add(bob.keyPackage))],
				sign: recorder.sign, randomness: .generate(provider))
			#expect(recorder.roles == [.leafNode, .framedContent, .groupInfo])
		}

		// Path, no add: an empty commit still requires a path (§12.4.1), and
		// nothing is added, so no Welcome/groupInfo.
		do {
			let group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.committing(
				provider, proposals: [], sign: recorder.sign,
				randomness: .generate(provider))
			#expect(recorder.roles == [.leafNode, .framedContent])
		}

		// `includePath: false` + add: an Add alone never forces a path
		// (§12.4's Path Required table), so the pathless commit consumes no
		// leaf ticket -- framedContent then groupInfo for the Welcome.
		do {
			let group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.committing(
				provider, proposals: [.proposal(.add(bob.keyPackage))],
				sign: recorder.sign, randomness: .generate(provider),
				includePath: false)
			#expect(recorder.roles == [.framedContent, .groupInfo])
		}

		// proposeUpdate (default private framing): leaf, then framedContent.
		do {
			var group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.proposeUpdate(provider, sign: recorder.sign)
			#expect(recorder.roles == [.leafNode, .framedContent])
		}

		// Add + path, public framing: `signPublic` must tag its commit
		// signature `.framedContent`, exactly as `signPrivate` does above --
		// pins the role `signPublic` uses (`Protect.swift`), which nothing
		// above exercises since every prior commit case is private-framed.
		do {
			let group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.committing(
				provider, proposals: [.proposal(.add(bob.keyPackage))],
				sign: recorder.sign, randomness: .generate(provider),
				framing: .publicMessage)
			#expect(recorder.roles == [.leafNode, .framedContent, .groupInfo])
		}

		// proposeUpdate, public framing: same `signPublic` role pin, on the
		// leaf-then-framedContent shape (no Welcome/groupInfo for a proposal).
		do {
			var group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.proposeUpdate(
				provider, sign: recorder.sign, framing: .publicMessage)
			#expect(recorder.roles == [.leafNode, .framedContent])
		}

		// protect: framedContent alone.
		do {
			var group = try SelfInteropTests.createGroup(alice)
			let recorder = RoleRecorder(provider: provider, key: alice.signingKey)
			_ = try group.protect(
				provider, applicationData: Data("hi".utf8), sign: recorder.sign,
				reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)))
			#expect(recorder.roles == [.framedContent])
		}
	}

	// MARK: - signingKeySugarUnchanged

	/// A regression check that `signingKey:` — the adapter's own sugar —
	/// still produces a commit a peer accepts and converges on, exactly as
	/// before this seam existed.
	@Test func signingKeySugarUnchanged() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		let transition = try SelfInteropTests.createGroup(alice).committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		let welcomeOption: MLS.RFC9420.Welcome? = transition.output.welcome
		let welcome = try #require(welcomeOption)
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: bob.joinCredentials,
			psk: { _ in nil })
		let sealedGroup = transition.group
		let pending = transition.takeOutput().takePending()
		let groupA = try pending.apply(onto: sealedGroup).group

		SelfInteropTests.assertConverged(groupA, groupB)
	}

	// MARK: - throwingClosureLeavesGroupUnchanged

	/// Pins the S2 reorder (frame → sign → derive → seal): a signer closure
	/// that throws must leave `Membership.ownSend` untouched, because
	/// `deriveOwnSendKey` — the mutation that spends this membership's own
	/// generation — now runs strictly after the signature is in hand.
	/// Getting the order backwards (derive, THEN sign) would burn a
	/// generation on every declined/exhausted signature.
	@Test func throwingClosureLeavesGroupUnchanged() throws {
		struct Boom: Error {}

		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		var group = try SelfInteropTests.createGroup(alice)

		let before = group.memberships[0].ownSend.nextGeneration(isHandshake: false)
		#expect(throws: Boom.self) {
			_ = try group.protect(
				provider, applicationData: Data("declined".utf8),
				sign: { _ in throw Boom() },
				reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)))
		}
		#expect(group.memberships[0].ownSend.nextGeneration(isHandshake: false) == before)

		// Sanity: an ordinary protect on the same group DOES advance it, so the
		// check above is not vacuously true of a ratchet that never moves.
		_ = try group.protect(
			provider, applicationData: Data("accepted".utf8),
			sign: Self.plainClosure(provider, alice.signingKey),
			reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)))
		#expect(
			group.memberships[0].ownSend.nextGeneration(isHandshake: false) == before
				+ 1)
	}
}
