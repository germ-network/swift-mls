import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// Zeroization hardening: once secret-carrying fields are held in
/// `SecretBytes`, a zero-length secret is unconstructible — `SecretBytes`
/// **throws** on empty input rather than trapping. This suite pins that the
/// key schedule and the join path both *reject* such input (a throw, never a
/// trap), and that the profile surfaces a clean domain error rather than the
/// dependency's own.
@Suite("Hostile/malformed Welcome: empty secrets are rejected, not trapped")
struct HostileWelcomeTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	/// A zero-length `joiner_secret` cannot key the schedule. Proven at the
	/// component level: `fromJoinerSecret` throws rather than trapping or
	/// silently deriving from empty input.
	@Test("fromJoinerSecret rejects a zero-length joiner secret with a throw")
	func keyScheduleRejectsEmptyJoinerSecret() throws {
		#expect(throws: (any Error).self) {
			_ = try MLS.KeySchedule.fromJoinerSecret(
				Self.provider,
				joinerSecret: Data(),
				pskSecret: Data(repeating: 0, count: Self.provider.hashSize),
				groupContext: Data("ctx".utf8))
		}
	}

	/// The end-to-end hostile-decode test the zeroization review asked for:
	/// build a
	/// real Welcome (Alice adds Bob), then re-seal a tampered `GroupSecrets`
	/// whose `joiner_secret` is zero-length to Bob's own init key. `join`
	/// must reject it with `emptyJoinerSecret` — a clean domain error thrown
	/// before any garbage derivation, not a trap and not the confirmation-tag
	/// mismatch that would otherwise mask it.
	@Test("join rejects a re-sealed Welcome carrying an empty joiner secret")
	func joinRejectsEmptyJoinerSecret() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider,
			proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey,
			randomness: .generate(provider))
		let welcome = try #require(add.welcome)

		// Sanity: the untampered Welcome joins cleanly.
		_ = try MLS.RFC9420.Group.join(
			provider, welcome: welcome,
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Tamper: seal a GroupSecrets with a zero-length joiner_secret to
		// Bob's public init key, under the same "Welcome" label and
		// encrypted_group_info context the real Welcome binds — exactly what
		// a malicious inviter (who signs the GroupInfo) could produce.
		let tampered = MLS.RFC9420.GroupSecrets(
			joinerSecret: Data(), pathSecret: nil, psks: [])
		let (enc, ciphertext) = try MLS.encryptWithLabel(
			provider, publicKey: bob.keyPackage.initKey, label: "Welcome",
			context: welcome.encryptedGroupInfo,
			plaintext: try tampered.mlsEncoded())
		let hostile = MLS.RFC9420.Welcome(
			cipherSuite: welcome.cipherSuite,
			secrets: [
				.init(
					newMember: try bob.keyPackage.reference(provider),
					encryptedGroupSecrets: .init(
						kemOutput: enc, ciphertext: ciphertext))
			],
			encryptedGroupInfo: welcome.encryptedGroupInfo)

		#expect(throws: MLS.RFC9420.GroupError.emptyJoinerSecret) {
			_ = try MLS.RFC9420.Group.join(
				provider, welcome: hostile,
				credentials: bob.joinCredentials, psk: { _ in nil })
		}
	}

	/// The external-PSK custody boundary, end to end: a resolver that hands
	/// back a zero-length PSK for a referenced id is malformed input, mapped
	/// to `emptyPreSharedKey` at `resolvePsk` rather than folded into the key
	/// schedule (or surfaced as the dependency's own error).
	@Test("an empty external PSK is rejected with emptyPreSharedKey at processing")
	func emptyExternalPskRejectedAtProcessing() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let groupB = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Alice commits an external-PSK proposal, built with a valid
		// (non-empty) resolver so the commit itself is well-formed.
		let pskID = provider.randomBytes(provider.hashSize)
		let realSecret = Data(repeating: 0xAB, count: provider.hashSize)
		let goodResolve: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			guard case .external(let id, _) = id, id == pskID else { return nil }
			return realSecret
		}
		let pskCommit = try groupA.commit(
			provider,
			proposals: [
				.proposal(
					.preSharedKey(
						.external(
							pskID: pskID,
							nonce: provider.randomBytes(
								provider.hashSize))))
			],
			signingKey: alice.signingKey, randomness: .generate(provider),
			includePath: false, psk: goodResolve)

		// Bob processes the same commit, but his resolver hands back an empty
		// PSK for that id — rejected at the custody boundary before the fold.
		let emptyResolve: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			guard case .external(let id, _) = id, id == pskID else { return nil }
			return Data()
		}
		#expect(throws: MLS.RFC9420.GroupError.emptyPreSharedKey) {
			var b = groupB
			try SelfInteropTests.processPrivate(
				&b, provider, pskCommit.commit, psk: emptyResolve)
		}
	}
}
