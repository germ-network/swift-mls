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

	/// RFC 9420 §12.4.3.1: "if a PreSharedKeyID has type resumption with usage
	/// reinit or branch, verify that it is the only such PSK." Read per the
	/// anaphoric "such" as: at most one resumption PSK of usage reinit/branch.
	/// A Welcome carrying two of them — reinit+reinit, reinit+branch, or
	/// branch+branch — violates the rule and `join` must reject it with the
	/// dedicated `resumptionPSKNotSole`, thrown before any resolution or
	/// derivation. (Pre-fix, the per-entry capability gate would throw
	/// `unsupportedResumptionUsage` on the first entry instead, so this pins the
	/// new structural check specifically, not the pre-existing gate.)
	@Test(
		"join rejects a Welcome with more than one reinit/branch resumption PSK",
		arguments: [
			[MLS.RFC9420.ResumptionPSKUsage.reinit, .reinit],
			[.reinit, .branch],
			[.branch, .branch],
		])
	func joinRejectsMultipleReinitBranchResumptionPSKs(
		_ usages: [MLS.RFC9420.ResumptionPSKUsage]
	) throws {
		let provider = Self.provider
		let psks = usages.map { Self.resumptionPSK(provider, usage: $0) }
		let (hostile, bob) = try Self.hostileWelcome(provider, psks: psks)

		#expect(throws: MLS.RFC9420.GroupError.resumptionPSKNotSole) {
			_ = try MLS.RFC9420.Group.join(
				provider, welcome: hostile,
				credentials: bob.joinCredentials, psk: { _ in nil })
		}
	}

	/// The discriminator between the RFC-correct reading and the stricter
	/// misreading (that a reinit/branch PSK must be the *sole* PSK): a single
	/// reinit resumption PSK accompanied by an allowed companion is well-formed
	/// under the only-such rule, which counts only the reinit/branch kind
	/// ("external/application PSKs may accompany it"), so it is NOT rejected as
	/// `resumptionPSKNotSole`. Exercised for all three companion kinds the rule
	/// permits — external, resumption-usage `application`, and the draft
	/// top-level `application` type — so the test fails if the only-such check
	/// is ever tightened to count any of them (e.g. reading A, or folding
	/// application PSKs into the limit). It is still rejected here, by the
	/// capability gate (`unsupportedResumptionUsage`, reinit/branch deferred
	/// project-wide), with the reinit entry ordered first so the gate, not the
	/// unresolved companion, is what fires.
	@Test(
		"a lone reinit resumption PSK beside an allowed companion is not an only-such violation",
		arguments: ["external", "resumption-application", "application-component"])
	func loneReinitWithAllowedCompanionIsNotOnlySuchViolation(_ companion: String) throws {
		let provider = Self.provider
		let nonce = Data(repeating: 0, count: provider.hashSize)
		let companionPSK: MLS.RFC9420.PreSharedKeyIdentifier =
			switch companion {
			case "external":
				.external(pskID: Data(repeating: 9, count: 8), nonce: nonce)
			case "resumption-application":
				.resumption(
					.init(
						usage: .application, groupID: Data("other".utf8),
						epoch: 2),
					nonce: nonce)
			default:
				.application(
					componentID: MLS.KeySchedule.ComponentID(0xFF01),
					pskID: Data(repeating: 9, count: 8), nonce: nonce)
			}
		let psks: [MLS.RFC9420.PreSharedKeyIdentifier] = [
			Self.resumptionPSK(provider, usage: .reinit), companionPSK,
		]
		let (hostile, bob) = try Self.hostileWelcome(provider, psks: psks)

		#expect(throws: MLS.RFC9420.GroupError.unsupportedResumptionUsage) {
			_ = try MLS.RFC9420.Group.join(
				provider, welcome: hostile,
				credentials: bob.joinCredentials, psk: { _ in nil })
		}
	}

	private static func resumptionPSK(
		_ provider: any MLS.CipherSuiteProvider,
		usage: MLS.RFC9420.ResumptionPSKUsage
	) -> MLS.RFC9420.PreSharedKeyIdentifier {
		.resumption(
			.init(usage: usage, groupID: Data("old-group".utf8), epoch: 1),
			nonce: Data(repeating: 0, count: provider.hashSize))
	}

	/// Build a real Welcome (Alice adds Bob), then re-seal a `GroupSecrets`
	/// carrying `psks` to Bob's own init key, under the same "Welcome" label and
	/// `encrypted_group_info` context the real Welcome binds — exactly what a
	/// malicious inviter (who signs the GroupInfo) could produce. `joiner_secret`
	/// is non-empty so the structural PSK check, not the empty-joiner guard, is
	/// what fires.
	private static func hostileWelcome(
		_ provider: any MLS.CipherSuiteProvider,
		psks: [MLS.RFC9420.PreSharedKeyIdentifier]
	) throws -> (welcome: MLS.RFC9420.Welcome, bob: SelfInteropTests.Member) {
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")

		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider,
			proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey,
			randomness: .generate(provider))
		let welcome = try #require(add.welcome)

		let tampered = MLS.RFC9420.GroupSecrets(
			joinerSecret: Data(repeating: 1, count: provider.hashSize),
			pathSecret: nil, psks: psks)
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
		return (hostile, bob)
	}
}
