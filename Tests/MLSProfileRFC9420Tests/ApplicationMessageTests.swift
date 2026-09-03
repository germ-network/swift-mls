import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeMath
import Testing

@testable import MLSProfileRFC9420

/// Phase 7a's gate: the stateful application-message layer, driven
/// cross-member like everything else in this profile — A protects, B
/// unprotects, and every §9.2/§15.3 property is exercised through the
/// public API.
@Suite("Application messages (§9.2 consuming store, §15.3 bounds)")
struct ApplicationMessageTests {
	static let provider = SelfInteropTests.provider

	struct Duo {
		var alice: SelfInteropTests.Member
		var bob: SelfInteropTests.Member
		var groupA: MLS.RFC9420.Group
		var groupB: MLS.RFC9420.Group
	}

	static func duo() throws -> Duo {
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
		return Duo(alice: alice, bob: bob, groupA: groupA, groupB: groupB)
	}

	@Test("messages round-trip in order, with authenticated data")
	func inOrder() throws {
		var d = try Self.duo()
		for i in 0..<5 {
			let msg = try d.groupA.protect(
				Self.provider, applicationData: Data("hello \(i)".utf8),
				authenticatedData: Data("aad \(i)".utf8),
				signingKey: d.alice.signingKey)
			let opened = try d.groupB.unprotect(Self.provider, message: msg)
			guard case .application(let data) = opened.content else {
				Issue.record("expected application content")
				return
			}
			#expect(data == Data("hello \(i)".utf8))
			#expect(opened.authenticatedData == Data("aad \(i)".utf8))
			#expect(opened.sender == d.groupA.myLeafIndex)
		}
	}

	@Test("out-of-order within an epoch: later first, earlier from the skipped cache")
	func outOfOrderWithinEpoch() throws {
		var d = try Self.duo()
		let m0 = try d.groupA.protect(
			Self.provider, applicationData: Data("zero".utf8),
			signingKey: d.alice.signingKey)
		let m1 = try d.groupA.protect(
			Self.provider, applicationData: Data("one".utf8),
			signingKey: d.alice.signingKey)
		let m2 = try d.groupA.protect(
			Self.provider, applicationData: Data("two".utf8),
			signingKey: d.alice.signingKey)
		for (msg, expected) in [(m2, "two"), (m0, "zero"), (m1, "one")] {
			let opened = try d.groupB.unprotect(Self.provider, message: msg)
			guard case .application(let data) = opened.content else {
				Issue.record("expected application content")
				return
			}
			#expect(data == Data(expected.utf8))
		}
	}

	@Test("out-of-order across epochs: an old epoch's message decrypts after a commit")
	func outOfOrderAcrossEpochs() throws {
		var d = try Self.duo()
		let old = try d.groupA.protect(
			Self.provider, applicationData: Data("from the old epoch".utf8),
			signingKey: d.alice.signingKey)
		// Advance an epoch before B ever sees the message.
		let pcs = try d.groupA.committing(
			Self.provider, proposals: [], signingKey: d.alice.signingKey,
			randomness: .generate(Self.provider))
		d.groupA = pcs.group
		guard case .privateMessage(let pcsCommit) = pcs.commit else {
			Issue.record("expected a privateMessage-framed commit")
			return
		}
		try d.groupB.process(
			Self.provider, privateCommit: pcsCommit, proposals: .init(),
			psk: { _ in nil })

		let opened = try d.groupB.unprotect(Self.provider, message: old)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("from the old epoch".utf8))

		// And the new epoch works too, in both directions.
		let fresh = try d.groupB.protect(
			Self.provider, applicationData: Data("new epoch".utf8),
			signingKey: d.bob.signingKey)
		let openedFresh = try d.groupA.unprotect(Self.provider, message: fresh)
		guard case .application(let freshData) = openedFresh.content else {
			Issue.record("expected application content")
			return
		}
		#expect(freshData == Data("new epoch".utf8))
	}

	@Test("an epoch beyond the retention depth is rejected, not derived")
	func beyondRetentionDepth() throws {
		var d = try Self.duo()
		let old = try d.groupA.protect(
			Self.provider, applicationData: Data("too old".utf8),
			signingKey: d.alice.signingKey)
		for _ in 0..<2 {  // depth is 1: two commits retire the epoch
			let pcs = try d.groupA.committing(
				Self.provider, proposals: [], signingKey: d.alice.signingKey,
				randomness: .generate(Self.provider))
			d.groupA = pcs.group
			guard case .privateMessage(let pcsCommit) = pcs.commit else {
				Issue.record("expected a privateMessage-framed commit")
				return
			}
			try d.groupB.process(
				Self.provider, privateCommit: pcsCommit, proposals: .init(),
				psk: { _ in nil })
		}
		#expect(
			throws: MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
				epoch: old.epoch)
		) {
			_ = try d.groupB.unprotect(Self.provider, message: old)
		}
	}

	@Test("a replayed message is rejected: the consumed key no longer exists")
	func replayRejected() throws {
		var d = try Self.duo()
		let msg = try d.groupA.protect(
			Self.provider, applicationData: Data("once".utf8),
			signingKey: d.alice.signingKey)
		_ = try d.groupB.unprotect(Self.provider, message: msg)
		#expect(throws: MLS.RFC9420.GroupError.generationAlreadyConsumed(generation: 0)) {
			_ = try d.groupB.unprotect(Self.provider, message: msg)
		}
	}

	@Test("a member's own message is refused, not decrypted")
	func ownMessageRefused() throws {
		var d = try Self.duo()
		let msg = try d.groupA.protect(
			Self.provider, applicationData: Data("mine".utf8),
			signingKey: d.alice.signingKey)
		#expect(throws: MLS.RFC9420.GroupError.cannotDecryptOwnMessage) {
			_ = try d.groupA.unprotect(Self.provider, message: msg)
		}
	}

	/// §15.3's DoS: a forged generation far ahead must be rejected BEFORE
	/// the derivation loop — this test completing quickly is itself the
	/// assertion.
	@Test("a huge generation jump is rejected before any derivation", .timeLimit(.minutes(1)))
	func jumpBounded() throws {
		var d = try Self.duo()
		var group = d.groupB
		// Build a message whose *sender data* claims a huge generation:
		// protect at generation 0, then re-seal the sender data by hand
		// is heavy — instead drive the store directly, which is where the
		// bound lives.
		#expect(
			throws: MLS.RFC9420.GroupError.generationJumpTooLarge(
				requested: 500_000, head: 0)
		) {
			_ = try group.deriveMessageKey(
				epoch: group.context.epoch, leaf: d.groupA.myLeafIndex,
				generation: 500_000, isHandshake: false, Self.provider)
		}
		_ = d
	}

	/// The §9.2 "(successfully)" parenthetical as an attack test: sender
	/// data is sealed under a secret every member holds, so any member
	/// can forge a message naming (victim, generation) over garbage
	/// ciphertext. A store that consumed on derivation would let that
	/// destroy the victim's real message; ours must leave state untouched
	/// on the failed open.
	@Test("a forged message cannot destroy the real one at its generation")
	func forgedMessageDoesNotConsume() throws {
		var d = try Self.duo()
		let real = try d.groupA.protect(
			Self.provider, applicationData: Data("the real message".utf8),
			signingKey: d.alice.signingKey)
		var forged = real
		// Corrupt only the TAIL, past the sender-data sample window
		// (prefix Nh): the sender data still opens -- so deriveMessageKey
		// runs and would consume, on the buggy design -- and only the
		// content AEAD fails. Corrupting the whole ciphertext (an earlier
		// version of this test) failed at sender-data opening instead and
		// never reached the attack path, which the m1 mutation exposed.
		let last = forged.ciphertext.count - 1
		forged.ciphertext[last] ^= 0xFF
		// The forgery fails in the content open...
		#expect(throws: (any Error).self) {
			_ = try d.groupB.unprotect(Self.provider, message: forged)
		}
		// ...and the real message still decrypts: nothing was consumed.
		let opened = try d.groupB.unprotect(Self.provider, message: real)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("the real message".utf8))
	}

	/// The consuming walker against the stateless vector-pinned oracle:
	/// every leaf of an 8-leaf tree, derived in adversarial order, must
	/// equal `MLS.KeySchedule.leafSecret`.
	@Test("the consuming secret tree agrees with the stateless oracle on every leaf")
	func consumingTreeMatchesOracle() throws {
		let provider = Self.provider
		let encryptionSecret = provider.randomBytes(provider.hashSize)
		let leafCount = try MLS.LeafCount(validating: 8)
		var tree = try MLS.RFC9420.Group.ConsumingSecretTree(
			encryptionSecret: encryptionSecret, leafCount: leafCount)
		for leaf in [5, 0, 7, 2, 6, 1, 3, 4] {
			let index = MLS.LeafIndex(value: UInt32(leaf))
			let consumed = try tree.consumeLeafSecret(for: index, provider)
			let oracle = try MLS.KeySchedule.leafSecret(
				provider, encryptionSecret: encryptionSecret,
				leafIndex: UInt32(leaf), numLeaves: leafCount)
			#expect(consumed.withUnsafeBytes { Data($0) } == oracle, "leaf \(leaf)")
		}
		// And the root is long gone: no leaf can be derived twice.
		#expect(throws: MLS.RFC9420.GroupError.self) {
			_ = try tree.consumeLeafSecret(for: .init(value: 3), provider)
		}
	}
}
