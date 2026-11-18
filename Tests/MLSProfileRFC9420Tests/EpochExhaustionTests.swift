import Foundation
import MLSCodec
import Testing

@testable import MLSProfileRFC9420

/// The epoch is a `uint64` (RFC 9420 §8.1, which states no bound). Advancing past
/// `UInt64.max` throws rather than trapping; this implementation's choice.
@Suite("Epoch increment cannot trap")
struct EpochExhaustionTests {
	private static func context(epoch: UInt64) -> MLS.RFC9420.GroupContext {
		.init(
			version: .mls10, cipherSuite: .curve25519Aes128, groupID: Data([1]),
			epoch: epoch,
			treeHash: Data([2]), confirmedTranscriptHash: Data([3]), extensions: [])
	}

	@Test("the next epoch after UInt64.max throws epochExhausted")
	func nextEpochThrowsAtMaximum() throws {
		#expect(throws: MLS.RFC9420.GroupError.epochExhausted) {
			_ = try Self.context(epoch: .max).nextEpoch()
		}
	}

	@Test("the next epoch below the maximum is one more")
	func nextEpochIncrementsBelowMaximum() throws {
		#expect(try Self.context(epoch: 0).nextEpoch() == 1)
		#expect(try Self.context(epoch: .max - 1).nextEpoch() == .max)
	}

	@Test("committing on a group at epoch UInt64.max throws epochExhausted")
	func committingAtMaximumEpochThrowsEpochExhausted() throws {
		let provider = SelfInteropTests.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var group = try SelfInteropTests.createGroup(alice)
		group.context.epoch = .max
		for includePath in [true, false] {
			#expect(throws: MLS.RFC9420.GroupError.epochExhausted) {
				_ = try group.committing(
					provider, proposals: [.proposal(.add(bob.keyPackage))],
					signingKey: alice.signingKey,
					randomness: .generate(provider),
					lifetimeCheck: .unchecked, includePath: includePath)
			}
		}
	}

	@Test("validating a pathless commit at epoch UInt64.max throws epochExhausted")
	func validatingAtMaximumEpochThrowsEpochExhausted() throws {
		var pair = try ProposalValidationTests.pair()
		let carol = try SelfInteropTests.member("carol")
		pair.groupA.context.epoch = .max
		pair.groupB.context.epoch = .max
		let message = try ConstructedRejectionTests.craftedCommit(
			.init(alice: pair.alice, groupA: pair.groupA, groupB: pair.groupB),
			proposals: [.proposal(.add(carol.keyPackage))], path: nil)
		let receiver = pair.groupB
		#expect(throws: MLS.RFC9420.GroupError.epochExhausted) {
			_ = try receiver.validating(
				SelfInteropTests.provider, commit: message, proposals: .init(),
				psk: { _ in nil })
		}
	}
}
