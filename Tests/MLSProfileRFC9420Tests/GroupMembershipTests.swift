import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// D18 slice 1a — the Group/Membership carve-out. The structural split is
/// behavior-preserving at N = 1 (the whole existing suite proves that); these
/// pin the new surface: the sole-membership accessor, the membership-scoped
/// entry points, and the N > 1 send guard that keeps "N > 1 supported" honest
/// (receive works; send fails loudly until the send-side slice).
@Suite("Group / Membership carve-out (D18 1a)")
struct GroupMembershipTests {
	static let provider = ConstructedRejectionTests.provider

	@Test("at N = 1 the sole membership carries the client's leaf")
	func soleMembershipAtNOne() throws {
		let pair = try ConstructedRejectionTests.pair()
		let sole = try #require(pair.groupA.soleMembership)
		#expect(sole.leafIndex == pair.groupA.myLeafIndex)
		#expect(pair.groupA.memberships.count == 1)
	}

	@Test("committing(as:) delegates to the sole membership at N = 1")
	func committingAsSoleMembership() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var group = pair.groupA
		let output = try group.commit(
			as: group.myLeafIndex, provider, proposals: [],
			signingKey: pair.alice.signingKey, randomness: .generate(provider))
		// Advanced the epoch exactly as the plain `commit` would.
		#expect(output.group.context.epoch == pair.groupA.context.epoch + 1)
	}

	@Test("committing(as:) rejects a leaf that is not a local membership")
	func committingAsForeignLeaf() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 1)) {
			_ = try pair.groupA.committing(
				as: MLS.LeafIndex(value: 999), provider, proposals: [],
				signingKey: pair.alice.signingKey, randomness: .generate(provider))
		}
	}

	@Test("at N > 1 every bare send entry is ambiguous; the (as:) form names the membership")
	func multipleMembershipsSendResolution() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var group = pair.groupA
		// A second local membership on a DISTINCT leaf (identity is the leaf
		// index). Every send is per-membership now (slices 3b + 4a: pure sends and
		// `commit`), so the bare (non-`as:`) entry can no longer pick one — it is
		// `ambiguousMembership`, and the `(as:)` forms are the N > 1 path (proven
		// in `PerMembershipSendTests` / `PerMembershipReceiveTests`).
		group.memberships.append(
			MLS.RFC9420.Membership(
				leafIndex: MLS.LeafIndex(value: 1), secretKeys: [:]))

		#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 2)) {
			_ = try group.protect(
				provider, applicationData: Data("x".utf8),
				signingKey: pair.alice.signingKey)
		}
		#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 2)) {
			_ = try group.commit(
				provider, proposals: [], signingKey: pair.alice.signingKey,
				randomness: .generate(provider))
		}
		// Both framings resolve the membership before branching, so both are
		// ambiguous on the bare form.
		for framing in [
			MLS.RFC9420.Group.HandshakeFraming.privateMessage, .publicMessage,
		] {
			#expect(throws: MLS.RFC9420.GroupError.ambiguousMembership(count: 2)) {
				_ = try group.proposeUpdate(
					provider, signingKey: pair.alice.signingKey,
					framing: framing)
			}
		}
	}

}
