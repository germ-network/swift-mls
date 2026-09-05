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

	@Test("every send path fails closed at N > 1")
	func multipleMembershipsFailClosed() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		var group = pair.groupA
		// A second local membership on a DISTINCT leaf (identity is the leaf
		// index). This is the shape the send-side slice makes correct; until
		// then every send path must fail closed rather than share positions or
		// silently drop a membership. (The format-2 snapshot no longer guards
		// here — it persists every membership; see `SnapshotTests`.)
		group.memberships.append(
			MLS.RFC9420.Membership(
				leafIndex: MLS.LeafIndex(value: 1), secretKeys: [:]))

		#expect(throws: MLS.RFC9420.GroupError.multipleMembershipsUnsupported) {
			_ = try group.protect(
				provider, applicationData: Data("x".utf8),
				signingKey: pair.alice.signingKey)
		}
		#expect(throws: MLS.RFC9420.GroupError.multipleMembershipsUnsupported) {
			_ = try group.commit(
				provider, proposals: [], signingKey: pair.alice.signingKey,
				randomness: .generate(provider))
		}
		// Both framings: the public branch seals via `sealPublic` and never
		// reaches `protectContent`'s guard, so `proposeUpdate` must guard at its
		// top.
		for framing in [
			MLS.RFC9420.Group.HandshakeFraming.privateMessage, .publicMessage,
		] {
			#expect(throws: MLS.RFC9420.GroupError.multipleMembershipsUnsupported) {
				_ = try group.proposeUpdate(
					provider, signingKey: pair.alice.signingKey,
					framing: framing)
			}
		}
	}

	@Test("commit-receive fails closed at N > 1 (installs keys for one membership only)")
	func commitReceiveFailsClosed() throws {
		let provider = Self.provider
		let pair = try ConstructedRejectionTests.pair()
		// A real public commit from Alice at N = 1, that Bob would receive.
		let commitOut = try pair.groupA.committing(
			provider, proposals: [], signingKey: pair.alice.signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let publicCommit) = commitOut.output.message else {
			Issue.record("expected a public commit")
			return
		}
		// Bob gains a second local membership; receiving the commit then fails
		// closed rather than installing keys for `memberships[0]` alone.
		var bob = pair.groupB
		bob.memberships.append(
			MLS.RFC9420.Membership(leafIndex: MLS.LeafIndex(value: 2), secretKeys: [:]))
		#expect(throws: MLS.RFC9420.GroupError.multipleMembershipsUnsupported) {
			_ = try bob.processing(
				provider, commit: publicCommit, proposals: .init(),
				psk: { _ in nil })
		}
	}
}
