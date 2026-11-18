import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// Every `membershipRemoved` names the committer, including a full eviction,
/// where `epochAdvanced` is absent. This implementation's choice, not an RFC 9420
/// rule.
@Suite("Eviction reports the committer")
struct EvictionCommitterTests {
	static let provider = ConstructedRejectionTests.provider

	private static func removeCommit(
		of removed: MLS.LeafIndex, by committer: MLS.RFC9420.Group,
		signingKey: MLS.SignatureSecretKey
	) throws -> MLS.RFC9420.PublicMessage {
		var committer = committer
		let out = try committer.commit(
			provider, proposals: [.proposal(.remove(removed))], signingKey: signingKey,
			randomness: .generate(provider), framing: .publicMessage)
		guard case .publicMessage(let message) = out.commit else { throw Failure.framing }
		return message
	}

	enum Failure: Error { case framing }

	@Test("a full eviction reports the committer")
	func fullEvictionReportsCommitter() throws {
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.bobView.myLeafIndex
		let commit = try Self.removeCommit(
			of: bobLeaf, by: t.aliceView, signingKey: t.alice.signingKey)

		let events = try t.bobView.validating(
			Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
		).effects.events
		#expect(
			events.contains(
				.membershipRemoved(
					leaf: bobLeaf, committer: t.aliceView.myLeafIndex)))
		#expect(
			!events.contains {
				if case .epochAdvanced = $0 { true } else { false }
			})
	}

	@Test("a partial eviction reports the committer")
	func partialEvictionReportsCommitter() throws {
		let t = try PerMembershipReceiveTests.trio()
		let bobLeaf = t.multi.memberships[1].leafIndex
		let commit = try Self.removeCommit(
			of: bobLeaf, by: t.carolView, signingKey: t.carol.signingKey)

		let events = try t.multi.validating(
			Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
		).effects.events
		#expect(
			events.contains(
				.membershipRemoved(
					leaf: bobLeaf, committer: t.carolView.myLeafIndex)))
		#expect(
			events.contains {
				if case .epochAdvanced = $0 { true } else { false }
			})
	}
}
