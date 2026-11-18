import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §16.7: tree encryption keys "MUST be distinct from one another".
/// §12.4.2's checks compare an UpdatePath only against the tree before it is
/// merged; this implementation also checks the commit's final tree, path or not,
/// and the send side runs the same checks, so every commit this library builds
/// is one it accepts.
@Suite("Commits never leave two tree nodes with one encryption key (RFC 9420 §16.7)")
struct CommitKeyUniquenessTests {
	static let provider = SelfInteropTests.provider

	/// Alice and Bob at epoch 1; Alice has already committed once with `used`.
	private static func afterCommit(
		using used: MLS.RFC9420.Group.CommitRandomness
	) throws -> (alice: SelfInteropTests.Member, group: MLS.RFC9420.Group) {
		let pair = try ProposalValidationTests.pair()
		var group = pair.groupA
		try group.commit(
			provider, proposals: [], signingKey: pair.alice.signingKey, randomness: used
		)
		return (pair.alice, group)
	}

	@Test(
		"committing twice with one CommitRandomness is refused on the second commit"
	)
	func committingRefusesReusedRandomness() throws {
		let used = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		let (alice, group) = try Self.afterCommit(using: used)
		#expect(throws: MLS.RFC9420.GroupError.updatePathReusesCommitterKey) {
			_ = try group.committing(
				Self.provider, proposals: [], signingKey: alice.signingKey,
				randomness: used, lifetimeCheck: .unchecked)
		}
	}

	@Test("committing with a reused path secret and a fresh leaf key is refused")
	func committingRefusesReusedPathSecretWithFreshLeafKey() throws {
		let used = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		let (alice, group) = try Self.afterCommit(using: used)
		var reused = try MLS.RFC9420.Group.CommitRandomness.generate(Self.provider)
		reused.firstPathSecret = used.firstPathSecret
		#expect(throws: MLS.RFC9420.GroupError.updatePathReusesEncryptionKey) {
			_ = try group.committing(
				Self.provider, proposals: [], signingKey: alice.signingKey,
				randomness: reused, lifetimeCheck: .unchecked)
		}
	}

	@Test(
		"committing with a path whose leaf key equals one of its node keys throws",
		.disabled("not yet implemented"))
	func committingRefusesPathWhoseLeafKeyEqualsANodeKey() throws {}

	@Test(
		"receiving a commit whose path repeats a node key is rejected",
		.disabled("not yet implemented"))
	func receivingRejectsPathWithDuplicateNodeKeys() throws {}

	@Test(
		"receiving a pathless commit that Adds a leaf whose key equals a parent key is rejected",
		.disabled("not yet implemented"))
	func pathlessCommitRejectsAddWhoseLeafKeyEqualsAParentKey() throws {}

	@Test(
		"committing an Add whose leaf key equals a parent key throws",
		.disabled("not yet implemented"))
	func committingRefusesAddWhoseLeafKeyEqualsAParentKey() throws {}
}
