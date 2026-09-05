import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// A `PrivateMessage` from a retained past epoch must be attributed within
/// *that epoch's* roster, never the current tree. A leaf index is reused the
/// instant its occupant is removed and a new member added (RFC 9420 §12.1.1
/// fills the leftmost empty leaf), so resolving a late message's `sender`
/// against the current tree misattributes it to the leaf's new occupant.
/// `Unprotected` carries the message `epoch` and the verified
/// `senderSignatureKey` so the application can bind attribution to the epoch.
@Suite("Retained-epoch attribution")
struct RetainedEpochAttributionTests {
	static let provider = SelfInteropTests.provider

	@Test(
		"a late message from a removed member is attributed to its own epoch and key, not the leaf's new occupant"
	)
	func retainedEpochMessageNotMisattributed() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let mallory = try SelfInteropTests.member("mallory")
		let xavier = try SelfInteropTests.member("xavier")

		// Alice + Mallory converged; Mallory joins at the leftmost blank leaf.
		var aliceGroup = try SelfInteropTests.createGroup(alice)
		let add = try aliceGroup.committing(
			provider, proposals: [.proposal(.add(mallory.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		aliceGroup = add.group
		let malloryGroup = try MLS.RFC9420.Group.join(
			provider, welcome: try #require(add.welcome),
			credentials: mallory.joinCredentials, psk: { _ in nil })
		let malloryLeaf = malloryGroup.myLeafIndex
		let epochN = aliceGroup.context.epoch

		// Honest housekeeping by Alice: remove Mallory and add Xavier in one
		// commit. Update→Remove→Add order (RFC §12.3) blanks Mallory's leaf, then
		// Add fills the leftmost empty leaf (RFC §12.1.1) — so Xavier
		// deterministically takes Mallory's just-vacated leaf.
		let commit = try aliceGroup.committing(
			provider,
			proposals: [
				.proposal(.remove(malloryLeaf)),
				.proposal(.add(xavier.keyPackage)),
			],
			signingKey: alice.signingKey, randomness: .generate(provider))
		aliceGroup = commit.group
		#expect(aliceGroup.context.epoch == epochN + 1)

		// In the CURRENT tree, Mallory's old leaf is now Xavier's.
		let occupantRecord = try #require(aliceGroup.tree.leaf(at: malloryLeaf))
		let currentOccupant = try MLS.RFC9420.LeafNode(mlsEncoded: occupantRecord.encoded)
		#expect(currentOccupant.signatureKey == xavier.signatureKey)

		// Mallory, still at epoch N, sends a message — cryptographically valid on
		// every member that still retains epoch N (the default depth does).
		var malloryEpochN = malloryGroup
		let message = try malloryEpochN.protect(
			provider, applicationData: Data("it is I, the new member".utf8),
			signingKey: mallory.signingKey)
		#expect(message.epoch == epochN)

		let opened = try aliceGroup.unprotect(provider, message: message)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("it is I, the new member".utf8))

		// The bare leaf index is Mallory's old leaf — the very index Xavier now
		// holds. Attribution MUST be epoch-bound:
		#expect(opened.sender == malloryLeaf)
		#expect(opened.epoch == epochN)  // the message's OLD epoch, not N + 1
		#expect(opened.senderSignatureKey == mallory.signatureKey)  // Mallory's key
		#expect(opened.senderSignatureKey != xavier.signatureKey)  // NOT the new occupant

		// The defense in one line: resolving `sender` against the current tree
		// yields Xavier's key (the misattribution); the epoch-bound key yields
		// Mallory's.
		#expect(currentOccupant.signatureKey != opened.senderSignatureKey)
	}
}
