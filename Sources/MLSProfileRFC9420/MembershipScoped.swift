import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

// D18 — the membership-scoped entry points. Operations that depend on *which*
// local client acts (committing, proposing a self-Update) name the membership
// explicitly, so client-dependence is visible exactly where it exists; the
// receive path and application receive are client-independent and stay on
// `Group`. In slice 1a these validate the leaf and delegate to the pre-D18
// sole-membership methods (which, at N = 1, act on that membership); N > 1 send
// fails closed until the send-side slice, which reshapes `committing(as:)` to
// return a `Transition<SentCommit>` and moves per-leaf ratchets onto each
// `Membership`.

extension MLS.RFC9420.Group {
	/// Validates that `leaf` names one of this group's local memberships — the
	/// precondition of every membership-scoped operation.
	func requireLocalMembership(_ leaf: MLS.LeafIndex) throws {
		guard memberships.contains(where: { $0.leafIndex == leaf }) else {
			throw MLS.RFC9420.GroupError.ambiguousMembership(count: memberships.count)
		}
	}

	/// Commit as the local membership occupying `leaf` (D18). See this file's
	/// note; slice 3 gives it the D17 `Transition<SentCommit>` shape.
	public func committing(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		proposals proposalList: [MLS.RFC9420.ProposalOrRef],
		proposalStore: MLS.RFC9420.ProposalStore = MLS.RFC9420.ProposalStore(),
		signingKey: MLS.SignatureSecretKey,
		randomness: CommitRandomness,
		includePath: Bool = true,
		includeRatchetTreeExtension: Bool = true,
		framing: HandshakeFraming = .privateMessage,
		reuseGuard: MLS.Framing.ReuseGuard? = nil,
		paddingLength: Int = 0,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { _ in nil }
	) throws -> CommitOutput {
		try requireLocalMembership(leaf)
		return try committing(
			provider, proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension,
			framing: framing, reuseGuard: reuseGuard, paddingLength: paddingLength,
			psk: psk)
	}

	/// Propose a self-Update for the local membership occupying `leaf` (D18) —
	/// the membership's pending transition to a new LeafNode.
	public mutating func proposingUpdate(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey,
		framing: HandshakeFraming = .privateMessage
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		try requireLocalMembership(leaf)
		return try proposeUpdate(provider, signingKey: signingKey, framing: framing)
	}
}
