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

	/// The sole local membership's index, or `ambiguousMembership` at N ≠ 1 — how
	/// the bare (non-`as:`) send API resolves which membership acts.
	func soleMembershipIndex() throws -> Int {
		guard memberships.count == 1 else {
			throw MLS.RFC9420.GroupError.ambiguousMembership(count: memberships.count)
		}
		return 0
	}

	/// The index of the local membership occupying `leaf`, or `ambiguousMembership`
	/// if none does — how the `(as:)` send API resolves the named membership.
	func membershipIndex(of leaf: MLS.LeafIndex) throws -> Int {
		guard let index = memberships.firstIndex(where: { $0.leafIndex == leaf })
		else {
			throw MLS.RFC9420.GroupError.ambiguousMembership(count: memberships.count)
		}
		return index
	}

	/// Commit as the local membership occupying `leaf` (D18), in the D17
	/// `Transition<SentCommit>` shape. See this file's note; the per-leaf ratchet
	/// move that makes N > 1 send correct is slice 3b.
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
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.SentCommit> {
		try requireLocalMembership(leaf)
		return try committing(
			provider, proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension,
			framing: framing, reuseGuard: reuseGuard, paddingLength: paddingLength,
			psk: psk)
	}

	/// The eager convenience of `committing(as:)` — see `commit(_:proposals:…)`.
	@discardableResult
	public mutating func commit(
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
		return try commit(
			provider, proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension,
			framing: framing, reuseGuard: reuseGuard, paddingLength: paddingLength,
			psk: psk)
	}

	/// Propose a self-Update for the local membership occupying `leaf` (D18) —
	/// the membership's pending transition to a new LeafNode. N > 1-correct (slice
	/// 3b): the pending self-Update and the seal are both scoped to this membership.
	public mutating func proposingUpdate(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey,
		framing: HandshakeFraming = .privateMessage
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		try proposeUpdate(
			membershipIndex: try membershipIndex(of: leaf), provider,
			signingKey: signingKey, framing: framing)
	}

	/// Send an application message as the local membership occupying `leaf` (D18),
	/// with an explicit reuse guard. N > 1-correct (slice 3b): spends this
	/// membership's own application ratchet, independent of any other membership's.
	public mutating func protect(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		applicationData: Data,
		authenticatedData: Data = Data(),
		signingKey: MLS.SignatureSecretKey,
		reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int = 0
	) throws -> MLS.RFC9420.PrivateMessage {
		try protectContent(
			membershipIndex: try membershipIndex(of: leaf), provider,
			content: .application(applicationData),
			authenticatedData: authenticatedData, signingKey: signingKey,
			reuseGuard: reuseGuard, paddingLength: max(0, paddingLength)
		).message
	}

	/// Convenience: fresh reuse-guard bytes from the provider.
	public mutating func protect(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		applicationData: Data,
		authenticatedData: Data = Data(),
		signingKey: MLS.SignatureSecretKey,
		paddingLength: Int = 0
	) throws -> MLS.RFC9420.PrivateMessage {
		try protect(
			as: leaf, provider, applicationData: applicationData,
			authenticatedData: authenticatedData, signingKey: signingKey,
			reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)),
			paddingLength: paddingLength)
	}
}
