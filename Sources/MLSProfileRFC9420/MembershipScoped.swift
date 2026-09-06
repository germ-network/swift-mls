import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

// D18 — the membership-scoped entry points. Operations that depend on *which*
// local client acts (committing, sending, proposing a self-Update) name the
// membership explicitly, so client-dependence is visible exactly where it
// exists; the receive path and application receive are client-independent and
// stay on `Group`. Each `(as:)` form resolves the leaf to a membership index and
// drives that membership's own state (slices 3b/4a make this N > 1-correct: the
// send ratchets are per-membership, and a commit installs new-epoch keys for
// every membership by decapping its path). The bare (non-`as:`) forms resolve
// the sole membership and are `ambiguousMembership` at N ≠ 1.

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
	/// `Transition<SentCommit>` shape. N > 1-correct (slice 4a): the delta installs
	/// new-epoch keys for every local membership — `leaf` from the path it builds,
	/// the others by decapping that path.
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
		try committing(
			committerIndex: try membershipIndex(of: leaf), provider,
			proposals: proposalList, proposalStore: proposalStore,
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
