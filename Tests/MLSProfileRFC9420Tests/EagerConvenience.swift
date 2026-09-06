import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming

@testable import MLSProfileRFC9420

// Test-only eager convenience over the D17 two-step handshake API.
//
// The library's public surface is the two-step contract: `committing` /
// `validating` / `joining` return a pending the caller adopts (and persists)
// before transmitting, and `apply(onto:)` composes it onto the live state. Most
// tests only need "advance this group by a commit" to reach a scenario, so these
// wrappers do committing → adopt → apply (and the receive/join twins) in one
// call. They live in the test target, not the library: the shipped API is the
// contract, and the terse form is a test concern. Each body is exactly the
// two-step sequence, so a test using these still exercises the real path.
//
// A test that means to demonstrate the seam itself (SentCommit adoption, a
// declined validation, roster adjudication before join) calls the real API
// directly and does not route through here.
extension MLS.RFC9420.Group {
	struct CommitOutput: Sendable {
		let group: MLS.RFC9420.Group
		let commit: MLS.RFC9420.Message
		let welcome: MLS.RFC9420.Welcome?
	}

	/// Sole-membership eager commit: `committing` then adopt + apply.
	@discardableResult
	mutating func commit(
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
		try commit(
			committerIndex: try soleMembershipIndex(), provider,
			proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension, framing: framing,
			reuseGuard: reuseGuard, paddingLength: paddingLength, psk: psk)
	}

	/// Membership-scoped eager commit: `committing(as:)` then adopt + apply.
	@discardableResult
	mutating func commit(
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
		try commit(
			committerIndex: try membershipIndex(of: leaf), provider,
			proposals: proposalList, proposalStore: proposalStore,
			signingKey: signingKey, randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension, framing: framing,
			reuseGuard: reuseGuard, paddingLength: paddingLength, psk: psk)
	}

	/// The committer-scoped core: `committing(committerIndex:)` then adopt the
	/// consumption and apply the epoch advance, so a commit authored by any local
	/// membership installs every membership's new-epoch keys before returning.
	@discardableResult
	mutating func commit(
		committerIndex: Int,
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
		let transition = try committing(
			committerIndex: committerIndex, provider, proposals: proposalList,
			proposalStore: proposalStore, signingKey: signingKey,
			randomness: randomness, includePath: includePath,
			includeRatchetTreeExtension: includeRatchetTreeExtension,
			framing: framing, reuseGuard: reuseGuard, paddingLength: paddingLength,
			psk: psk)
		self = transition.group
		let sent = transition.takeOutput()
		let message = sent.message
		let welcome = sent.welcome
		self = try sent.takePending().apply(onto: self).group
		return CommitOutput(group: self, commit: message, welcome: welcome)
	}

	/// Mirrors the retired `applyingOrEvicted`: a full self-eviction (every local
	/// membership removed — the delta is empty and terminal) throws
	/// `removedFromGroup`, the pre-two-step signal the eager convenience gave; a
	/// partial eviction or ordinary commit applies normally. The public two-step
	/// `validating(commit:)` surfaces a full eviction as a `membershipRemoved`
	/// effect instead (D17 §5) — this throw is a test-helper convenience.
	private mutating func adopt(
		_ pending: consuming MLS.RFC9420.PendingCommit
	) throws {
		if !pending.removedMemberships.isEmpty,
			pending.removedMemberships == pending.baseMemberships
		{
			throw MLS.RFC9420.GroupError.removedFromGroup
		}
		self = try pending.apply(onto: self).group
	}

	/// Eager public-framed receive: `validating(commit:)` then adopt. Assigns
	/// only on success (a throw leaves `self` untouched).
	mutating func process(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PublicMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws {
		let pending = try validating(
			provider, commit: message, proposals: proposals, psk: psk)
		try adopt(pending)
	}

	/// Non-mutating public-framed receive: the value-returning twin of
	/// `process(commit:)`. Returns the advanced group (throws `removedFromGroup`
	/// on a full self-eviction), leaving the receiver untouched.
	func processing(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PublicMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Group {
		var advanced = self
		try advanced.process(
			provider, commit: message, proposals: proposals, psk: psk)
		return advanced
	}

	/// Eager private-framed receive. Unlike the public overload, a throw here may
	/// still have advanced `self`'s own message-secret ratchet: `validating`
	/// consumes the sender's generation on a successful AEAD open (§9.2), and that
	/// consumption is unrelated to whether the commit goes on to validate. The
	/// `Transition.group` carries that consumption, so it is adopted before the
	/// `.pending` / `.rejected` split.
	mutating func process(
		_ provider: any MLS.CipherSuiteProvider,
		privateCommit message: MLS.RFC9420.PrivateMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws {
		let transition = try validating(
			provider, commit: message, proposals: proposals, psk: psk)
		self = transition.group
		switch transition.takeOutput() {
		case .pending(let pending):
			try adopt(pending)
		case .rejected(let rejection):
			throw rejection.reason
		}
	}

	/// Eager join: `joining` then `apply` in one step. A caller that must
	/// adjudicate the roster (§5.3.1) before trusting it uses `joining` and
	/// inspects `PendingJoin.roster` before calling `apply()`.
	static func join(
		_ provider: any MLS.CipherSuiteProvider,
		welcome: MLS.RFC9420.Welcome,
		credentials: JoinerCredentials,
		externalTree: [MLS.RFC9420.Node?]? = nil,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Group {
		try joining(
			provider, welcome: welcome, credentials: credentials,
			externalTree: externalTree, psk: psk
		).apply().group
	}
}
