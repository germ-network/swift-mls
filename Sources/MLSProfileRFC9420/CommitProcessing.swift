import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath
import SecretBytes

extension MLS.RFC9420 {
	/// A proposal a member has seen by reference this epoch, with the
	/// sender who framed it — an `Update`'s effect depends on who sent it,
	/// so the sender travels with the proposal, not beside it.
	///
	/// The synthesized memberwise init is not `public` (Swift never
	/// promotes it to the type's own access level automatically), and
	/// that is deliberate: the only way to produce a `StoredProposal` from
	/// outside this module is `ProposalStore.insert`, which derives
	/// proposal, sender, and the ref that keys them from one
	/// `VerifiedProposal` — see that type's doc comment.
	public struct StoredProposal: Sendable {
		public var proposal: Proposal
		public var sender: MLS.Sender
		/// The epoch and group the proposal was framed in. Checked against the
		/// committing/processing context at by-reference resolution, so a
		/// stale-epoch (or foreign-group) reference cannot be applied — the
		/// `sender` leaf index only names the right member within `epoch`, and a
		/// later epoch may have reused it.
		public var epoch: UInt64
		public var groupID: Data
	}

	/// A proposal whose framing has been authenticated — the capability
	/// `ProposalStore.insert` requires, so an unverified proposal cannot enter
	/// the store. Minted only two ways, both of which check the framing
	/// signature (and, for public framing, the membership tag) against the
	/// sender's current leaf key: `Group.verifying(proposal:)` for a
	/// `PublicMessage`, and `unprotect` for a `PrivateMessage`. The `init` is
	/// not `public`, so a caller cannot fabricate one from raw bytes — the same
	/// unrepresentable-by-construction technique `StoredProposal` uses.
	public struct VerifiedProposal: Sendable {
		/// The authenticated frame. Deliberately not `public`: exposing the raw
		/// `AuthenticatedContent` would let a caller extract and re-wrap it, and
		/// the read-only accessors below give an app everything it needs to
		/// apply policy. **Do not make this type (or `StoredProposal`)
		/// `Decodable`/`MLSCodable`** — a synthesized `init(from:)` is a public,
		/// byte-level constructor with no verification, which reopens the gate.
		/// To persist a pending proposal, keep the raw `PublicMessage` bytes and
		/// re-run `verify` on restore.
		let content: AuthenticatedContent
		init(verified content: AuthenticatedContent) { self.content = content }

		/// The proposal, for an app inspecting it before it is committed.
		public var proposal: MLS.RFC9420.Proposal? {
			guard case .proposal(let proposal) = content.content.content else {
				return nil
			}
			return proposal
		}
		/// The authenticated framer (a member of the group at `epoch`).
		public var sender: MLS.Sender { content.content.sender }
		/// The epoch whose roster `sender` indexes, and whose key authenticated
		/// the framing — the two are only consistent within this epoch.
		public var epoch: UInt64 { content.content.epoch }
		/// The group the proposal was framed in.
		public var groupID: Data { content.content.groupID }
	}

	/// A commit whose framing has been authenticated — the capability the
	/// commit-processing core (`validatedDelta`) requires, so an unauthenticated
	/// frame cannot be turned into an epoch delta. Minted only two ways, both of
	/// which check the framing signature (and, for public framing, the
	/// membership tag) against the sender's current leaf key: `validating` for a
	/// `PublicMessage`, and `unprotect` for a `PrivateMessage` (D17 §2.1, M-1).
	///
	/// The commit path's analogue of `VerifiedProposal`, and for the same
	/// reason: an `AuthenticatedContent` is plain wire data — publicly
	/// constructible and `MLSDecodable` — so requiring *that type* would not
	/// prove verification. This type's `init` is not `public`, so a caller
	/// cannot fabricate one from raw bytes. **Do not make it
	/// `Decodable`/`MLSCodable`** — a synthesized `init(from:)` is a public,
	/// byte-level constructor with no verification, which reopens the gate.
	struct VerifiedCommit: ~Copyable {
		/// The authenticated frame. Not `public`: exposing the raw
		/// `AuthenticatedContent` would let a caller extract and re-wrap it.
		let content: AuthenticatedContent
		init(verified content: AuthenticatedContent) { self.content = content }
	}

	/// By-reference proposals, keyed by `ProposalRef`.
	///
	/// **The store is a trust boundary, and `insert` is its gate.**
	/// `processing` never recomputes a `ProposalRef` against its stored
	/// proposal, and never re-verifies a stored `sender` — it does not need
	/// to, because `insert` accepts only a `VerifiedProposal`, whose framing
	/// signature was already checked against the sender's current leaf key by
	/// `Group.verifying(proposal:)` or `unprotect`. A `StoredProposal`'s `sender`
	/// is therefore the authenticated framer, not a claimed one.
	///
	/// Two things this boundary deliberately does not cover: epoch freshness
	/// (a caller must not store a stale proposal as fresh — retention is the
	/// caller's job), and §5.3.1 credential/identity validation (that a
	/// sender's credential legitimately binds its signature key) — RFC 9420's
	/// Authentication Service, an application responsibility, not the store's.
	///
	/// A `struct` wrapping the dictionary rather than a plain
	/// `[HashReference: StoredProposal]` typealias: `insert` is the only way
	/// in, and it derives the ref, the proposal, and the sender from the SAME
	/// `VerifiedProposal` — so a ref that doesn't match the proposal stored
	/// under it, or a sender that doesn't match how the proposal was framed,
	/// is unrepresentable. The old typealias let a caller assemble those three
	/// independently, which is what made a mismatched (or unverified)
	/// substitution constructible.
	public struct ProposalStore: Sendable {
		private var entries: [MLS.HashReference: StoredProposal] = [:]

		// swift-format-ignore: UseSynthesizedInitializer -- the synthesized
		// memberwise init is `internal` (its access level follows `entries`,
		// which must stay `private`), which breaks every cross-file default
		// argument of `proposalStore: ProposalStore = ProposalStore()`. This
		// explicit `public init()` is the only way to keep `entries` private
		// while still letting `insert` be the sole way to populate a store.
		public init() {}

		/// Refs and stores an already framing-verified proposal. A
		/// `VerifiedProposal` (from `Group.verifying(proposal:)` or `unprotect`)
		/// carries `.proposal` content by construction; the guard keeps
		/// `notAProposal` as a defensive invariant rather than a live path.
		@discardableResult
		public mutating func insert(
			_ verified: VerifiedProposal, _ provider: any MLS.CipherSuiteProvider
		) throws -> MLS.HashReference {
			let content = verified.content
			guard case .proposal(let proposal) = content.content.content else {
				throw MLS.RFC9420.GroupError.notAProposal
			}
			let ref = try proposalRef(provider, content)
			entries[ref] = StoredProposal(
				proposal: proposal, sender: content.content.sender,
				epoch: content.content.epoch, groupID: content.content.groupID)
			return ref
		}

		public subscript(_ ref: MLS.HashReference) -> StoredProposal? {
			entries[ref]
		}

		public var keys: Dictionary<MLS.HashReference, StoredProposal>.Keys {
			entries.keys
		}

		public var isEmpty: Bool { entries.isEmpty }
		public var count: Int { entries.count }
	}

	/// `ProposalRef = RefHash("MLS 1.0 Proposal Reference",
	/// Encode(AuthenticatedContent))` — over the *framed and authenticated*
	/// proposal, not the bare `Proposal`, which is why a sender storing
	/// proposals must keep the `AuthenticatedContent` it received.
	public static func proposalRef(
		_ provider: any MLS.CipherSuiteProvider, _ content: AuthenticatedContent
	) throws -> MLS.HashReference {
		try MLS.HashReference.compute(
			provider, label: "MLS 1.0 Proposal Reference",
			value: try content.mlsEncoded())
	}
}

extension MLS.RFC9420.Group {
	/// A by-reference proposal must have been framed in the group and epoch of
	/// the commit referencing it. Proposals are epoch-scoped (RFC 9420 §12.4:
	/// a proposal resent in a later epoch is updated to reflect it), and a
	/// `StoredProposal`'s `sender` leaf index only names the right member within
	/// its own epoch — a later epoch may have reused that leaf. Checked at
	/// resolution so a stale (or foreign-group) reference can't be applied even
	/// from a store a caller carried across epochs.
	func requireCurrentContext(_ stored: MLS.RFC9420.StoredProposal) throws {
		guard stored.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		guard stored.epoch == context.epoch else {
			throw MLS.RFC9420.GroupError.referencedProposalWrongEpoch(
				expected: context.epoch, actual: stored.epoch)
		}
	}

	/// Authenticate a `PublicMessage`-framed **proposal** before it enters a
	/// `ProposalStore` — the proposal-side counterpart to
	/// `validating(commit:)`, which is `verifyPublic`'s only other caller. RFC 9420
	/// §6.1: "Recipients of an MLSMessage MUST verify the signature"; §6.2: a
	/// `PublicMessage` recipient "MUST check membership_tag and MUST check that
	/// the FramedContentAuthData is valid." Mirrors the commit path's framing
	/// checks — current epoch, group id, a `.member` sender at a non-blank
	/// leaf, and the framing signature + membership tag under that leaf's
	/// `signature_key`. A private-framed proposal is authenticated by
	/// `unprotect` instead; both mint the `VerifiedProposal` the store
	/// requires, so an unverified proposal can never reach `insert`.
	///
	/// This authenticates the *framing* only — that the message was signed by
	/// the current occupant of the sender's leaf. Validating that the sender's
	/// credential legitimately binds that signature key (and is a valid
	/// successor when a credential is replaced) is RFC 9420 §5.3.1's
	/// Authentication Service: an application responsibility, outside this gate.
	public func verifying(
		_ provider: any MLS.CipherSuiteProvider,
		proposal message: MLS.RFC9420.PublicMessage
	) throws -> MLS.RFC9420.VerifiedProposal {
		guard message.content.epoch == context.epoch else {
			throw MLS.RFC9420.GroupError.wrongEpoch(
				expected: context.epoch, actual: message.content.epoch)
		}
		guard message.content.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		guard case .proposal = message.content.content else {
			throw MLS.RFC9420.GroupError.notAProposal
		}
		guard case .member(let senderIndex) = message.content.sender else {
			throw MLS.RFC9420.GroupError.unsupportedSender
		}
		guard let senderLeafRecord = tree.leaf(at: senderIndex) else {
			throw MLS.RFC9420.GroupError.blankSenderLeaf
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderLeafRecord.encoded)
		guard
			try MLS.RFC9420.verifyPublic(
				provider, message: message, groupContext: context,
				verificationKey: senderLeaf.signatureKey,
				membershipKey: epoch.membershipKey)
		else {
			throw MLS.CryptoError.signatureVerificationFailed
		}
		return MLS.RFC9420.VerifiedProposal(
			verified: MLS.RFC9420.AuthenticatedContent(
				wireFormat: .publicMessage, content: message.content,
				auth: message.auth))
	}

	/// Framing verification of a `PrivateMessage`-framed proposal (D17): the
	/// private-framing counterpart of `verifying(proposal: PublicMessage)`.
	/// Decrypting the message spends the sender's handshake generation (§9.2), so
	/// this returns a `Transition`: `group` is the post-consumption state to
	/// **adopt** (the consumption lives only there), the `output` is the
	/// `VerifiedProposal` ready for `ProposalStore.insert`. Unlike a commit a
	/// proposal has no deeper validity step here (§12.1 runs at commit time), so
	/// there is no rejected arm — a non-proposal content type is refused on the
	/// cleartext header before decrypting, and once the frame opens this never
	/// throws.
	public func verifying(
		_ provider: any MLS.CipherSuiteProvider,
		proposal message: MLS.RFC9420.PrivateMessage
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.VerifiedProposal> {
		guard message.contentType == .proposal else {
			throw MLS.RFC9420.GroupError.wrongContentType(message.contentType)
		}
		var group = self
		let opened = try group.openPrivate(provider, message)
		group.commitConsumption(opened.pending)
		return MLS.RFC9420.Transition(
			group: group,
			output: MLS.RFC9420.VerifiedProposal(verified: opened.authenticated))
	}

	/// D17 step 1 (validate) for a `PublicMessage`-framed commit: run RFC 9420
	/// §12.4.2's first framing checks — epoch match, then the membership MAC and
	/// FramedContent signature (§12.4.2's first three bullets) — and derive the
	/// epoch DELTA WITHOUT advancing. Public framing consumes no key, so nothing
	/// is persisted at validation (D17 §1.1). Adjudicate `pending.effects`, then
	/// `pending.apply(onto:)` the group you kept operating on.
	///
	/// **Never mutates `self`** — it returns a `PendingCommit`, and every state
	/// change is deferred to `apply(onto:)`, so a failure anywhere below leaves
	/// the caller's group exactly as it was (§12.4.2: "if the above checks are
	/// successful, consider the new GroupContext as the current state").
	///
	/// `psk` resolves *external* PSK ids. Resumption ids are resolved from
	/// this group's own retained per-epoch history and never reach the
	/// closure.
	public func validating(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PublicMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.PendingCommit {
		guard message.content.epoch == context.epoch else {
			throw MLS.RFC9420.GroupError.wrongEpoch(
				expected: context.epoch, actual: message.content.epoch)
		}
		guard message.content.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		// Cheapest framing rejection, before any crypto -- also keeps this
		// error ahead of `verifyPublic`, which refuses application content
		// in a PublicMessage with a different error.
		guard case .commit = message.content.content else {
			throw MLS.RFC9420.GroupError.notACommit
		}
		guard case .member(let senderIndex) = message.content.sender else {
			throw MLS.RFC9420.GroupError.unsupportedSender
		}
		guard let senderLeafRecord = tree.leaf(at: senderIndex) else {
			throw MLS.RFC9420.GroupError.blankSenderLeaf
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderLeafRecord.encoded)
		guard
			try MLS.RFC9420.verifyPublic(
				provider, message: message, groupContext: context,
				verificationKey: senderLeaf.signatureKey,
				membershipKey: epoch.membershipKey)
		else {
			throw MLS.CryptoError.signatureVerificationFailed
		}
		return try validatedDelta(
			provider,
			commit: MLS.RFC9420.VerifiedCommit(
				verified: MLS.RFC9420.AuthenticatedContent(
					wireFormat: .publicMessage, content: message.content,
					auth: message.auth)),
			proposals: proposals, psk: psk)
	}

	/// D17 step 1 (validate) for a `PrivateMessage`-framed commit. Decrypting the
	/// message spends the sender's handshake generation the moment its AEAD opens
	/// (RFC 9420 §9.2), so this is a `Transition`: `group` is the post-consumption
	/// live state — **adopt it** (apply onto it or a successor, never onto the
	/// pre-call group; the consumption lives only here), and the `output` is a
	/// `CommitValidation`.
	///
	/// The entry **throws only when nothing was consumed** — a non-commit content
	/// type (checked on the cleartext header before decrypting), a failed AEAD or
	/// signature, a replayed or out-of-window generation. Once the frame opens it
	/// never throws: a valid commit is `.pending` (adjudicate, then `apply`), an
	/// authentic-but-invalid one is `.rejected` — either way the consumption is
	/// kept in `group`, so a replay is rejected and §9.2's delete-once-used MUST
	/// holds even when the commit itself is rejected.
	public func validating(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PrivateMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Transition<MLS.RFC9420.CommitValidation> {
		// Refuse a non-commit before decrypting (content type is in the cleartext
		// header), so this throws with nothing consumed.
		guard message.contentType == .commit else {
			throw MLS.RFC9420.GroupError.wrongContentType(message.contentType)
		}
		var group = self
		let opened = try group.openPrivate(provider, message)
		// AEAD opened: the generation is spent. Commit it now so it survives every
		// arm below, and never throw past this point.
		group.commitConsumption(opened.pending)
		let output: MLS.RFC9420.CommitValidation
		do {
			let pending = try group.validatedDelta(
				provider,
				commit: MLS.RFC9420.VerifiedCommit(verified: opened.authenticated),
				proposals: proposals, psk: psk)
			output = .pending(pending)
		} catch {
			output = .rejected(
				MLS.RFC9420.CommitRejection(
					sender: opened.senderLeaf, epoch: opened.epoch,
					reason: error))
		}
		return MLS.RFC9420.Transition(group: group, output: output)
	}

	/// The commit-processing core, on an *already authenticated* frame —
	/// §12.4.2 from the proposal-validation bullet onward (the framing signature,
	/// its preceding bullet, is already checked by the caller) — producing the
	/// D17 epoch **delta**
	/// (`PendingCommit`) rather than a successor `Group`: it validates and
	/// derives the successor epoch, reading no message-secret state, so
	/// `apply(onto:)` can compose it onto a live group that kept operating
	/// (D17 §2/§4). A `PublicMessage`-framed commit reaches here after its
	/// membership MAC and framing signature are checked; a `PrivateMessage`
	/// one (`unprotect`) after its AEAD and signature are checked. Either way
	/// the frame is trusted on entry, and the epoch/group/member/blank-leaf
	/// checks below still run because the private path does not repeat them.
	///
	/// Assemble the §5.3.1 membership/credential effects a commit had (slice 4b),
	/// shared by receive (`validatedDelta`) and send (`committing`) so both report
	/// the same effects. `epochAdvanced` is `nil` for a full eviction (no member
	/// could derive the new epoch). `committerChange` is the committer's own
	/// path-leaf refresh (`nil` for a pathless commit). A `removed` leaf that
	/// names a local membership also emits `membershipRemoved`.
	func commitMembershipEffects(
		epochAdvanced: MLS.RFC9420.CommitEffect?,
		added: [(leaf: MLS.LeafIndex, presentation: MLS.RFC9420.CredentialPresentation)],
		updateChanges: [(
			leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
			new: MLS.RFC9420.CredentialPresentation
		)],
		committerChange: (
			leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
			new: MLS.RFC9420.CredentialPresentation
		)?,
		removedLeaves: [MLS.LeafIndex],
		localMembershipLeaves: Set<MLS.LeafIndex>,
		appDataUpdates: [MLS.Extensions.AppDataUpdate]
	) -> MLS.RFC9420.CommitEffects {
		// Emitted in §12.3 application order — update, then remove, then add — so
		// the stream is replayable against a leaf-indexed roster: an Add fills the
		// leftmost blank, which a Remove in the SAME commit may have just freed, so
		// `removed` MUST precede `added` for that leaf, or a replay would delete the
		// member it just added.
		var events: [MLS.RFC9420.CommitEffect] = []
		if let epochAdvanced { events.append(epochAdvanced) }
		for change in updateChanges + (committerChange.map { [$0] } ?? []) {
			events.append(
				change.old == change.new
					? .updated(leaf: change.leaf)
					: .credentialReplaced(
						leaf: change.leaf, old: change.old, new: change.new)
			)
		}
		for leaf in removedLeaves {
			events.append(.removed(leaf: leaf))
			if localMembershipLeaves.contains(leaf) {
				events.append(.membershipRemoved(leaf: leaf))
			}
		}
		for entry in added {
			events.append(.added(leaf: entry.leaf, presentation: entry.presentation))
		}
		// App-data effects follow the membership stream, in proposal-list order —
		// they touch no roster slot, so they carry no §12.3 replay ordering.
		for update in appDataUpdates {
			events.append(.appDataUpdate(update))
		}
		return MLS.RFC9420.CommitEffects(events)
	}

	/// Internal: the public entries are the `validating(commit:)` overloads,
	/// which compose the returned delta onto the live group via `apply(onto:)`.
	/// Gated on `VerifiedCommit`, not a raw `AuthenticatedContent`, so it cannot
	/// be reached with an unauthenticated frame (D17 §2.1, M-1).
	func validatedDelta(
		_ provider: any MLS.CipherSuiteProvider,
		commit verified: consuming MLS.RFC9420.VerifiedCommit,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.PendingCommit {
		let message = verified.content
		// slice 4a: the delta now installs path keys per local membership — each
		// decaps the commit's path against its own held keys (see the per-
		// membership loop below), and `apply` installs each. The N > 1 fence is
		// gone; `commit_secret` agreement across memberships guards a divergent
		// decap.
		guard message.content.epoch == context.epoch else {
			throw MLS.RFC9420.GroupError.wrongEpoch(
				expected: context.epoch, actual: message.content.epoch)
		}
		guard message.content.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		guard case .commit(let commit) = message.content.content else {
			throw MLS.RFC9420.GroupError.notACommit
		}
		guard case .member(let senderIndex) = message.content.sender else {
			throw MLS.RFC9420.GroupError.unsupportedSender
		}
		guard let senderLeafRecord = tree.leaf(at: senderIndex) else {
			throw MLS.RFC9420.GroupError.blankSenderLeaf
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderLeafRecord.encoded)

		// 6: resolve the proposal list in list order. An unresolvable
		// reference is an error, never a skip -- applying a commit with a
		// shorter list than its sender used would silently diverge state.
		var resolved: [MLS.RFC9420.StoredProposal] = []
		for entry in commit.proposals {
			switch entry {
			case .proposal(let proposal):
				// Inline (by-value): framed in this commit, so this epoch.
				resolved.append(
					.init(
						proposal: proposal, sender: message.content.sender,
						epoch: context.epoch, groupID: context.groupID))
			case .reference(let ref):
				guard let stored = proposals[ref] else {
					throw MLS.RFC9420.GroupError.unknownProposalReference
				}
				try requireCurrentContext(stored)
				resolved.append(stored)
			}
		}

		// §12.2 list validation and §12.1 per-proposal validity, over the
		// resolved list -- "decide what's valid to apply", the half phase
		// 5 explicitly left here. Runs against the *provisional*
		// extensions per §12.3 ("The new extensions MUST be used when
		// evaluating other proposals in this list"), so GCE is folded in
		// before anything is judged. The reinit/branch PSK-usage rejection
		// stays `resolvePsk`'s (`unsupportedResumptionUsage`, at the
		// availability step just below) -- this pass checks only what
		// §12.1.4 adds, the nonce length.
		var provisionalExtensions = context.extensions
		for stored in resolved {
			if case .groupContextExtensions(let extensions) = stored.proposal {
				provisionalExtensions = extensions
			}
		}
		let updateChanges = try validateProposalList(
			resolved, committer: senderIndex,
			provisionalExtensions: provisionalExtensions, provider: provider)

		// §12.4.2 makes PSK *availability* its own step, five bullets
		// before the tree is touched: "Verify that all PreSharedKey
		// proposals in the proposals vector are available." Resolved here,
		// in RFC order, and reused at the derivation step below -- so a
		// commit naming a PSK we don't hold dies before any tree work.
		let pskIDs = resolved.compactMap { stored -> MLS.RFC9420.PreSharedKeyIdentifier? in
			guard case .preSharedKey(let id) = stored.proposal else { return nil }
			return id
		}
		let resolvedPsks = try pskIDs.map { id -> (encodedID: Data, psk: SecretBytes) in
			guard let secret = try resolvePsk(id, psk) else {
				throw MLS.RFC9420.GroupError.unresolvedPreSharedKey
			}
			return (try id.mlsEncoded(), secret)
		}

		// 7: path-required. **The RFC contradicts itself here.** §12.4's
		// pseudocode and §17.4's "Path Required" registry column both give
		// four types -- update, remove, external_init,
		// group_context_extensions -- while §12.4.2's own receive-side
		// bullet names only "any Update or Remove proposals, or if it's
		// empty". No erratum is filed. The four-type set wins: it is the
		// normative registry plus the algorithm, and it is strictly safer.
		// Do not "fix" this to two types against §12.4.2 alone -- that
		// would accept a pathless GroupContextExtensions commit §12.4
		// forbids.
		let pathRequired =
			resolved.isEmpty
			|| resolved.contains { stored in
				switch stored.proposal {
				case .update, .remove, .externalInit, .groupContextExtensions: true
				// app_data_update is Path Required N (§7.2.1) — same class as PSK.
				case .add, .preSharedKey, .reInit, .appDataUpdate: false
				}
			}
		if pathRequired && commit.path == nil {
			throw MLS.RFC9420.GroupError.pathRequired
		}

		// A ReInit-bearing commit is rejected rather than applied, because
		// the alternative here is uniquely bad: it would *succeed*.
		//
		// RFC 9420 §12.4.2: "If the Commit included a ReInit proposal, the
		// client MUST NOT use the group to send messages anymore. Instead,
		// it MUST wait for a Welcome message from the committer meeting
		// the requirements of Section 11.2." ReInit is deferred
		// project-wide, so there is no state to transition into and no
		// Welcome path to wait on.
		//
		// This rejection lives here, not in `validateProposalList`,
		// because ReInit is the one deferred type that does not perturb
		// the key schedule: processing it would silently return a
		// live-looking `Group` the caller must not send from -- the one
		// case where "unimplemented" and "succeeded" are indistinguishable
		// to a caller. Every §12.2 list-validity rule that CAN be caught
		// in `validateProposalList` is (ExternalInit included -- it is
		// rejected there, not left to "die at the confirmation tag", which
		// a malicious committer computes just as the receiver does).
		if resolved.contains(where: {
			if case .reInit = $0.proposal { true } else { false }
		}) {
			throw MLS.RFC9420.GroupError.unsupportedReInit
		}

		// 8: apply proposals in §12.3's order, NOT list order.
		//
		// GroupContextExtensions is computed first and separately, because
		// §12.3 says "The new extensions MUST be used when evaluating
		// other proposals in this list" -- its output is *input* to
		// everything after it, not merely earlier in sequence.
		// `validateProposalList` above already judged every proposal
		// against these provisional extensions; this hoisted copy is what
		// made that possible.
		//
		// GCE is routed here rather than through `RatchetTree.apply`
		// deliberately: it changes `GroupContext.extensions`, which a
		// `RatchetTree` does not have and must not learn about. See
		// `TreeEditError.notATreeEditingProposal`'s own doc comment --
		// passing one to `apply` is a caller error by design, exactly as
		// for preSharedKey/reInit/externalInit.

		let applied = try applyProposals(resolved, committer: senderIndex)
		var provisionalTree = applied.tree
		let blankedNodes = applied.blankedNodes
		let addedLeaves = applied.addedLeaves

		// Slice 4b eviction: a commit that removes one of THIS device's local
		// memberships evicts it rather than throwing (4a's `removedFromGroup`). A
		// removed member is framing-authenticated (signature + MAC passed above)
		// but cannot derive the new epoch's key schedule — the commit's fresh path
		// entropy is not delivered to a removed member (RFC 9420 §3.2) — so it
		// cannot verify the confirmation tag; §12.4.2 says such a client SHOULD
		// promptly delete its state. So partition the local memberships:
		//   - FULL eviction (no survivor): the delta is EMPTY and terminal — no
		//     member here can derive the new epoch. Package the `membershipRemoved`
		//     effects (the private-frame consumption is already in `self`); `apply`
		//     returns the group unchanged and the app tears down.
		//   - PARTIAL eviction (≥1 survivor): a survivor derives the new epoch
		//     normally; the delta drops the removed memberships and advances.
		// Precedence: PSK availability and the ReInit rejection run above (RFC
		// 9420 §12.4.2 order), so a full-eviction commit that ALSO names a PSK this
		// member cannot resolve is rejected with that error rather than packaged as
		// an eviction — an edge, since a removed member has no use for the PSK.
		let removedLeaves = resolved.compactMap { stored -> MLS.LeafIndex? in
			if case .remove(let leaf) = stored.proposal { return leaf }
			return nil
		}
		let localLeaves = Set(memberships.map(\.leafIndex))
		let removedLocal = localLeaves.intersection(removedLeaves)
		let survivingMemberships = memberships.filter {
			!removedLocal.contains($0.leafIndex)
		}

		if !removedLocal.isEmpty, survivingMemberships.isEmpty {
			// FULL eviction — framing-authenticated, not tag-confirmed. Empty,
			// terminal delta: no path validation, no decap, no epoch advance. The
			// advance fields below are placeholders `apply` never reads (it returns
			// at the terminal branch): the current-epoch store and resumption PSK
			// are always retained, but the exporter tree can be legitimately absent
			// on a migration-restored group (predating the snapshot's exporter
			// key), so fall back rather than requiring state the terminal delta
			// does not use. Only `removed`/`membershipRemoved` are reported here —
			// any add/update in the same commit belongs to an epoch this device
			// never enters, and is not tag-confirmed.
			guard let store = core.messageSecrets[context.epoch],
				let resumption = core.resumptionPsks[context.epoch]
			else {
				throw MLS.RFC9420.GroupError.messageFromUnretainedEpoch(
					epoch: context.epoch)
			}
			let exporter =
				core.exporterTrees[context.epoch]
				?? MLS.Extensions.ExporterTree(restoringFrontier: [:])
			let effects = commitMembershipEffects(
				epochAdvanced: nil, added: [], updateChanges: [],
				committerChange: nil, removedLeaves: removedLeaves,
				localMembershipLeaves: localLeaves, appDataUpdates: [])
			return MLS.RFC9420.PendingCommit(
				effects: effects, base: context, baseMemberships: localLeaves,
				newContext: context, newTree: tree, newEpoch: epoch,
				newSecretKeysByLeaf: [:],
				newInterimTranscriptHash: interimTranscriptHash,
				newMessageStore: store, newExporterTree: exporter,
				newResumptionPsk: resumption, removedMemberships: removedLocal)
		}

		// The committer's own path-leaf refresh, for the credential effects
		// (set inside the path block below once `path.leafNode` is validated).
		var committerChange:
			(
				leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
				new: MLS.RFC9420.CredentialPresentation
			)?

		// 9: merge the UpdatePath (each SURVIVING membership decaps its own path),
		// or take the pathless commit_secret. `newSecretKeysByLeaf` is the per-
		// membership install the D17 delta carries.
		var newSecretKeysByLeaf: [MLS.LeafIndex: [UInt32: MLS.HpkeSecretKey]] = [:]
		let commitSecret: Data

		if let path = commit.path {
			// 9a: §12.4.2's path bullet is two sentences, and both bind:
			// "Validate the LeafNode as specified in Section 7.3. The
			// leaf_node_source field MUST be set to commit."
			//
			// §7.3 splits into an authenticity half (the leaf's own
			// signature, over a TBS that binds `(group_id, leaf_index)`
			// for a commit-sourced leaf) and a policy half (lifetime,
			// capabilities, required_capabilities). Both halves run here
			// -- this leaf is the committer's *new* identity binding, and
			// installing it unverified means every later message from
			// that member verifies against a key nothing ever proved they
			// hold. (An earlier revision ran only the authenticity half
			// and deferred policy "to phase 6"; the stage-5 review found
			// the deferral had silently outlived its phase.)
			guard case .commit = path.leafNode.source else {
				throw MLS.RFC9420.GroupError.updatePathLeafNotCommitSource
			}
			try path.leafNode.verifySignature(
				provider,
				placement: .inGroup(
					groupID: context.groupID, leafIndex: senderIndex))
			var pathMemberCapabilities: [MLS.RFC9420.Capabilities] = []
			var pathMemberCredentialTypes: Set<MLS.RFC9420.CredentialType> = []
			for (index, record) in provisionalTree.nonBlankLeaves()
			where index != senderIndex {
				let leaf = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
				pathMemberCapabilities.append(leaf.capabilities)
				pathMemberCredentialTypes.insert(leaf.credential.credentialType)
			}
			try path.leafNode.validatePolicy(
				.commitUpdatePath,
				groupRequirements:
					try provisionalExtensions
					.requiredCapabilities(),
				memberCredentialTypes: pathMemberCredentialTypes,
				memberCapabilities: pathMemberCapabilities)
			// §12.4.2's own bullet, distinct from the whole-tree freshness
			// sweep below so each is separately testable -- a crafted leaf
			// reusing the committer's key necessarily also trips the
			// sweep, which is what made the earlier shared error case
			// mutation-invisible.
			guard path.leafNode.encryptionKey != senderLeaf.encryptionKey else {
				throw MLS.RFC9420.GroupError.updatePathReusesCommitterKey
			}

			// 9c: "Verify that none of the public keys in the UpdatePath
			// appear in any node of the new ratchet tree." "New" means
			// after §12.3's proposals are applied but BEFORE this path is
			// merged -- both halves matter. Against the pre-proposal tree
			// this misses a key a Remove just freed; after the merge it is
			// vacuous, since merging is what puts these keys in the tree.
			try checkUpdatePathKeysAreFresh(path, in: provisionalTree)

			// The committer's own leaf is refreshed by its path; report the
			// presentation change (slice 4b). Usually an encryption-key-only
			// `updated`, but a committer MAY carry a new credential/key here.
			committerChange = (
				leaf: senderIndex,
				old: MLS.RFC9420.CredentialPresentation(
					credential: senderLeaf.credential,
					signatureKey: senderLeaf.signatureKey),
				new: MLS.RFC9420.CredentialPresentation(
					credential: path.leafNode.credential,
					signatureKey: path.leafNode.signatureKey)
			)

			// 9d
			try provisionalTree.applyUpdatePath(
				sender: senderIndex, leaf: try path.leafNode.record,
				pathNodes: path.nodes.map(\.pathNode), provider)

			// 9e: the provisional GroupContext the sender encrypted path
			// secrets against -- new epoch, POST-merge tree hash, OLD
			// confirmed transcript hash, new extensions. Every one of those
			// four is a distinct way to get this wrong and each produces a
			// silent decap failure rather than a useful error.
			let provisionalContext = MLS.RFC9420.GroupContext(
				version: context.version, cipherSuite: context.cipherSuite,
				groupID: context.groupID, epoch: context.epoch + 1,
				treeHash: try provisionalTree.treeHash(provider),
				confirmedTranscriptHash: context.confirmedTranscriptHash,
				extensions: provisionalExtensions)

			// 10 + 9f + 9g, per local membership: each prunes and decaps against
			// its OWN held keys and pending self-Update (the pruning-before-decap
			// ordering, the committer-not-proposer Update seeding, and the decap
			// are all in `installKeysForMembership`). Every membership recovers the
			// same whole-group `commit_secret` — the path secret converges at the
			// root — so a divergence means the memberships decapped inconsistent
			// path material and the commit is rejected, never applied.
			let provisionalContextEncoded = try provisionalContext.mlsEncoded()
			var agreedCommitSecret: Data?
			for membership in survivingMemberships {
				let (keys, derived) = try installKeysForMembership(
					membership, path: path, provisionalTree: provisionalTree,
					senderIndex: senderIndex,
					provisionalContextEncoded: provisionalContextEncoded,
					blankedNodes: blankedNodes, addedLeaves: addedLeaves,
					provider)
				if let agreed = agreedCommitSecret {
					guard derived == agreed else {
						throw MLS.RFC9420.GroupError.divergentCommitSecret
					}
				} else {
					agreedCommitSecret = derived
				}
				newSecretKeysByLeaf[membership.leafIndex] = keys
			}
			// The loop always runs (`survivingMemberships` is non-empty here — a
			// full eviction returned at the terminal branch above), so agreement is
			// set. Guard rather than fall back to the all-zero pathless secret,
			// which would be wrong for a path commit.
			guard let agreed = agreedCommitSecret else {
				throw MLS.RFC9420.GroupError.membershipMismatch
			}
			commitSecret = agreed
		} else {
			// S23: §12.4.2 -- a commit without a path contributes an
			// all-zero commit_secret of the hash's own length, not an
			// absent one. No decap: each membership only sheds keys for the
			// nodes this commit blanked, off its own path.
			commitSecret = Data(repeating: 0, count: provider.hashSize)
			for membership in survivingMemberships {
				newSecretKeysByLeaf[membership.leafIndex] = prunedSecretKeys(
					heldSecretKeys: membership.secretKeys,
					ownLeaf: membership.leafIndex, blankedNodes: blankedNodes,
					senderIndex: nil, leafCount: provisionalTree.leafCount)
			}
		}

		// 11. The wire format is part of §8.2's confirmed-transcript-hash
		// input, and a private-framed commit carries `.privateMessage` --
		// so this must be the frame's actual format, not a constant, or a
		// private commit's transcript (and thus its confirmation tag)
		// diverges from its sender's.
		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: message.wireFormat,
			encodedContent: try message.content.mlsEncoded(),
			encodedGroupContext: nil)
		guard let signature = message.auth.signature else {
			throw MLS.FramingError.signatureRequired
		}
		var signatureWriter = MLS.Writer()
		try signatureWriter.encode(signature)
		let confirmedTranscriptHash = try MLS.Framing.confirmedTranscriptHash(
			provider, interimBefore: interimTranscriptHash,
			input: try signedContent.confirmedTranscriptHashInput(
				encodedSignature: Data(signatureWriter.bytes)))

		// 12
		let newContext = MLS.RFC9420.GroupContext(
			version: context.version, cipherSuite: context.cipherSuite,
			groupID: context.groupID, epoch: context.epoch + 1,
			treeHash: try provisionalTree.treeHash(provider),
			confirmedTranscriptHash: confirmedTranscriptHash,
			extensions: provisionalExtensions)

		// 13-14
		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: resolvedPsks)
		let newEpoch = try MLS.KeySchedule.advance(
			provider, initSecret: epoch.initSecret, commitSecret: commitSecret,
			pskSecret: pskSecret, groupContext: try newContext.mlsEncoded())

		// 15: constant-time, via MLS.ConfirmationTag's own ==.
		guard let confirmationTag = message.auth.confirmationTag else {
			throw MLS.FramingError.confirmationTagMissing
		}
		let expectedTag = try MLS.Framing.confirmationTag(
			provider, confirmationKey: newEpoch.confirmationKey,
			confirmedTranscriptHash: confirmedTranscriptHash)
		guard expectedTag == confirmationTag else {
			throw MLS.RFC9420.GroupError.confirmationTagMismatch
		}

		// Build the epoch DELTA (D17 §2). The new-epoch message store and
		// exporter tree are built standalone from the NEW epoch's inputs; the
		// old-epoch stores and resumption PSKs are deliberately NOT captured —
		// `apply(onto:)` takes them from the live group (D17 §4), which is what
		// keeps consumption made while the commit was pending from being rolled
		// back. `pendingUpdates` clearing likewise happens at apply.
		let (newStore, newExporter) = try Self.makeEpochMessageState(
			context: newContext, senderDataSecret: newEpoch.senderDataSecret,
			encryptionSecret: newEpoch.encryptionSecret,
			applicationExportSecret: newEpoch.applicationExportSecret,
			tree: provisionalTree, provider)
		let newInterim = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmedTranscriptHash,
			confirmationTag: confirmationTag)
		let effects = commitMembershipEffects(
			epochAdvanced: .epochAdvanced(
				from: context.epoch, to: newContext.epoch, committer: senderIndex),
			added: applied.added, updateChanges: updateChanges,
			committerChange: committerChange, removedLeaves: removedLeaves,
			localMembershipLeaves: localLeaves,
			appDataUpdates: resolved.compactMap {
				if case .appDataUpdate(let update) = $0.proposal {
					update
				} else {
					nil
				}
			})
		return MLS.RFC9420.PendingCommit(
			effects: effects, base: context, baseMemberships: localLeaves,
			newContext: newContext, newTree: provisionalTree,
			newEpoch: MLS.RFC9420.Group.EpochSecrets(retaining: newEpoch),
			newSecretKeysByLeaf: newSecretKeysByLeaf,
			newInterimTranscriptHash: newInterim,
			newMessageStore: newStore, newExporterTree: newExporter,
			newResumptionPsk: newEpoch.resumptionPsk,
			removedMemberships: removedLocal)
	}

	/// What `applyProposals` hands back: the provisional tree plus the two
	/// index sets that feed key pruning (`blankedNodes`) and copath
	/// exclusion (`addedLeaves`).
	struct AppliedProposals {
		var tree: MLS.TreeKEM.RatchetTree
		var blankedNodes: Set<UInt32>
		/// Added members in application order, each with the presentation its
		/// KeyPackage carried (slice 4b's `.added` effect).
		var added: [(leaf: MLS.LeafIndex, presentation: MLS.RFC9420.CredentialPresentation)]
		/// The leaves an Add filled — for copath exclusion at decap.
		var addedLeaves: Set<MLS.LeafIndex> { Set(added.map(\.leaf)) }
	}

	/// The §12.3 application pass — update, then remove, then add, in
	/// §12.3's order, plus §12.2's closing post-application uniqueness
	/// sweep. Extracted so `processing` (receive) and `committing`
	/// (construct) run the *same* code: the two sides must land on
	/// byte-identical trees and on the same `blankedNodes`/`addedLeaves`
	/// sets, and a re-implementation that diverged even slightly would
	/// silently fork the group.
	func applyProposals(
		_ resolved: [MLS.RFC9420.StoredProposal], committer: MLS.LeafIndex
	) throws -> AppliedProposals {
		var provisionalTree = tree
		var blankedNodes: Set<UInt32> = []
		var added:
			[(leaf: MLS.LeafIndex, presentation: MLS.RFC9420.CredentialPresentation)] =
				[]

		for stored in resolved {
			guard case .update = stored.proposal else { continue }
			guard case .member(let updateSender) = stored.sender else {
				throw MLS.RFC9420.GroupError.unsupportedSender
			}
			// The same membership check the Remove path below performs, and
			// for a sharper reason. RFC 9420 §12.1.2 defines applying an
			// Update as "Replace the sender's LeafNode with the one
			// contained in the Update proposal" -- if the sender occupies no
			// leaf there is nothing to replace and the operation is
			// undefined. Historically this guard was also the only thing
			// between an out-of-range store-supplied sender and a process
			// abort (`setLeaf` grew the array unboundedly); the tree's
			// setters now throw on out-of-range indices, so this is
			// defense-in-depth with the spec-shaped error rather than the
			// sole line of defense.
			guard provisionalTree.leaf(at: updateSender) != nil else {
				throw MLS.RFC9420.GroupError.updateFromNonMember(leaf: updateSender)
			}
			blankedNodes.formUnion(
				MLS.TreeMath.directPath(
					from: 2 * updateSender.value,
					leafCount: provisionalTree.leafCount
				).map(\.path))
			try provisionalTree.apply(stored.proposal, sender: updateSender)
		}

		for stored in resolved {
			guard case .remove(let removed) = stored.proposal else { continue }
			// The peer-derived half of remove validation: mls-rs errors
			// (`RemovingNonExistingMember`) rather than blanking an
			// already-blank leaf. The tree's own primitives stay
			// unconditional by design; "is this leaf a member" is context
			// only this layer has.
			guard provisionalTree.leaf(at: removed) != nil else {
				throw MLS.RFC9420.GroupError.removeOfNonMember(leaf: removed)
			}
			blankedNodes.insert(2 * removed.value)
			blankedNodes.formUnion(
				MLS.TreeMath.directPath(
					from: 2 * removed.value,
					leafCount: provisionalTree.leafCount
				).map(\.path))
			try provisionalTree.apply(stored.proposal, sender: committer)
		}

		for stored in resolved {
			guard case .add(let keyPackage) = stored.proposal else { continue }
			// Positional, from `insertLeaf` itself -- content matching
			// only agreed with §7.6's positional rule while leaves were
			// unique, and the uniqueness sweep runs after this loop.
			if let addedLeaf = try provisionalTree.apply(
				stored.proposal, sender: committer)
			{
				added.append(
					(
						leaf: addedLeaf,
						presentation: MLS.RFC9420.CredentialPresentation(
							credential: keyPackage.leafNode.credential,
							signatureKey: keyPackage.leafNode
								.signatureKey)
					))
			}
		}

		// §12.2's closing rule: the commit is invalid if "After
		// processing the Commit the ratchet tree is invalid, in
		// particular, if it contains any leaf node that is invalid
		// according to Section 7.3." The per-proposal pass above validated
		// each leaf *individually*; what only the post-application tree
		// can show is a §7.3 uniqueness violation introduced by
		// combination -- two Adds in one commit, each fine alone, sharing
		// a signature key. Join-side validation never sees this: it runs
		// once, at join.
		var postCommitSignatureKeys: Set<MLS.SignaturePublicKey> = []
		var postCommitEncryptionKeys: Set<MLS.HpkePublicKey> = []
		for (leafIndex, record) in provisionalTree.nonBlankLeaves() {
			let leafNode = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			guard postCommitSignatureKeys.insert(leafNode.signatureKey).inserted
			else {
				throw MLS.RFC9420.GroupError.duplicateSignatureKey(leaf: leafIndex)
			}
			// §7.3 names both fields; the earlier sweep checked only the
			// signature half, so two Adds sharing an encryption key --
			// each valid alone, distinct signature keys -- slid through.
			guard postCommitEncryptionKeys.insert(leafNode.encryptionKey).inserted
			else {
				throw MLS.TreeKEM.TreeError.duplicateEncryptionKey(
					node: 2 * leafIndex.value)
			}
		}

		return AppliedProposals(
			tree: provisionalTree, blankedNodes: blankedNodes, added: added)
	}

	/// RFC 9420 §12.2 (list rules) and §12.1 (per-proposal validity), over
	/// the resolved list. This is the authenticity payload of phase 6a as
	/// much as the policy one: before this pass, an Update's or Add's
	/// LeafNode was installed into the tree with **no signature check at
	/// all** -- `processing` takes the `ProposalStore` (proposal *and*
	/// sender) on trust, so an unverified leaf could enter the tree and
	/// every later message from that member would verify against a key
	/// nothing ever proved anyone holds.
	func validateProposalList(
		_ resolved: [MLS.RFC9420.StoredProposal], committer: MLS.LeafIndex,
		provisionalExtensions: [MLS.RFC9420.Extension],
		provider: any MLS.CipherSuiteProvider
	) throws -> [(
		leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
		new: MLS.RFC9420.CredentialPresentation
	)] {
		let groupRequirements = try provisionalExtensions.requiredCapabilities()
		// The old→new presentation for each Update, for slice 4b's credential
		// effects — computed here because this is where the replaced leaf is
		// already decoded (D17 §2 L4: "must be returned", not read "already in
		// hand"). Shared by receive (`validatedDelta`) and send (`committing`).
		var updateChanges:
			[(
				leaf: MLS.LeafIndex, old: MLS.RFC9420.CredentialPresentation,
				new: MLS.RFC9420.CredentialPresentation
			)] = []

		// One decode pass over the members, shared by every leaf check.
		// Indexed, because §12.1.7's membership sweep below needs to
		// exclude removed members and substitute updated leaves.
		var memberCapabilitiesByLeaf: [MLS.LeafIndex: MLS.RFC9420.Capabilities] = [:]
		var memberCredentialTypes: Set<MLS.RFC9420.CredentialType> = []
		for (leafIndex, record) in tree.nonBlankLeaves() {
			let leaf = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			memberCapabilitiesByLeaf[leafIndex] = leaf.capabilities
			memberCredentialTypes.insert(leaf.credential.credentialType)
		}
		let memberCapabilities = Array(memberCapabilitiesByLeaf.values)

		var updatedOrRemoved: Set<MLS.LeafIndex> = []
		var seenPskIDs: Set<Data> = []
		var seenGroupContextExtensions = false
		var appDataUpdates: [MLS.Extensions.AppDataUpdate] = []

		for stored in resolved {
			switch stored.proposal {
			case .add(let keyPackage):
				// §12.1.1 delegates to §10.1 wholesale; §10.1's own
				// bullets include the KeyPackage signature and the leaf's
				// §7.3 validity for a KeyPackage.
				try keyPackage.validate(
					provider, groupContext: context,
					groupRequirements: groupRequirements,
					memberCredentialTypes: memberCredentialTypes,
					memberCapabilities: memberCapabilities)

			case .update(let leafNode):
				guard case .member(let updateSender) = stored.sender else {
					throw MLS.RFC9420.GroupError.unsupportedSender
				}
				// §12.2: "It contains an Update proposal generated by the
				// committer." An inline Update is attributed to the
				// committer by construction, so an inline Update is
				// always invalid -- correct, not a bug: an Update in your
				// own commit is yours, and UpdatePath exists for that.
				guard updateSender != committer else {
					throw MLS.RFC9420.GroupError.updateByCommitter
				}
				// The membership lookup comes FIRST, and it is a read,
				// never a write: the replaced leaf is both the
				// `updateFromNonMember` guard (load-bearing -- see that
				// case's doc comment) and the input to §7.3's
				// changed-encryption-key rule.
				guard let replacedRecord = tree.leaf(at: updateSender) else {
					throw MLS.RFC9420.GroupError.updateFromNonMember(
						leaf: updateSender)
				}
				let replaced = try MLS.RFC9420.LeafNode(
					mlsEncoded: replacedRecord.encoded)
				guard updatedOrRemoved.insert(updateSender).inserted else {
					throw MLS.RFC9420.GroupError.duplicateProposalForLeaf(
						leaf: updateSender)
				}
				try leafNode.verifySignature(
					provider,
					placement: .inGroup(
						groupID: context.groupID, leafIndex: updateSender))
				try leafNode.validatePolicy(
					.updateProposal(replacing: replaced),
					groupRequirements: groupRequirements,
					memberCredentialTypes: memberCredentialTypes,
					memberCapabilities: memberCapabilities)
				updateChanges.append(
					(
						leaf: updateSender,
						old: MLS.RFC9420.CredentialPresentation(
							credential: replaced.credential,
							signatureKey: replaced.signatureKey),
						new: MLS.RFC9420.CredentialPresentation(
							credential: leafNode.credential,
							signatureKey: leafNode.signatureKey)
					))

			case .remove(let removed):
				// §12.2: a self-remove must come through someone else's
				// commit; §12.1.3's non-blank rule is re-checked at apply
				// time against the provisional tree (`removeOfNonMember`),
				// but the committer rule is list-level and lives here.
				guard removed != committer else {
					throw MLS.RFC9420.GroupError.removeOfCommitter
				}
				guard tree.leaf(at: removed) != nil else {
					throw MLS.RFC9420.GroupError.removeOfNonMember(
						leaf: removed)
				}
				guard updatedOrRemoved.insert(removed).inserted else {
					throw MLS.RFC9420.GroupError.duplicateProposalForLeaf(
						leaf: removed)
				}

			case .preSharedKey(let id):
				// §12.1.4: nonce length equals the suite's KDF.Nh, for *every*
				// psktype (external, resumption, application) — checked via the
				// common `nonce` accessor so a new arm can't silently skip it.
				// Read from the provider -- suite 5 is SHA512 (Nh = 64), which a
				// hand table gets wrong. The reinit/branch usage rejection
				// deliberately stays in `resolvePsk`.
				guard id.nonce.count == provider.hashSize else {
					throw MLS.RFC9420.GroupError.wrongPskNonceLength(
						expected: provider.hashSize, actual: id.nonce.count)
				}
				// §12.2: "Multiple PSK proposals that reference the same
				// PreSharedKeyID."
				guard seenPskIDs.insert(try id.mlsEncoded()).inserted else {
					throw MLS.RFC9420.GroupError.duplicatePreSharedKey
				}

			case .groupContextExtensions:
				guard !seenGroupContextExtensions else {
					throw MLS.RFC9420.GroupError.multipleGroupContextExtensions
				}
				seenGroupContextExtensions = true

			case .appDataUpdate(let update):
				// §4.7's per-component_id list rule is checked once after the loop
				// (`validateProposalList`). The two state-dependent §4.7 clauses
				// (unknown component; removing absent state) and the dictionary
				// mutation are deferred to the app_data_dictionary layer a profile
				// owns; this envelope makes no group-state change.
				appDataUpdates.append(update)

			case .reInit:
				// Rejected later in `processing` with its own explicit
				// error (`unsupportedReInit`); list validation has
				// nothing to add.
				break
			case .externalInit:
				// §12.2: a regular commit's proposal list "is invalid if
				// … It contains an ExternalInit proposal", and an invalid
				// list MUST be rejected. This is the §12.2 gate for both
				// construct and process. It is NOT redundant with the
				// confirmation tag: this project derives the new epoch from
				// the ordinary retained `init_secret` -- the §8.3 external
				// initialization step (reached only by §12.4.3.2's external
				// commit path) is not wired, and nothing consumes
				// `kemOutput` -- so a *malicious* committer computes a
				// matching tag exactly as the receiver does and the commit
				// would be accepted. "Dies at the confirmation tag" holds
				// only against an honest committer, who computes the tag.
				//
				// Unconditional because this project processes only regular
				// commits. If external commits are ever supported, this
				// needs the sender's commit type: §12.2's *external* rules
				// require exactly one ExternalInit rather than forbidding it.
				throw MLS.RFC9420.GroupError.externalInitInRegularCommit
			}
		}

		// draft-ietf-mls-extensions-09 §4.7: for a given component_id a proposal
		// list is valid only if it holds a single remove XOR one-or-more updates.
		// Runs on send and receive (both callers), so a committer can't build an
		// invalid list either.
		try MLS.Extensions.AppDataUpdate.validateProposalList(appDataUpdates)

		// §12.1.7: "A GroupContextExtensions proposal is invalid if it
		// includes a required_capabilities extension and some members of
		// the group do not support some of the required capabilities
		// (including those added in the same Commit, and excluding those
		// removed)." The added half is covered above -- every Add's leaf
		// was validated against `groupRequirements`. This is the missing
		// half, over the EXISTING members: without it, one accepted
		// commit puts the group into a state its own join-side
		// `validateLeaves` rejects -- no Welcome from that epoch onward
		// is joinable and no Add can ever be committed again. Updated
		// members are judged by their replacement leaf (validated above),
		// removed members are excluded per the parenthetical.
		if seenGroupContextExtensions, let required = groupRequirements {
			for (leafIndex, capabilities) in memberCapabilitiesByLeaf {
				if updatedOrRemoved.contains(leafIndex) { continue }
				for type in required.extensionTypes
				where
					!MLS.RFC9420.defaultExtensionTypes.contains(type)
					&& !capabilities.extensions.contains(type)
				{
					throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
				}
				for type in required.proposalTypes
				where
					!MLS.RFC9420.defaultProposalTypes.contains(type)
					&& !capabilities.proposals.contains(type)
				{
					throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
				}
				for type in required.credentialTypes
				where !capabilities.credentials.contains(type) {
					throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
				}
			}
		}
		return updateChanges
	}

	/// Resumption ids resolve from this group's own retained history;
	/// everything else goes to the caller. A `reinit`/`branch` usage is
	/// rejected outright for the same reason `join` rejects it: those
	/// carry §12.4.3.1 rules that are meaningless without ReInit/branching
	/// support, which this project defers project-wide.
	/// Returns `SecretBytes?` so a resumption PSK never leaves zeroizing
	/// storage: the resumption branch hands back the retained `SecretBytes`
	/// directly, and the external branch takes custody of the app-supplied
	/// `Data` on the way in. The external callback keeps its `Data?` shape —
	/// the adopter API is unchanged.
	func resolvePsk(
		_ id: MLS.RFC9420.PreSharedKeyIdentifier,
		_ external: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> SecretBytes? {
		guard case .resumption(let resumption, _) = id else {
			guard let bytes = try external(id) else { return nil }
			guard !bytes.isEmpty else {
				throw MLS.RFC9420.GroupError.emptyPreSharedKey
			}
			return try SecretBytes(bytes: bytes)
		}
		guard resumption.usage == .application else {
			throw MLS.RFC9420.GroupError.unsupportedResumptionUsage
		}
		guard resumption.groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		return resumptionPsks[resumption.epoch]
	}

	/// RFC 9420 §7.5: "After processing the update, each recipient MUST
	/// delete outdated key material" — §6 is Message Framing and was a
	/// mis-citation. The three-step order below is this implementation's
	/// own construction, not the section's text: drop keys at nodes this
	/// commit blanked, drop keys on the committer's direct path (which
	/// `applyUpdatePath` just re-keyed), then keep only what is still on
	/// our own path. Steps 1-2 must precede the merge of fresh keys, or a
	/// stale entry overwrites a fresh one at the same index.
	///
	/// Under-pruning is functionally invisible — a re-keyed node this
	/// member still covers gets overwritten by the same commit's decap,
	/// and blanked nodes never appear in a resolution — so it breaks no
	/// test while still violating §7.5's forward-secrecy MUST. That is
	/// exactly why the rule is written out here rather than left implicit.
	func prunedSecretKeys(
		blankedNodes: Set<UInt32>, senderIndex: MLS.LeafIndex?, leafCount: MLS.LeafCount
	) -> [UInt32: MLS.HpkeSecretKey] {
		prunedSecretKeys(
			heldSecretKeys: secretKeys, ownLeaf: myLeafIndex,
			blankedNodes: blankedNodes, senderIndex: senderIndex, leafCount: leafCount)
	}

	/// The per-membership form (slice 4a): prunes `heldSecretKeys` (that
	/// membership's own keys) against `ownLeaf`'s direct path, so each local
	/// membership prunes its own key set — never another's.
	func prunedSecretKeys(
		heldSecretKeys: [UInt32: MLS.HpkeSecretKey], ownLeaf: MLS.LeafIndex,
		blankedNodes: Set<UInt32>, senderIndex: MLS.LeafIndex?, leafCount: MLS.LeafCount
	) -> [UInt32: MLS.HpkeSecretKey] {
		var stale = blankedNodes
		if let senderIndex {
			stale.formUnion(
				MLS.TreeMath.directPath(
					from: 2 * senderIndex.value, leafCount: leafCount
				).map(\.path))
		}

		var ownNodes: Set<UInt32> = [2 * ownLeaf.value]
		ownNodes.formUnion(
			MLS.TreeMath.directPath(
				from: 2 * ownLeaf.value, leafCount: leafCount
			).map(\.path))

		return heldSecretKeys.filter { node, _ in
			!stale.contains(node) && ownNodes.contains(node)
		}
	}

	/// Decap the committer's path for one **local membership** (slice 4a),
	/// returning that membership's installed new-epoch keys and the
	/// `commit_secret` it derives. Each membership prunes and decaps against its
	/// own held keys and its own pending self-Update, so no membership's key
	/// material crosses into another's. The `commit_secret` is a whole-group
	/// value (the path secret converges at the root); the caller checks that
	/// every local membership derives the same one.
	func installKeysForMembership(
		_ membership: MLS.RFC9420.Membership,
		path: MLS.RFC9420.UpdatePath,
		provisionalTree: MLS.TreeKEM.RatchetTree,
		senderIndex: MLS.LeafIndex,
		provisionalContextEncoded: Data,
		blankedNodes: Set<UInt32>,
		addedLeaves: Set<MLS.LeafIndex>,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> (keys: [UInt32: MLS.HpkeSecretKey], commitSecret: Data) {
		// Stale keys go before the fresh ones arrive (the prune-before-merge order
		// is this layer's — a stale entry would otherwise overwrite a fresh one at
		// the same node; §7.5's MUST is the deletion itself, see `prunedSecretKeys`),
		// pruned against this membership's own path.
		var keys = prunedSecretKeys(
			heldSecretKeys: membership.secretKeys, ownLeaf: membership.leafIndex,
			blankedNodes: blankedNodes, senderIndex: senderIndex,
			leafCount: provisionalTree.leafCount)
		// Seed this membership's committed self-Update leaf key (see the N = 1
		// path's own comment): retain every proposed secret, install the one whose
		// public key the provisional tree actually placed at this leaf.
		if let pending = membership.pendingUpdate, pending.epoch == context.epoch,
			let installedKey = provisionalTree.leaf(at: membership.leafIndex)?
				.encryptionKey,
			let match = pending.updates.first(where: { $0.publicKey == installedKey })
		{
			keys[pending.node] = match.secret
		}
		let result = try provisionalTree.decapCommitPath(
			heldSecretKeys: keys, sender: senderIndex,
			pathNodes: path.nodes.map(\.pathNode),
			groupContext: provisionalContextEncoded, excluding: addedLeaves, provider)
		for (node, secretKey) in result.nodeSecretKeys { keys[node] = secretKey }
		return (keys, result.commitSecret)
	}

	/// §12.4.2: "Verify that none of the public keys in the UpdatePath
	/// appear in any node of the new ratchet tree."
	func checkUpdatePathKeysAreFresh(
		_ path: MLS.RFC9420.UpdatePath, in tree: MLS.TreeKEM.RatchetTree
	) throws {
		var existing: Set<MLS.HpkePublicKey> = []
		for i in 0..<tree.serializedNodeCount {
			if MLS.TreeMath.isLeaf(i) {
				if let record = tree.leaf(at: .init(value: i / 2)) {
					existing.insert(record.encryptionKey)
				}
			} else if let parent = tree.parent(at: i) {
				existing.insert(parent.encryptionKey)
			}
		}

		var pathKeys = [path.leafNode.encryptionKey]
		pathKeys.append(contentsOf: path.nodes.map(\.encryptionKey))
		for key in pathKeys where existing.contains(key) {
			throw MLS.RFC9420.GroupError.updatePathReusesEncryptionKey
		}
	}
}
