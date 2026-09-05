import Foundation
import MLSCodec
import MLSCrypto
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
	/// sender's current leaf key: `Group.verify(proposal:)` for a
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

	/// By-reference proposals, keyed by `ProposalRef`.
	///
	/// **The store is a trust boundary, and `insert` is its gate.**
	/// `processing` never recomputes a `ProposalRef` against its stored
	/// proposal, and never re-verifies a stored `sender` — it does not need
	/// to, because `insert` accepts only a `VerifiedProposal`, whose framing
	/// signature was already checked against the sender's current leaf key by
	/// `Group.verify(proposal:)` or `unprotect`. A `StoredProposal`'s `sender`
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
		/// `VerifiedProposal` (from `Group.verify(proposal:)` or `unprotect`)
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
	/// `processing(commit:)`, which was `verifyPublic`'s only caller. RFC 9420
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
	public func verify(
		proposal message: MLS.RFC9420.PublicMessage,
		_ provider: any MLS.CipherSuiteProvider
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

	/// RFC 9420 §12.4.2, for a `PublicMessage`-framed commit.
	///
	/// **Never mutates `self`.** Swift does not roll back partial mutation
	/// on `throw`, and §12.4.2 ends "if the above checks are successful,
	/// consider the new GroupContext as the current state" — so a failure
	/// anywhere below must leave the caller's group exactly as it was. That
	/// is why this returns a new `Group` rather than mutating; `process`
	/// below is the thin value-semantics wrapper over it.
	///
	/// `psk` resolves *external* PSK ids. Resumption ids are resolved from
	/// this group's own retained per-epoch history and never reach the
	/// closure.
	public func processing(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PublicMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Group {
		// A PublicMessage-framed commit authenticates via the membership
		// MAC plus the framing signature; both run here, then the core
		// takes over on an already-authenticated frame. This is §12.4.2
		// step 2's first branch.
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
		return try processing(
			provider,
			authenticatedContent: MLS.RFC9420.AuthenticatedContent(
				wireFormat: .publicMessage, content: message.content,
				auth: message.auth),
			proposals: proposals, psk: psk)
	}

	/// The commit-processing core, on an *already authenticated* frame —
	/// §12.4.2 from step 3 on. A `PublicMessage`-framed commit reaches
	/// here after its membership MAC and framing signature are checked; a
	/// `PrivateMessage`-framed one (`unprotect`) reaches here after its
	/// AEAD and signature are checked. Either way the frame is trusted on
	/// entry, and the epoch/group/member/blank-leaf checks below still run
	/// because the private path does not repeat them.
	public func processing(
		_ provider: any MLS.CipherSuiteProvider,
		authenticatedContent message: MLS.RFC9420.AuthenticatedContent,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> MLS.RFC9420.Group {
		// D18 guard: commit-receive installs path keys (`secretKeys`) for the
		// sole membership (`memberships[0]`) only; at N > 1 the other local
		// memberships would silently keep stale keys (the M3 silent-loss class).
		// Fails closed until 1b's per-membership installs. Unreachable via public
		// API today (no public constructor yields N > 1), but kept uniform with
		// the send and snapshot guards. Application receive (`unprotect`, which
		// touches only `core`) is correct at N > 1 and is not guarded.
		guard memberships.count <= 1 else {
			throw MLS.RFC9420.GroupError.multipleMembershipsUnsupported
		}
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
		try validateProposalList(
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
				case .add, .preSharedKey, .reInit: false
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
		// Every other unhandled proposal type fails closed on its own --
		// an ExternalInit in a regular commit diverges the key schedule
		// and dies at the confirmation tag. ReInit does not touch the key
		// schedule at all, so processing it silently returns a
		// live-looking `Group` that the caller must not send from. That is
		// the one case where "unimplemented" and "succeeded" are
		// indistinguishable to a caller, which is why it gets an explicit
		// rejection instead.
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

		// S19: detect self-removal explicitly. This is *after* step 5, so
		// the signature and membership MAC have both passed -- an
		// authenticated member told us we are out. It is necessarily
		// *before* the confirmation tag, which needs the new epoch, which
		// needs a commit_secret we can no longer derive. So this means "an
		// authenticated member removed me", not "a fully verified commit
		// removed me", and the caller decides what to do about it.
		guard provisionalTree.leaf(at: myLeafIndex) != nil else {
			throw MLS.RFC9420.GroupError.removedFromGroup
		}

		// 9: merge the UpdatePath, or take the pathless commit_secret.
		var newSecretKeys = secretKeys
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

			// 10 (before 9f): stale keys must go before the fresh ones
			// arrive, or a stale entry overwrites a fresh one at the same
			// node index.
			newSecretKeys = prunedSecretKeys(
				blankedNodes: blankedNodes, senderIndex: senderIndex,
				leafCount: provisionalTree.leafCount)

			// The updater-side handoff: `secretKeys` has no entry for a
			// self-proposed Update's new leaf key until it is seeded here
			// -- `proposeUpdate` only ever stashed it in `pendingUpdates`,
			// never in `secretKeys`, because until a commit lands there is
			// nothing to decap against.
			//
			// The committer -- not the proposer -- is the authority on
			// which Update lands. Across an epoch this member may propose
			// several self-Updates (each a fresh leaf key); §12.2 permits a
			// single commit to apply at most one per leaf (validation
			// rejects the rest as `duplicateProposalForLeaf`), but separate
			// commits may each reference a different one. So we retain
			// *every* proposed secret and seed the one whose public key the
			// already-validated provisional tree actually installed at our
			// leaf -- ground truth for what this commit's UpdatePath
			// encrypts against, and independent of the store's sender field.
			//
			// Two gates: the epoch must match (a stale-epoch secret must
			// never leak into a new epoch), and the installed leaf key must
			// be one we hold a secret for. If it is not -- a concurrent
			// commit that applied none of our Updates -- we seed nothing and
			// decap under our old leaf key, which `prunedSecretKeys` above
			// deliberately retained.
			//
			// Must run strictly after the `prunedSecretKeys` reassignment
			// above and before decap below: seeding earlier is discarded
			// the moment that reassignment runs.
			if let pendingUpdates, pendingUpdates.epoch == context.epoch,
				let installedKey = provisionalTree.leaf(at: myLeafIndex)?
					.encryptionKey,
				let match = pendingUpdates.updates.first(where: {
					$0.publicKey == installedKey
				})
			{
				newSecretKeys[pendingUpdates.node] = match.secret
			}

			// 9f
			let result = try provisionalTree.decapCommitPath(
				heldSecretKeys: newSecretKeys, sender: senderIndex,
				pathNodes: path.nodes.map(\.pathNode),
				groupContext: try provisionalContext.mlsEncoded(),
				excluding: addedLeaves, provider)

			// 9g
			for (node, secretKey) in result.nodeSecretKeys {
				newSecretKeys[node] = secretKey
			}
			commitSecret = result.commitSecret
		} else {
			// S23: §12.4.2 -- a commit without a path contributes an
			// all-zero commit_secret of the hash's own length, not an
			// absent one.
			commitSecret = Data(repeating: 0, count: provider.hashSize)
			newSecretKeys = prunedSecretKeys(
				blankedNodes: blankedNodes, senderIndex: nil,
				leafCount: provisionalTree.leafCount)
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

		// 16-18
		var updated = self
		updated.context = newContext
		updated.tree = provisionalTree
		updated.epoch = MLS.RFC9420.Group.EpochSecrets(retaining: newEpoch)
		updated.secretKeys = newSecretKeys
		updated.interimTranscriptHash = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmedTranscriptHash,
			confirmationTag: confirmationTag)
		// `pendingUpdates` is valid only for the epoch it names -- every
		// epoch advance retires the whole set, seeded or not (forward
		// secrecy: proposed-but-uncommitted leaf secrets must not outlive
		// their epoch).
		updated.pendingUpdates = nil
		updated.resumptionPsks[newContext.epoch] = newEpoch.resumptionPsk
		// Against the *new* epoch, after the insert above -- pruning
		// against the old epoch with a small depth could evict the entry
		// this very commit added.
		updated.pruneResumptionPsks(currentEpoch: newContext.epoch)
		try updated.installMessageSecrets(
			context: newContext, senderDataSecret: newEpoch.senderDataSecret,
			encryptionSecret: newEpoch.encryptionSecret,
			applicationExportSecret: newEpoch.applicationExportSecret,
			tree: provisionalTree,
			provider)
		return updated
	}

	/// Value-semantics convenience over `processing`. Assigns only on
	/// success, so a throw leaves `self` untouched — see `processing`'s own
	/// doc comment for why that cannot be achieved by mutating in place.
	public mutating func process(
		_ provider: any MLS.CipherSuiteProvider,
		commit message: MLS.RFC9420.PublicMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws {
		self = try processing(provider, commit: message, proposals: proposals, psk: psk)
	}

	/// The private-framed counterpart: `unprotect` authenticates the
	/// `PrivateMessage` (AEAD open plus framing signature) and hands back
	/// the `AuthenticatedContent` `processing` takes over from — mirroring
	/// how `process(commit:)` authenticates a `PublicMessage` first. Unlike
	/// `process(commit:)`, a throw here may still have advanced `self`'s
	/// own message-secret ratchet: `unprotect` is itself mutating (§9.2
	/// consumption on successful decrypt), and that consumption is
	/// unrelated to whether the *commit* — authenticated by that point —
	/// goes on to pass `processing`.
	public mutating func process(
		_ provider: any MLS.CipherSuiteProvider,
		privateCommit message: MLS.RFC9420.PrivateMessage,
		proposals: MLS.RFC9420.ProposalStore,
		psk: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws {
		let unprotected = try unprotect(provider, message: message)
		guard case .commit(let authenticated) = unprotected.content else {
			throw MLS.RFC9420.GroupError.notACommit
		}
		self = try processing(
			provider, authenticatedContent: authenticated, proposals: proposals,
			psk: psk)
	}

	/// What `applyProposals` hands back: the provisional tree plus the two
	/// index sets that feed key pruning (`blankedNodes`) and copath
	/// exclusion (`addedLeaves`).
	struct AppliedProposals {
		var tree: MLS.TreeKEM.RatchetTree
		var blankedNodes: Set<UInt32>
		var addedLeaves: Set<MLS.LeafIndex>
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
		var addedLeaves: Set<MLS.LeafIndex> = []

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
			guard case .add = stored.proposal else { continue }
			// Positional, from `insertLeaf` itself -- content matching
			// only agreed with §7.6's positional rule while leaves were
			// unique, and the uniqueness sweep runs after this loop.
			if let added = try provisionalTree.apply(
				stored.proposal, sender: committer)
			{
				addedLeaves.insert(added)
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
			tree: provisionalTree, blankedNodes: blankedNodes,
			addedLeaves: addedLeaves)
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
	) throws {
		let groupRequirements = try provisionalExtensions.requiredCapabilities()

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

			case .reInit:
				// Rejected later in `processing` with its own explicit
				// error (`unsupportedReInit`); list validation has
				// nothing to add.
				break
			case .externalInit:
				// §12.2 forbids ExternalInit in a regular commit. No
				// explicit rejection here by prior decision: it fails
				// closed -- an unapplied ExternalInit diverges the key
				// schedule and dies at the confirmation tag, which the
				// vector gate exercises. Documented rather than doubled.
				break
			}
		}

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
		var stale = blankedNodes
		if let senderIndex {
			stale.formUnion(
				MLS.TreeMath.directPath(
					from: 2 * senderIndex.value, leafCount: leafCount
				).map(\.path))
		}

		var ownNodes: Set<UInt32> = [2 * myLeafIndex.value]
		ownNodes.formUnion(
			MLS.TreeMath.directPath(
				from: 2 * myLeafIndex.value, leafCount: leafCount
			).map(\.path))

		return secretKeys.filter { node, _ in
			!stale.contains(node) && ownNodes.contains(node)
		}
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
