import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSTreeMath

extension MLS.RFC9420 {
	/// A proposal a member has seen by reference this epoch, with the
	/// sender who framed it — an `Update`'s effect depends on who sent it,
	/// so the sender travels with the proposal, not beside it.
	public struct StoredProposal: Sendable {
		public var proposal: Proposal
		public var sender: MLS.Sender

		public init(proposal: Proposal, sender: MLS.Sender) {
			self.proposal = proposal
			self.sender = sender
		}
	}

	/// By-reference proposals, keyed by `ProposalRef`. A plain dictionary
	/// rather than a wrapper type: it would add no invariant a
	/// `Dictionary` doesn't already have, and which proposals to retain is
	/// application policy — RFC 9420 §12.4 explicitly declines to make
	/// receivers enforce that every proposal they saw is referenced, so
	/// baking a retention policy into a library type would overreach.
	public typealias ProposalStore = [MLS.HashReference: StoredProposal]

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
		// 1-3: cheap framing checks, before any tree work.
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

		// 4: external commits are deferred project-wide, so a non-member
		// sender is rejected outright rather than silently mishandled.
		guard case .member(let senderIndex) = message.content.sender else {
			throw MLS.RFC9420.GroupError.unsupportedSender
		}
		guard let senderLeafRecord = tree.leaf(at: senderIndex) else {
			throw MLS.RFC9420.GroupError.blankSenderLeaf
		}
		let senderLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: senderLeafRecord.encoded)

		// 5: one call covers both the membership MAC and the
		// FramedContentTBS signature. The signature is checked against the
		// sender's *pre-commit* leaf key -- the UpdatePath's new leaf key
		// has not been merged yet and must not be used here.
		guard
			try MLS.RFC9420.verifyPublic(
				provider, message: message, groupContext: context,
				verificationKey: senderLeaf.signatureKey,
				membershipKey: epoch.membershipKey)
		else {
			throw MLS.CryptoError.signatureVerificationFailed
		}

		// 6: resolve the proposal list in list order. An unresolvable
		// reference is an error, never a skip -- applying a commit with a
		// shorter list than its sender used would silently diverge state.
		var resolved: [MLS.RFC9420.StoredProposal] = []
		for entry in commit.proposals {
			switch entry {
			case .proposal(let proposal):
				resolved.append(
					.init(proposal: proposal, sender: message.content.sender))
			case .reference(let ref):
				guard let stored = proposals[ref] else {
					throw MLS.RFC9420.GroupError.unknownProposalReference
				}
				resolved.append(stored)
			}
		}

		// §12.4.2 makes PSK *availability* its own step, five bullets
		// before the tree is touched: "Verify that all PreSharedKey
		// proposals in the proposals vector are available." Resolved here,
		// in RFC order, and reused at the derivation step below -- so a
		// commit naming a PSK we don't hold dies before any tree work.
		let pskIDs = resolved.compactMap { stored -> MLS.RFC9420.PreSharedKeyIdentifier? in
			guard case .preSharedKey(let id) = stored.proposal else { return nil }
			return id
		}
		let resolvedPsks = try pskIDs.map { id -> (encodedID: Data, psk: Data) in
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
		// everything after it, not merely earlier in sequence. Nothing in
		// this phase evaluates required_capabilities (that is §12.2
		// proposal validation, phase 6), so nothing breaks today; the
		// ordering is established now so phase 6 adds those checks against
		// the *new* extensions rather than the old.
		//
		// GCE is routed here rather than through `RatchetTree.apply`
		// deliberately: it changes `GroupContext.extensions`, which a
		// `RatchetTree` does not have and must not learn about. See
		// `TreeEditError.notATreeEditingProposal`'s own doc comment --
		// passing one to `apply` is a caller error by design, exactly as
		// for preSharedKey/reInit/externalInit.
		var provisionalExtensions = context.extensions
		for stored in resolved {
			if case .groupContextExtensions(let extensions) = stored.proposal {
				provisionalExtensions = extensions
			}
		}

		var provisionalTree = tree
		var blankedNodes: Set<UInt32> = []
		var addedLeaves: Set<MLS.LeafIndex> = []

		for stored in resolved {
			guard case .update = stored.proposal else { continue }
			guard case .member(let updateSender) = stored.sender else {
				throw MLS.RFC9420.GroupError.unsupportedSender
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
			// GER-2355's second half: mls-rs errors
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
			try provisionalTree.apply(stored.proposal, sender: senderIndex)
		}

		for stored in resolved {
			guard case .add(let keyPackage) = stored.proposal else { continue }
			try provisionalTree.apply(stored.proposal, sender: senderIndex)
			if let added = provisionalTree.nonBlankLeaves().first(where: {
				(try? $0.record.encoded == keyPackage.leafNode.mlsEncoded())
					?? false
			}) {
				addedLeaves.insert(added.index)
			}
		}

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
			// capabilities, required_capabilities). This phase implements
			// the authenticity half everywhere and defers the policy half
			// to phase 6 -- the same split `join` already applies to every
			// leaf in the tree. Verifying it here matters more than
			// anywhere else: this leaf is the committer's *new* identity
			// binding, and installing it unverified means every later
			// message from that member verifies against a key nothing ever
			// proved they hold.
			guard case .commit = path.leafNode.source else {
				throw MLS.RFC9420.GroupError.updatePathLeafNotCommitSource
			}
			try path.leafNode.verifySignature(
				provider, groupContext: (context.groupID, senderIndex))
			guard path.leafNode.encryptionKey != senderLeaf.encryptionKey else {
				throw MLS.RFC9420.GroupError.updatePathReusesEncryptionKey
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

		// 11
		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
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
		updated.epoch = newEpoch
		updated.secretKeys = newSecretKeys
		updated.interimTranscriptHash = try MLS.Framing.interimTranscriptHash(
			provider, confirmed: confirmedTranscriptHash,
			confirmationTag: confirmationTag)
		updated.resumptionPsks[newContext.epoch] = newEpoch.resumptionPsk
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

	/// Resumption ids resolve from this group's own retained history;
	/// everything else goes to the caller. A `reinit`/`branch` usage is
	/// rejected outright for the same reason `join` rejects it: those
	/// carry §12.4.3.1 rules that are meaningless without ReInit/branching
	/// support, which this project defers project-wide.
	private func resolvePsk(
		_ id: MLS.RFC9420.PreSharedKeyIdentifier,
		_ external: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data?
	) throws -> Data? {
		guard case .resumption(let resumption, _) = id else { return try external(id) }
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
	private func prunedSecretKeys(
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
	private func checkUpdatePathKeysAreFresh(
		_ path: MLS.RFC9420.UpdatePath, in tree: MLS.TreeKEM.RatchetTree
	) throws {
		var existing: Set<MLS.HpkePublicKey> = []
		for i in 0..<tree.physicalNodeCount {
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
