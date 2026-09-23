import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming

extension MLS.RFC9420.Group {
	/// A self-Update, RFC 9420 §12.1.2: a fresh leaf HPKE key pair, signed
	/// into a `LeafNode` bound to this member's own `(group_id,
	/// leaf_index)`, framed as a `Proposal`. Mutating: stashes the new
	/// secret in `pendingUpdates` so `processing` can seed it back in when a
	/// later commit — this member's own or another member's — applies this
	/// Update (see `processing`'s own doc comment on the handoff). Every
	/// self-Update proposed in an epoch is retained, not just the latest: the
	/// committer, not the proposer, chooses which one lands, so all their
	/// secrets must survive until a commit picks one. `updates.last` is the
	/// most recent.
	///
	/// Returns the framed proposal and its `ProposalRef` — the same ref a
	/// receiver would compute over the identical bytes after authenticating
	/// the proposal (`unprotect` for a `privateMessage`, or
	/// `Group.verifying(proposal:)` for a `publicMessage`) and feeding the
	/// resulting `VerifiedProposal` to `ProposalStore.insert`. A caller that
	/// is also the eventual committer needs nothing else to reference it by.
	///
	/// `authenticatedData` rides in the proposal's `FramedContent` (RFC 9420
	/// §6), covered by its signature and by `ref`. Sent UNENCRYPTED under
	/// either framing, including `.privateMessage`, where it rides in
	/// `PrivateMessage`'s own plaintext field (RFC 9420 §6.3) rather than
	/// inside the encrypted ciphertext.
	public mutating func proposeUpdate(
		_ provider: any MLS.CipherSuiteProvider,
		sign: MLS.RFC9420.SigningClosure,
		framing: HandshakeFraming = .privateMessage,
		newIdentity: MLS.RFC9420.NewSigningIdentity? = nil,
		authenticatedData: Data = Data()
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		// Proposes for the sole local membership; `ambiguousMembership` at N ≠ 1,
		// where `proposingUpdate(as:)` names it (slice 3b: the pending self-Update
		// and the seal are both per-membership now, so this is N > 1-correct).
		try proposeUpdate(
			membershipIndex: try soleMembershipIndex(), provider,
			sign: sign, framing: framing, newIdentity: newIdentity,
			authenticatedData: authenticatedData)
	}

	/// `signingKey:` sugar over the closure form above (ADR 0002), `authenticatedData`
	/// included. `newIdentity:` is legitimate here too for a credential-only
	/// rotation (M1) — see `committing`'s matching overload.
	public mutating func proposeUpdate(
		_ provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey,
		framing: HandshakeFraming = .privateMessage,
		newIdentity: MLS.RFC9420.NewSigningIdentity? = nil,
		authenticatedData: Data = Data()
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		try proposeUpdate(
			provider, sign: MLS.RFC9420.signingClosure(provider, signingKey),
			framing: framing, newIdentity: newIdentity,
			authenticatedData: authenticatedData)
	}

	mutating func proposeUpdate(
		membershipIndex: Int,
		_ provider: any MLS.CipherSuiteProvider,
		sign: MLS.RFC9420.SigningClosure,
		framing: HandshakeFraming = .privateMessage,
		newIdentity: MLS.RFC9420.NewSigningIdentity? = nil,
		authenticatedData: Data = Data()
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		let leaf = memberships[membershipIndex].leafIndex
		guard let currentRecord = tree.leaf(at: leaf) else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}
		let currentLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: currentRecord.encoded)
		let (newSecretKey, newPublicKey) = try provider.hpkeGenerateKeyPair()

		var updateLeaf = currentLeaf
		updateLeaf.encryptionKey = newPublicKey
		if let newIdentity {
			updateLeaf.credential = newIdentity.credential
			updateLeaf.signatureKey = newIdentity.signatureKey
		}
		updateLeaf.source = .update
		updateLeaf.signature = Data()
		if newIdentity != nil {
			// SC-2: policy validated BEFORE signing, mirroring `committing`'s S1
			// reorder -- a policy-invalid rotation must never burn a `.leafNode`
			// signature (a ticket a stateful signer, ADR 0002, may not be able to
			// un-consume). `updateLeaf.capabilities` is untouched by `newIdentity`
			// (it carries only a credential/signature key), so this checks the NEW
			// credential against the group's OTHER members -- the same predicate
			// the receive side runs in `validateProposalList`
			// (`.updateProposal(replacing:)`), against the CURRENT tree/context
			// here since no commit exists yet to provision a new one.
			var memberCapabilities: [MLS.RFC9420.Capabilities] = []
			var memberCredentialTypes: Set<MLS.RFC9420.CredentialType> = []
			for (index, record) in tree.nonBlankLeaves() where index != leaf {
				let member = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
				memberCapabilities.append(member.capabilities)
				memberCredentialTypes.insert(member.credential.credentialType)
			}
			try updateLeaf.validatePolicy(
				.updateProposal(replacing: currentLeaf),
				groupRequirements: try context.extensions.requiredCapabilities(),
				memberCredentialTypes: memberCredentialTypes,
				memberCapabilities: memberCapabilities)
		}
		// A rotation self-signs the new leaf with the NEW key — receivers verify
		// it against the leaf's own embedded `signatureKey` (§7.3) — while the
		// enclosing proposal stays framed under the CALLER's CURRENT key below,
		// which is what `verifying(proposal:)` checks against the pre-commit
		// sender leaf.
		updateLeaf.signature = try MLS.RFC9420.sign(
			sign, role: .leafNode, label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: context.groupID, leafIndex: leaf)))
		// S2: self-verify, the same guard `committing`'s path leaf gets --
		// without it, a closure that mis-routes `.leafNode` to the wrong key
		// passes `verifying(proposal:)` (which checks the ENCLOSING proposal
		// against the pre-commit sender leaf, a different key when rotating)
		// and only detonates in every peer's `applyProposals` at commit time.
		try updateLeaf.verifySignature(
			provider,
			placement: .inGroup(groupID: context.groupID, leafIndex: leaf))

		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: context.epoch,
			sender: .member(leaf), authenticatedData: authenticatedData,
			content: .proposal(.update(updateLeaf)))

		let message: MLS.RFC9420.Message
		let authenticated: MLS.RFC9420.AuthenticatedContent
		let envelopeSignature: MLS.Signature
		switch framing {
		case .publicMessage:
			let (signedContent, signature) = try MLS.RFC9420.signPublic(
				provider, content: framed, groupContext: context, sign: sign)
			let sealed = try MLS.RFC9420.sealPublic(
				provider, content: framed, signedContent: signedContent,
				signature: signature, confirmationTag: nil,
				membershipKey: epoch.membershipKey)
			message = .publicMessage(sealed)
			authenticated = .init(
				wireFormat: .publicMessage, content: framed, auth: sealed.auth)
			envelopeSignature = signature
		case .privateMessage:
			// `protectContent` reconstructs the identical `FramedContent`
			// from these same fields, so its returned signature is the one
			// that actually sealed the message -- exactly what `ref` below
			// must be computed from (see `protectContent`'s own doc
			// comment on why signing twice would diverge them).
			let (sealed, signature) = try protectContent(
				membershipIndex: membershipIndex, provider,
				content: .proposal(.update(updateLeaf)),
				authenticatedData: authenticatedData, sign: sign,
				reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)),
				paddingLength: 0)
			message = .privateMessage(sealed)
			authenticated = .init(
				wireFormat: .privateMessage, content: framed,
				auth: .init(signature: signature, confirmationTag: nil))
			envelopeSignature = signature
		}

		// SC-1: self-verify the enclosing proposal's envelope signature against
		// the PROPOSER'S CURRENT leaf key -- the key `verifying(proposal:)`
		// checks it against on the receive side (never the `newIdentity` leaf a
		// rotation embeds: that key is what the leaf's OWN `.leafNode` signature
		// routes to, not the enclosing `.framedContent`). Catches a closure that
		// mis-routes `.framedContent` before ever sending a proposal every peer
		// would reject.
		let envelopeSignedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10,
			wireFormat: framing == .publicMessage ? .publicMessage : .privateMessage,
			encodedContent: try framed.mlsEncoded(),
			encodedGroupContext: framed.sender.bindsGroupContext
				? try context.mlsEncoded() : nil)
		guard
			try MLS.verifyWithLabel(
				provider, publicKey: currentLeaf.signatureKey,
				label: "FramedContentTBS",
				content: envelopeSignedContent.toBeSigned(),
				signature: envelopeSignature.data)
		else { throw MLS.CryptoError.signatureVerificationFailed }

		let ref = try MLS.RFC9420.proposalRef(provider, authenticated)
		if memberships[membershipIndex].pendingUpdate?.epoch == context.epoch {
			memberships[membershipIndex].pendingUpdate?.updates.append(
				(publicKey: newPublicKey, secret: newSecretKey))
		} else {
			memberships[membershipIndex].pendingUpdate = (
				epoch: context.epoch, node: 2 * leaf.value,
				updates: [(publicKey: newPublicKey, secret: newSecretKey)]
			)
		}
		return (message, ref)
	}
}
