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
	public mutating func proposeUpdate(
		_ provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey,
		framing: HandshakeFraming = .privateMessage
	) throws -> (message: MLS.RFC9420.Message, ref: MLS.HashReference) {
		// D18 send guard, at the top: a public-framed proposal seals via
		// `sealPublic` and never reaches `protectContent`'s guard, and this
		// mutates the sole membership's `pendingUpdate`. N > 1 fails closed until
		// the send-side slice.
		guard memberships.count <= 1 else {
			throw MLS.RFC9420.GroupError.multipleMembershipsUnsupported
		}
		guard let currentRecord = tree.leaf(at: myLeafIndex) else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}
		let currentLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: currentRecord.encoded)
		let (newSecretKey, newPublicKey) = try provider.hpkeGenerateKeyPair()

		var updateLeaf = currentLeaf
		updateLeaf.encryptionKey = newPublicKey
		updateLeaf.source = .update
		updateLeaf.signature = Data()
		updateLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try updateLeaf.toBeSigned(
				placement: .inGroup(
					groupID: context.groupID, leafIndex: myLeafIndex)))

		let framed = MLS.RFC9420.FramedContent(
			groupID: context.groupID, epoch: context.epoch,
			sender: .member(myLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(updateLeaf)))

		let message: MLS.RFC9420.Message
		let authenticated: MLS.RFC9420.AuthenticatedContent
		switch framing {
		case .publicMessage:
			let (signedContent, signature) = try MLS.RFC9420.signPublic(
				provider, content: framed, groupContext: context,
				signingKey: signingKey)
			let sealed = try MLS.RFC9420.sealPublic(
				provider, content: framed, signedContent: signedContent,
				signature: signature, confirmationTag: nil,
				membershipKey: epoch.membershipKey)
			message = .publicMessage(sealed)
			authenticated = .init(
				wireFormat: .publicMessage, content: framed, auth: sealed.auth)
		case .privateMessage:
			// `protectContent` reconstructs the identical `FramedContent`
			// from these same fields, so its returned signature is the one
			// that actually sealed the message -- exactly what `ref` below
			// must be computed from (see `protectContent`'s own doc
			// comment on why signing twice would diverge them).
			let (sealed, signature) = try protectContent(
				provider, content: .proposal(.update(updateLeaf)),
				authenticatedData: Data(), signingKey: signingKey,
				reuseGuard: MLS.Framing.ReuseGuard(provider.randomBytes(4)),
				paddingLength: 0)
			message = .privateMessage(sealed)
			authenticated = .init(
				wireFormat: .privateMessage, content: framed,
				auth: .init(signature: signature, confirmationTag: nil))
		}

		let ref = try MLS.RFC9420.proposalRef(provider, authenticated)
		if pendingUpdates?.epoch == context.epoch {
			pendingUpdates?.updates.append(
				(publicKey: newPublicKey, secret: newSecretKey))
		} else {
			pendingUpdates = (
				epoch: context.epoch, node: 2 * myLeafIndex.value,
				updates: [(publicKey: newPublicKey, secret: newSecretKey)]
			)
		}
		return (message, ref)
	}
}
