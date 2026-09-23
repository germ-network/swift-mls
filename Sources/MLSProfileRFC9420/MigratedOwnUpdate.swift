import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420.Group {
	/// Restores one of THIS member's own outstanding Update proposals after a
	/// migration from another implementation that kept its outstanding
	/// proposals only as `{proposal, sender, ref}` — never the signed framing
	/// bytes `ProposalStore.insert` normally requires to re-verify. Without
	/// this, a peer's commit that references the proposal by ref (RFC 9420
	/// §12.4) could never be resolved on the migrated side.
	///
	/// In place of the framing signature `insert` checks, this establishes:
	/// that `leaf` names the local membership that PROPOSED the Update (the
	/// `(as:)` convention `committing`/`proposingUpdate` already use, so a
	/// multi-membership group names which one); that `groupID` and `epoch`
	/// match the current context, since only a current-epoch proposal can
	/// ever be committed; that `leafNode`'s own signature verifies under its
	/// embedded `signatureKey`, bound to `(groupID, leaf)` exactly as a
	/// self-Update signs one (`proposeUpdate`'s S2 self-verify checks the
	/// same thing on the sending side); that `leaf`'s own retained
	/// `pendingUpdate`, for the CURRENT epoch, names an entry under this
	/// exact `encryptionKey` AND that entry's secret genuinely opens what it
	/// seals to that key — a possession proof, not just a name match (see
	/// `migratedUpdateSecretMismatch`'s doc comment for why a match alone
	/// isn't enough); and that `leafNode` passes the same §7.3 validity
	/// policy an incoming Update leaf gets. What none of this establishes is
	/// that `ref` is the real reference for `leafNode` — that can't be
	/// checked without the framing bytes a migration never retained. Trust
	/// in the `(ref, leafNode)` pairing rests entirely on the archive being
	/// this device's own, assembled locally. **Never call this with data
	/// received over the network.**
	///
	/// §12.2 forbids the membership that proposed an Update from ever
	/// committing it itself (`updateByCommitter`) — an Update in your own
	/// commit is yours, and `UpdatePath` exists for that instead — so
	/// `leaf` can never also be the one committing this entry. In a
	/// multi-membership group, a SIBLING local membership committing it by
	/// reference relies on the SAME `(ref, leafNode)` pairing this method
	/// cannot verify: if the pairing is wrong, remote peers — who resolve
	/// the same ref against their own, correctly-paired data — reject the
	/// sibling's commit, while THIS device, having built and self-signed
	/// that commit from its own wrong data, advances alone rather than
	/// failing closed, diverging from the rest of the group.
	///
	/// `ref` is stored exactly as given and never recomputed. A `ref` that
	/// resolves to no entry fails closed: this member can't process the
	/// peer's commit that lands its own Update, and stays stuck at that
	/// epoch (the commit just fails `unknownProposalReference`). A `ref`
	/// that resolves to the WRONG entry, when a genuine remote peer sends
	/// the commit, is not silently misapplied either — that peer built its
	/// commit from its OWN correct resolution, so this side's UpdatePath,
	/// tree hash, and confirmation tag stop matching once the wrong
	/// proposal is applied, and processing fails (just not necessarily with
	/// that same named error). The sibling-commits-it-wrong risk above is
	/// different, and worse: getting the `(ref, leafNode)` pairing right is
	/// the caller's job either way, since nothing here can check it.
	@_spi(Migration)
	public func insertMigratedOwnUpdate(
		as leaf: MLS.LeafIndex,
		_ provider: any MLS.CipherSuiteProvider,
		into store: inout MLS.RFC9420.ProposalStore,
		ref: MLS.HashReference,
		leafNode: MLS.RFC9420.LeafNode,
		epoch: UInt64,
		groupID: Data
	) throws {
		let membershipIndex = try membershipIndex(of: leaf)
		guard groupID == context.groupID else {
			throw MLS.RFC9420.GroupError.wrongGroup
		}
		guard epoch == context.epoch else {
			throw MLS.RFC9420.GroupError.wrongEpoch(
				expected: context.epoch, actual: epoch)
		}
		try leafNode.verifySignature(
			provider, placement: .inGroup(groupID: context.groupID, leafIndex: leaf))

		// Presence: THIS membership's own retained self-Update record, for the
		// CURRENT epoch, names an entry under this exact encryption key. Not by
		// itself proof of possession — `pendingUpdate` isn't written only by
		// `proposeUpdate` (a snapshot restore also stamps entries at the
		// current epoch, without cross-checking each secret against its public
		// key), so a name match alone shows the archive holds SOME entry filed
		// under this key, not that the paired secret is genuine. The
		// possession check right below is what actually proves that.
		let pendingUpdate = memberships[membershipIndex].pendingUpdate
		guard let pendingUpdate, pendingUpdate.epoch == context.epoch,
			let matched = pendingUpdate.updates.first(where: {
				$0.publicKey == leafNode.encryptionKey
			})
		else {
			throw MLS.RFC9420.GroupError.migratedUpdateHasNoPendingSecret
		}

		// Possession: seal a probe to the matched entry's OWN public key and
		// open it with its OWN secret. Without this, a corrupted or
		// mismatched archive entry — a name match with no genuine pair behind
		// it — would only surface later, when the *installed* leaf's commit
		// lands and this device silently can't decap its own path.
		do {
			let probe = Data("migrated-update-possession-probe".utf8)
			let sealed = try provider.hpkeSeal(
				publicKey: matched.publicKey, info: Data(), aad: nil,
				plaintext: probe)
			let opened = try provider.hpkeOpen(
				enc: sealed.enc, secretKey: matched.secret, info: Data(), aad: nil,
				ciphertext: sealed.ciphertext)
			guard opened == probe else {
				throw MLS.RFC9420.GroupError.migratedUpdateSecretMismatch
			}
		} catch {
			throw MLS.RFC9420.GroupError.migratedUpdateSecretMismatch
		}

		guard let currentRecord = tree.leaf(at: leaf) else {
			throw MLS.RFC9420.GroupError.ownLeafNotFound
		}
		let currentLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: currentRecord.encoded)
		let (memberCapabilitiesByLeaf, memberCredentialTypes) = try currentMemberRoster()
		try leafNode.validatePolicy(
			.updateProposal(replacing: currentLeaf),
			groupRequirements: try context.extensions.requiredCapabilities(),
			memberCredentialTypes: memberCredentialTypes,
			memberCapabilities: Array(memberCapabilitiesByLeaf.values))

		try store.insertMigratedOwnUpdate(
			ref,
			MLS.RFC9420.StoredProposal(
				proposal: .update(leafNode), sender: .member(leaf), epoch: epoch,
				groupID: groupID))
	}
}
