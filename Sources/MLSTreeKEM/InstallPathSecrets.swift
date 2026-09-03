import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// A joiner processing a `Welcome`, RFC 9420 §12.4.3.1: "Identify the
	/// lowest common ancestor of the leaf node my_leaf and of the node of
	/// the member with leaf index GroupInfo.signer. Set the private key
	/// for this node to the private key derived from the path_secret," and
	/// then "For each parent of the common ancestor, up to the root of the
	/// tree, derive a new path secret[…] The private key MUST be the
	/// private key that corresponds to the public key in the node" — the
	/// tree-key equality check below is that MUST.
	///
	/// Not the same walk as `decapCommitPath`: a joiner has no wire
	/// update-path to compare against, so every derived public key is
	/// checked against **the tree's own stored key** instead of a wire
	/// value — the tree is what the joiner is trying to confirm it can
	/// actually participate in, not something still mid-commit.
	///
	/// Returns the derived secret keys in root-to-leaf order, one per
	/// *unfiltered* direct-path entry from the LCA up to (and including)
	/// the root — the caller installs them at the corresponding node
	/// indices. A filtered entry (empty copath resolution at that level —
	/// mls-rs's `private.rs`'s `if *f { continue; }`) is skipped entirely:
	/// no key to check there (nobody encrypted to an empty resolution) and
	/// no chain advance, exactly `beginCommitPath`/`decapCommitPath`'s own
	/// unfiltered-entries-only semantics.
	public func installPathSecrets(
		forLeaf leafIndex: MLS.LeafIndex, from signer: MLS.LeafIndex, pathSecret: Data,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> [(node: UInt32, secretKey: MLS.HpkeSecretKey)] {
		let signerPath = MLS.TreeMath.directPath(
			from: 2 * signer.value, leafCount: leafCount)
		let signerFiltered = try filteredDirectPath(from: signer)
		let selfPath = Set(
			MLS.TreeMath.directPath(from: 2 * leafIndex.value, leafCount: leafCount)
				.map(\.path))

		guard let lcaIndex = signerPath.firstIndex(where: { selfPath.contains($0.path) })
		else {
			throw MLS.TreeKEM.TreeError.notAMember
		}

		var secret = pathSecret
		var installed: [(node: UInt32, secretKey: MLS.HpkeSecretKey)] = []
		for (step, isFiltered) in zip(signerPath[lcaIndex...], signerFiltered[lcaIndex...])
		where !isFiltered {
			let (secretKey, publicKey) = try MLS.TreeKEM.nodeKeyPair(
				provider, pathSecret: secret)
			guard let treeKey = parent(at: step.path)?.encryptionKey,
				treeKey == publicKey
			else {
				throw MLS.TreeKEM.TreeError.publicKeyMismatch
			}
			installed.append((step.path, secretKey))
			secret = try MLS.TreeKEM.nextPathSecret(provider, from: secret)
		}
		return installed
	}
}
