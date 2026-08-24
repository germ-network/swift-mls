import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// A joiner processing a `Welcome`: derive every node-key pair `self`
	/// can reach from the single path secret `GroupSecrets.pathSecret`
	/// carries, starting at the direct-path entry level-aligned with
	/// `GroupInfo.signer` and `self`'s own leaf's lowest common ancestor.
	///
	/// Not the same walk as `decapCommitPath`: a joiner has no wire
	/// update-path to compare against, so every derived public key is
	/// checked against **the tree's own stored key** instead of a wire
	/// value — the tree is what the joiner is trying to confirm it can
	/// actually participate in, not something still mid-commit.
	///
	/// Returns the derived secret keys in root-to-leaf order, one per
	/// direct-path entry from `startIndex` up to (and including) the
	/// root — the caller installs them at the corresponding node indices.
	public func installPathSecrets(
		forLeaf leafIndex: MLS.LeafIndex, from signer: MLS.LeafIndex, pathSecret: Data,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> [(node: UInt32, secretKey: MLS.HpkeSecretKey)] {
		let signerPath = try MLS.TreeMath.directPath(
			from: 2 * signer.value, leafCount: leafCount)
		let selfPath = Set(
			try MLS.TreeMath.directPath(from: 2 * leafIndex.value, leafCount: leafCount)
				.map(\.path))

		guard let lcaIndex = signerPath.firstIndex(where: { selfPath.contains($0.path) })
		else {
			throw MLS.TreeKEM.TreeError.notAMember
		}

		var secret = pathSecret
		var installed: [(node: UInt32, secretKey: MLS.HpkeSecretKey)] = []
		for step in signerPath[lcaIndex...] {
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
