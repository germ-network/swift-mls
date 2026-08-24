import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM {
	/// What a receiver gets out of decap: the `commit_secret` for the key
	/// schedule, and the node secret keys it must retain to decrypt the
	/// *next* commit. A member that processed commit N and holds only its
	/// own leaf key can be locked out of commit N+1: after N merges an
	/// `UpdatePath`, the receiver's covering ancestor is non-blank and
	/// freshly keyed, so N+1's ciphertext at that level targets the
	/// ancestor, not the leaf. `installPathSecrets` (the Welcome-joiner
	/// twin) already returns its derived keys for the same reason; this
	/// mirrors that shape deliberately. Root-ward order, one entry per
	/// unfiltered direct-path position from the decrypt level up to and
	/// including the root.
	public struct DecapResult: Sendable {
		public let commitSecret: Data
		public let nodeSecretKeys: [(node: UInt32, secretKey: MLS.HpkeSecretKey)]
	}
}

extension MLS.TreeKEM.RatchetTree {
	/// Decap: the receiver decrypts whichever `pathNodes` entry it can
	/// reach, derives forward through the remaining levels toward the
	/// root, and returns the resulting `commit_secret` plus every node
	/// secret key derived along the way (see `MLS.TreeKEM.DecapResult`).
	///
	/// `heldSecretKeys` is every HPKE secret key the receiver currently
	/// holds, keyed by node index — not just its own leaf. A receiver's
	/// own leaf key alone is *not* always enough: if an earlier commit
	/// already installed a shared key at some ancestor covering this
	/// receiver (the ancestor is non-blank, so `resolution` reports that
	/// ancestor's own node, not the individual leaves under it), the
	/// receiver must decrypt using *that* ancestor's key instead — RFC
	/// 9420's own resolution semantics, not a special case.
	///
	/// At every level, the freshly-derived public key is checked against
	/// the **wire** `pathNodes[i].publicKey` — not the tree's own stored
	/// key, which still holds the *pre-commit* value until the caller
	/// merges this path in. Only `installPathSecrets` (a joiner processing
	/// a `Welcome`, with no wire update-path to compare against) checks
	/// against the tree instead.
	///
	/// `excluding` must be the exact set the sender encrypted around
	/// (`finishCommitPath`'s own `excluding`) — a leaf added in this same
	/// commit has no key the path could have been encrypted under, so its
	/// node index is dropped from both the ciphertext-count expectation
	/// and every copath resolution used to find a ciphertext's position.
	/// Getting this wrong doesn't silently decrypt the wrong thing — the
	/// position lookup below is computed identically, so an inconsistent
	/// `excluding` fails structurally (`wrongCiphertextCount` or
	/// `notAMember`) rather than producing a wrong secret.
	public func decapCommitPath(
		heldSecretKeys: [UInt32: MLS.HpkeSecretKey], sender: MLS.LeafIndex,
		pathNodes: [MLS.TreeKEM.PathNode], groupContext: Data,
		excluding: Set<MLS.LeafIndex> = [],
		_ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.TreeKEM.DecapResult {
		let path = try MLS.TreeMath.directPath(from: 2 * sender.value, leafCount: leafCount)
		let filtered = try filteredDirectPath(from: sender)
		try validatePathStructure(
			sender: sender,
			nodeCiphertextCounts: pathNodes.map { $0.encryptedPathSecrets.count },
			excluding: excluding)

		let excludedNodeIndices = Set(excluding.map { 2 * $0.value })
		let unfilteredSteps = zip(path, filtered).filter { !$0.1 }.map(\.0)

		var decryptLevel: Int?
		var heldNode: UInt32?
		for (level, step) in unfilteredSteps.enumerated() {
			let resolutionAtLevel = resolution(of: step.sibling).filter {
				!excludedNodeIndices.contains($0)
			}
			if let match = resolutionAtLevel.first(where: { heldSecretKeys[$0] != nil })
			{
				decryptLevel = level
				heldNode = match
				break
			}
		}
		guard let decryptLevel, let heldNode, let heldKey = heldSecretKeys[heldNode] else {
			throw MLS.TreeKEM.TreeError.notAMember
		}

		let resolutionAtLevel = resolution(of: unfilteredSteps[decryptLevel].sibling).filter
		{
			!excludedNodeIndices.contains($0)
		}
		guard let position = resolutionAtLevel.firstIndex(of: heldNode) else {
			throw MLS.TreeKEM.TreeError.notAMember
		}
		guard position < pathNodes[decryptLevel].encryptedPathSecrets.count else {
			throw MLS.TreeKEM.TreeError.wrongCiphertextCount(
				pathIndex: decryptLevel, expected: position + 1,
				actual: pathNodes[decryptLevel].encryptedPathSecrets.count)
		}
		let ciphertext = pathNodes[decryptLevel].encryptedPathSecrets[position]
		var secret = try MLS.decryptWithLabel(
			provider, privateKey: heldKey, label: "UpdatePathNode",
			context: groupContext, enc: ciphertext.kemOutput,
			ciphertext: ciphertext.ciphertext)

		var nodeSecretKeys: [(node: UInt32, secretKey: MLS.HpkeSecretKey)] = []
		for level in decryptLevel..<pathNodes.count {
			let derivedKeyPair = try MLS.TreeKEM.nodeKeyPair(
				provider, pathSecret: secret)
			guard derivedKeyPair.publicKey == pathNodes[level].encryptionKey else {
				throw MLS.TreeKEM.TreeError.publicKeyMismatch
			}
			nodeSecretKeys.append(
				(unfilteredSteps[level].path, derivedKeyPair.secretKey))
			if level < pathNodes.count - 1 {
				secret = try MLS.TreeKEM.nextPathSecret(provider, from: secret)
			}
		}

		let commitSecret = try MLS.TreeKEM.commitSecret(provider, rootPathSecret: secret)
		return MLS.TreeKEM.DecapResult(
			commitSecret: commitSecret, nodeSecretKeys: nodeSecretKeys)
	}
}
