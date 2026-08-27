import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.TreeKEM {
	/// This component's own name for RFC 9420's `UpdatePathNode` — the
	/// profile maps 1:1 to/from its own wire type. Living here rather than
	/// in the profile keeps encap's actual encryption step (which produces
	/// exactly this shape) inside `MLSTreeKEM`, with no wire-format
	/// dependency either direction.
	public struct PathNode: Sendable, Equatable {
		public var encryptionKey: MLS.HpkePublicKey
		public var encryptedPathSecrets: [MLS.HpkeCiphertext]

		public init(
			encryptionKey: MLS.HpkePublicKey, encryptedPathSecrets: [MLS.HpkeCiphertext]
		) {
			self.encryptionKey = encryptionKey
			self.encryptedPathSecrets = encryptedPathSecrets
		}
	}

	/// Everything `finishCommitPath` needs, carried from `beginCommitPath`.
	/// Opaque to callers — the two functions are a matched pair; nothing
	/// else should construct or inspect this.
	public struct CommitPathStage: Sendable {
		fileprivate let path: [(path: UInt32, sibling: UInt32)]
		fileprivate let filtered: [Bool]
		/// The seed `beginCommitPath` was called with — needed as the
		/// "root path secret" fallback when every direct-path entry was
		/// filtered (empty copath resolution everywhere), since then the
		/// chain never advances past it at all.
		fileprivate let firstPathSecret: Data
		/// One entry per *unfiltered* direct-path position, leaf-to-root
		/// order — no entry for the committer's own leaf, since its HPKE
		/// key comes from the profile signing a fresh `LeafNode` (step 3
		/// of encap), not from this component.
		fileprivate let unfilteredPathSecrets: [Data]
		public let nodeSecretKeys: [MLS.HpkeSecretKey]
		/// The committer's own new leaf's `parent_hash` — install this on
		/// the `LeafNode` being signed (encap step 3) before computing the
		/// tree hash for `GroupContext` (step 4).
		public let leafParentHash: Data
	}
}

extension MLS.TreeKEM.RatchetTree {
	/// Encap, steps 1-2: derive fresh path secrets and node key pairs for
	/// every *unfiltered* direct-path entry, install the new public keys
	/// into the tree (clearing each parent's `unmergedLeaves` — RFC 9420's
	/// commit-construction rule), and compute the committer's leaf's new
	/// `parent_hash` — which also installs every ancestor's own
	/// `parent_hash` field along the way (`parentHashForLeaf`'s own doc
	/// comment). Steps 3-4 (sign the new `LeafNode`, compute the tree hash
	/// for `GroupContext`) are the profile's job, done between this call
	/// and `finishCommitPath`.
	///
	/// `firstPathSecret` is caller-supplied, not generated here: this
	/// component has no randomness source of its own
	/// (`MLS.CipherSuiteProvider` doesn't expose one), and taking it as a
	/// parameter keeps encap fully deterministic and testable — the
	/// caller owns randomness, matching how `MLSFraming`'s `ReuseGuard`
	/// takes bytes rather than generating them.
	public mutating func beginCommitPath(
		sender: MLS.LeafIndex, firstPathSecret: Data,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.TreeKEM.CommitPathStage {
		let path = try MLS.TreeMath.directPath(from: 2 * sender.value, leafCount: leafCount)
		let filtered = try filteredDirectPath(from: sender)

		var secret = firstPathSecret
		var pathSecrets: [Data] = []
		var secretKeys: [MLS.HpkeSecretKey] = []

		for (step, isFiltered) in zip(path, filtered) where !isFiltered {
			pathSecrets.append(secret)
			let (secretKey, publicKey) = try MLS.TreeKEM.nodeKeyPair(
				provider, pathSecret: secret)
			secretKeys.append(secretKey)
			setParent(
				step.path,
				to: .init(
					encryptionKey: publicKey, parentHash: Data(),
					unmergedLeaves: []))
			secret = try MLS.TreeKEM.nextPathSecret(provider, from: secret)
		}

		let leafParentHash = try parentHashForLeaf(sender, provider)

		return MLS.TreeKEM.CommitPathStage(
			path: path, filtered: filtered, firstPathSecret: firstPathSecret,
			unfilteredPathSecrets: pathSecrets, nodeSecretKeys: secretKeys,
			leafParentHash: leafParentHash)
	}

	/// Encap step 5: encrypt each unfiltered path secret to every member
	/// of its copath resolution, and derive `commit_secret` one step past
	/// the last path secret in the chain. RFC 9420 §7.6:
	/// `EncryptWithLabel(node_public_key, "UpdatePathNode", group_context,
	/// path_secret)`, where "the resolution of the corresponding copath
	/// node MUST exclude all new leaf nodes added as part of the current
	/// Commit" — a brand-new member has no key the committer's path could
	/// have been encrypted under yet.
	///
	/// `groupContext` must already reflect this commit's new tree hash —
	/// the profile computes that between `beginCommitPath` and this call
	/// (encap step 4) and encodes the `GroupContext` used here as
	/// `EncryptWithLabel`'s context.
	public func finishCommitPath(
		_ stage: MLS.TreeKEM.CommitPathStage, groupContext: Data,
		excluding: Set<MLS.LeafIndex>,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> (pathNodes: [MLS.TreeKEM.PathNode], commitSecret: Data) {
		let excludedNodeIndices = Set(excluding.map { 2 * $0.value })
		var pathNodes: [MLS.TreeKEM.PathNode] = []
		var pathIndex = 0

		for (step, isFiltered) in zip(stage.path, stage.filtered) where !isFiltered {
			let pathSecret = stage.unfilteredPathSecrets[pathIndex]
			let publicKey = try MLS.TreeKEM.nodeKeyPair(
				provider, pathSecret: pathSecret
			).publicKey
			let recipients = resolution(of: step.sibling).filter {
				!excludedNodeIndices.contains($0)
			}
			let ciphertexts = try recipients.map {
				recipientNode -> MLS.HpkeCiphertext in
				let recipientKey = try recipientKey(at: recipientNode)
				let (enc, ciphertext) = try MLS.encryptWithLabel(
					provider, publicKey: recipientKey, label: "UpdatePathNode",
					context: groupContext, plaintext: pathSecret)
				return MLS.HpkeCiphertext(kemOutput: enc, ciphertext: ciphertext)
			}
			pathNodes.append(
				.init(encryptionKey: publicKey, encryptedPathSecrets: ciphertexts))
			pathIndex += 1
		}

		let rootPathSecret = stage.unfilteredPathSecrets.last ?? stage.firstPathSecret
		let commitSecret = try MLS.TreeKEM.commitSecret(
			provider, rootPathSecret: rootPathSecret)
		return (pathNodes, commitSecret)
	}

	private func recipientKey(at nodeIndex: UInt32) throws -> MLS.HpkePublicKey {
		if MLS.TreeMath.isLeaf(nodeIndex) {
			guard let record = leaf(at: .init(value: nodeIndex / 2)) else {
				throw MLS.TreeKEM.TreeError.notAMember
			}
			return record.encryptionKey
		}
		guard let parentNode = parent(at: nodeIndex) else {
			throw MLS.TreeKEM.TreeError.notAMember
		}
		return parentNode.encryptionKey
	}
}
