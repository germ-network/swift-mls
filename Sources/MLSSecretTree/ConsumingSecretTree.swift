import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import SecretBytes

extension MLS.SecretTree {
	/// One node split — `ExpandWithLabel(secret, "tree", "left"/"right",
	/// Nh)` — exposed on its own because §9.2's deletion schedule makes a
	/// walk-from-the-root unusable for a *stateful* store: the first
	/// successful decrypt in an epoch consumes every node secret on its path,
	/// `encryption_secret` included, so later leaves must be reached from
	/// retained *sibling* secrets, never from the root again. `ConsumingSecretTree`
	/// walks with this primitive, caching each copath sibling and deleting each
	/// path node as it descends. `MLSKeySchedule`'s stateless `leafSecret` stays
	/// the vector-pinned oracle this walker is differentially tested against.
	package static func splitTreeNode(
		_ provider: any MLS.CipherSuiteProvider, secret: some ContiguousBytes
	) throws -> (left: SecretBytes, right: SecretBytes) {
		(
			try MLS.expandWithLabelSecret(
				provider, secret: secret, label: "tree",
				context: Data("left".utf8), length: provider.hashSize),
			try MLS.expandWithLabelSecret(
				provider, secret: secret, label: "tree",
				context: Data("right".utf8), length: provider.hashSize)
		)
	}

	/// Raised by `ConsumingSecretTree` when a leaf's covering subtree has
	/// already been fully consumed — a replay/reuse signal, not a derivation
	/// failure. `package` because it is a composing layer (the profile's message
	/// layer, the extensions' exporter) that surfaces it to callers, not this
	/// module.
	package enum SecretTreeError: Error, Sendable, Equatable {
		case subtreeExhausted
	}

	/// The §9.2-conforming secret-tree state: a map of *live* node
	/// secrets, seeded with `[root: encryption_secret]`, that consumes as
	/// it descends. Deriving a leaf deletes every path node it passes and
	/// caches every copath sibling — so after the first derivation the
	/// root (the epoch's `encryption_secret` itself, per §9.2's worked
	/// example) no longer exists in any representation, and later leaves
	/// are reached from retained siblings. `MLSKeySchedule`'s stateless
	/// `leafSecret` walks from the root every time and therefore cannot be
	/// the store; it remains the vector-pinned oracle this walker is
	/// differentially tested against.
	///
	/// `package`: it is the §9.2 consuming mechanism, homed here beside its
	/// `splitTreeNode` primitive; a composer (the profile's message-secret
	/// store, the extensions' exporter tree) owns the consume *timing* and
	/// §15.3 bounds.
	package struct ConsumingSecretTree: Sendable {
		package private(set) var nodeSecrets: [UInt32: SecretBytes]
		package let leafCount: MLS.LeafCount

		/// `encryptionSecret` is `some ContiguousBytes` so the epoch's
		/// (zeroizing) `encryption_secret` seeds the tree directly, staying in
		/// zeroizing storage — the retained node secrets it splits into are
		/// `SecretBytes` too, so no unscrubbed `Data` copy of a ratchet secret
		/// is minted here.
		package init(encryptionSecret: some ContiguousBytes, leafCount: MLS.LeafCount)
			throws
		{
			self.leafCount = leafCount
			self.nodeSecrets = [
				MLS.TreeMath.root(leafCount: leafCount):
					try SecretBytes(bytes: encryptionSecret)
			]
		}

		/// Restores a consuming tree from a decoded snapshot
		/// (spec/snapshot.md §4.3 SecretTreeState): the retained node-secret
		/// frontier verbatim. Distinct from `init(encryptionSecret:leafCount:)`,
		/// which seeds `[root: encryption_secret]` for a *fresh* epoch — a
		/// restored tree has already consumed down to whatever frontier the
		/// snapshot holds, so seeding the root would resurrect a consumed
		/// secret.
		package init(
			restoringNodeSecrets nodeSecrets: [UInt32: SecretBytes],
			leafCount: MLS.LeafCount
		) {
			self.leafCount = leafCount
			self.nodeSecrets = nodeSecrets
		}

		/// Derives (and consumes toward) the leaf's secret. Throws
		/// `SecretTreeError.subtreeExhausted` when the subtree covering this
		/// leaf has already been fully consumed — a replay/reuse signal, not a
		/// derivation failure.
		package mutating func consumeLeafSecret(
			for leafIndex: MLS.LeafIndex,
			_ provider: any MLS.CipherSuiteProvider
		) throws -> SecretBytes {
			let leafNode = 2 * leafIndex.value
			guard leafIndex.value < leafCount.value else {
				throw MLS.CryptoError.invalidKey
			}
			if let ready = nodeSecrets.removeValue(forKey: leafNode) {
				return ready
			}
			// Climb until a held ancestor, then split back down.
			let path =
				[leafNode]
				+ MLS.TreeMath.directPath(from: leafNode, leafCount: leafCount)
				.map(\.path)
			guard
				let heldLevel = path.firstIndex(where: {
					nodeSecrets[$0] != nil
				}), heldLevel > 0
			else {
				throw SecretTreeError.subtreeExhausted
			}
			var nodeIndex = path[heldLevel]
			var secret = nodeSecrets.removeValue(forKey: nodeIndex)!
			for level in stride(from: heldLevel - 1, through: 0, by: -1) {
				let child = path[level]
				let (left, right) = try MLS.SecretTree.splitTreeNode(
					provider, secret: secret)
				let goingLeft = MLS.TreeMath.left(nodeIndex) == child
				// Cache the sibling we are not taking; the taken side is
				// consumed by the descent itself.
				let sibling =
					goingLeft
					? MLS.TreeMath.right(nodeIndex)
					: MLS.TreeMath.left(nodeIndex)
				nodeSecrets[sibling] = goingLeft ? right : left
				secret = goingLeft ? left : right
				nodeIndex = child
			}
			return secret
		}
	}
}
