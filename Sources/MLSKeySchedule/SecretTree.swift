import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import SecretBytes

/// RFC 9420 §9's secret tree: `encryption_secret` sits at the root of a
/// tree with one leaf per group member (`MLS.TreeMath`'s pure index
/// arithmetic, not `MLSTreeKEM`'s member/LeafNode content — those are
/// unrelated trees that happen to share the same array-indexing scheme).
/// Two independent ratchets — handshake and application — hang off each
/// leaf, each producing a fresh key/nonce/next-secret per generation.
extension MLS.KeySchedule {
	/// Walks from `encryptionSecret` (the tree's root) down to one leaf,
	/// splitting `ExpandWithLabel(secret, "tree", "left"/"right", Nh)` at
	/// every node on the way. `numLeaves == 1` returns `encryptionSecret`
	/// itself unchanged — a one-member tree has no internal nodes to
	/// split, the root already is the only leaf.
	public static func leafSecret(
		_ provider: any MLS.CipherSuiteProvider,
		encryptionSecret: Data,
		leafIndex: UInt32,
		numLeaves: MLS.LeafCount
	) throws -> Data {
		// An empty path (no derivation loop) would otherwise silently hand
		// back `encryptionSecret` itself — the tree's root secret.
		guard leafIndex < numLeaves.value else { throw MLS.CryptoError.invalidKey }

		let leafNode = 2 * leafIndex
		let nodes =
			MLS.TreeMath.directPath(from: leafNode, leafCount: numLeaves).reversed()
			.map(\.path) + [leafNode]

		var secret = encryptionSecret
		for i in 1..<nodes.count {
			let goingLeft = MLS.TreeMath.left(nodes[i - 1]) == nodes[i]
			secret = try MLS.expandWithLabel(
				provider, secret: secret, label: "tree",
				context: Data((goingLeft ? "left" : "right").utf8),
				length: provider.hashSize)
		}
		return secret
	}

	/// One node split — `ExpandWithLabel(secret, "tree", "left"/"right",
	/// Nh)` — exposed on its own because §9.2's deletion schedule makes
	/// `leafSecret`'s walk-from-the-root unusable for a *stateful* store:
	/// the first successful decrypt in an epoch consumes every node secret
	/// on its path, `encryption_secret` included, so later leaves must be
	/// reached from retained *sibling* secrets, never from the root again.
	/// The profile's consuming store walks with this primitive, caching
	/// each copath sibling and deleting each path node as it descends;
	/// `leafSecret` stays as the vector-pinned stateless oracle the store
	/// is differentially tested against.
	public static func splitTreeNode(
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

	public static func handshakeRatchetSecret(
		_ provider: any MLS.CipherSuiteProvider, leafSecret: some ContiguousBytes
	) throws -> SecretBytes {
		try MLS.deriveSecretSecret(provider, secret: leafSecret, label: "handshake")
	}

	public static func applicationRatchetSecret(
		_ provider: any MLS.CipherSuiteProvider, leafSecret: some ContiguousBytes
	) throws -> SecretBytes {
		try MLS.deriveSecretSecret(provider, secret: leafSecret, label: "application")
	}

	public struct RatchetStep: Sendable {
		/// The per-generation AEAD key and nonce — consumed in-flight by the
		/// very next seal/open, so they terminate at the AEAD as `Data`.
		public let key: Data
		public let nonce: Data
		/// Feeds back into `ratchetStep` as `secret`, for `generation + 1`.
		/// Retained (a chain head, or a cached copath secret), so it is held
		/// in zeroizing storage. The caller owns discarding it once the next
		/// generation is derived — RFC 9420's forward secrecy comes from that
		/// discard, not from anything this function does.
		public let nextSecret: SecretBytes
	}

	/// One step of a handshake or application ratchet: `ExpandWithLabel`
	/// with the generation as a 4-byte big-endian context, for `"key"`,
	/// `"nonce"`, and `"secret"` in parallel — not in sequence, so deriving
	/// the next secret doesn't depend on having derived this generation's
	/// key or nonce first.
	public static func ratchetStep(
		_ provider: any MLS.CipherSuiteProvider,
		secret: some ContiguousBytes,
		generation: UInt32
	) throws -> RatchetStep {
		try RatchetStep(
			key: MLS.deriveTreeSecret(
				provider, secret: secret, label: "key", generation: generation,
				length: provider.aeadKeySize),
			nonce: MLS.deriveTreeSecret(
				provider, secret: secret, label: "nonce", generation: generation,
				length: provider.aeadNonceSize),
			nextSecret: MLS.deriveTreeSecretSecret(
				provider, secret: secret, label: "secret", generation: generation,
				length: provider.hashSize)
		)
	}
}

extension MLS.KeySchedule {
	/// Raised by `ConsumingSecretTree` when a leaf's covering subtree has
	/// already been fully consumed — a replay/reuse signal, not a derivation
	/// failure. `package` because it is the profile's message layer that
	/// surfaces it to callers, not this module.
	package enum SecretTreeError: Error, Sendable, Equatable {
		case subtreeExhausted
	}

	/// The §9.2-conforming secret-tree state: a map of *live* node
	/// secrets, seeded with `[root: encryption_secret]`, that consumes as
	/// it descends. Deriving a leaf deletes every path node it passes and
	/// caches every copath sibling — so after the first derivation the
	/// root (the epoch's `encryption_secret` itself, per §9.2's worked
	/// example) no longer exists in any representation, and later leaves
	/// are reached from retained siblings. The stateless `leafSecret`
	/// walks from the root every time and therefore cannot be the store;
	/// it remains the vector-pinned oracle this walker is differentially
	/// tested against.
	///
	/// `package`: it is the §9.2 consuming mechanism, homed here beside its
	/// oracle and `splitTreeNode`; the profile composes it into a
	/// message-secret store and owns the consume *timing* and §15.3 bounds.
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
				let (left, right) = try MLS.KeySchedule.splitTreeNode(
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

	/// One sender's ratchet (handshake or application): the head secret,
	/// its generation, and the bounded cache of skipped-but-unconsumed
	/// (key, nonce) pairs — §15.3's three policies live in the profile's
	/// `RetentionPolicy`, and the *ratchet secrets* skipped over are
	/// consumed and deleted per §9.2 even though their derived keys are
	/// kept.
	package struct RatchetChain: Sendable {
		package var headGeneration: UInt32
		/// nil once the chain is retired (head consumed with nothing
		/// ahead retainable). Zeroizing: the whole forward chain derives from
		/// it, so its exposure is the worst case.
		package var headSecret: SecretBytes?
		/// Skipped-but-not-yet-consumed message keys: retained at rest (up to
		/// `maxSkippedKeysPerSender` per chain, across retained epochs) until a
		/// late message consumes one or the epoch is pruned — so the key half is
		/// held zeroizing like every other retained secret, copied out to `Data`
		/// only at the AEAD call. The nonce stays `Data`: it is not secret.
		package var skipped: [UInt32: (key: SecretBytes, nonce: Data)]

		package init(
			headGeneration: UInt32, headSecret: SecretBytes?,
			skipped: [UInt32: (key: SecretBytes, nonce: Data)] = [:]
		) {
			self.headGeneration = headGeneration
			self.headSecret = headSecret
			self.skipped = skipped
		}
	}
}
