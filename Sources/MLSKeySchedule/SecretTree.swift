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
