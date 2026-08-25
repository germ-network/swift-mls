import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

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
		numLeaves: UInt32
	) throws -> Data {
		// Out of range must not fall through: with no path to walk, the
		// loop below would silently hand back `encryptionSecret` itself —
		// the tree's root secret — instead of failing.
		guard leafIndex < numLeaves else { throw MLS.CryptoError.invalidKey }

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
		_ provider: any MLS.CipherSuiteProvider, leafSecret: Data
	) throws -> Data {
		try MLS.deriveSecret(provider, secret: leafSecret, label: "handshake")
	}

	public static func applicationRatchetSecret(
		_ provider: any MLS.CipherSuiteProvider, leafSecret: Data
	) throws -> Data {
		try MLS.deriveSecret(provider, secret: leafSecret, label: "application")
	}

	public struct RatchetStep: Sendable {
		public let key: Data
		public let nonce: Data
		/// Feeds back into `ratchetStep` as `secret`, for `generation + 1`.
		/// The caller owns discarding it once the next generation is
		/// derived — RFC 9420's forward secrecy comes from that discard,
		/// not from anything this function does.
		public let nextSecret: Data
	}

	/// One step of a handshake or application ratchet: `ExpandWithLabel`
	/// with the generation as a 4-byte big-endian context, for `"key"`,
	/// `"nonce"`, and `"secret"` in parallel — not in sequence, so deriving
	/// the next secret doesn't depend on having derived this generation's
	/// key or nonce first.
	public static func ratchetStep(
		_ provider: any MLS.CipherSuiteProvider,
		secret: Data,
		generation: UInt32
	) throws -> RatchetStep {
		try RatchetStep(
			key: MLS.deriveTreeSecret(
				provider, secret: secret, label: "key", generation: generation,
				length: provider.aeadKeySize),
			nonce: MLS.deriveTreeSecret(
				provider, secret: secret, label: "nonce", generation: generation,
				length: provider.aeadNonceSize),
			nextSecret: MLS.deriveTreeSecret(
				provider, secret: secret, label: "secret", generation: generation,
				length: provider.hashSize)
		)
	}
}
