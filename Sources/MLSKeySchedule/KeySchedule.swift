import Foundation
import MLSCodec
import MLSCrypto

/// RFC 9420 §8's key schedule — the anchor every profile lands on.
/// `advance` takes exactly four inputs (a secret from the previous epoch, a
/// secret from however this epoch evolves the group, a secret from however
/// PSKs are bound in, and the encoded `GroupContext` committing to
/// everything else) and produces every downstream secret. Nothing here
/// knows a wire format or a tree exists — `groupContext` is opaque `Data`,
/// already encoded by whoever calls this.
extension MLS {
	public enum KeySchedule: Sendable {
		public struct Epoch: Sendable {
			/// Carried to the group's joiners in the Welcome; not derived
			/// from `epochSecret` — it is the parent secret `epochSecret`
			/// itself is expanded from, so this and `epochSecret`'s entire
			/// fan-out are siblings, not parent/child.
			public let joinerSecret: Data
			/// Encrypts the `GroupInfo`/`Welcome` at group creation.
			public let welcomeSecret: Data
			/// This epoch's contribution to the *next* epoch's key
			/// schedule — feeds back into `advance` as `initSecret`.
			public let initSecret: Data
			public let senderDataSecret: Data
			public let encryptionSecret: Data
			public let exporterSecret: Data
			public let epochAuthenticator: Data
			public let externalSecret: Data
			public let externalPublicKey: HpkePublicKey
			public let confirmationKey: Data
			public let membershipKey: Data
			public let resumptionPsk: Data
		}

		/// The whole key schedule, one call. `initSecret` is the previous
		/// epoch's `Epoch.initSecret` (or a group's fresh genesis secret,
		/// for epoch 0). `commitSecret` is whatever the evolution mechanism
		/// (TreeKEM, or anything else a profile substitutes) produced for
		/// this commit. `pskSecret` is `MLS.KeySchedule.pskSecret(_:psks:)`,
		/// or the all-zero `Nh`-byte value when no PSK is in use — RFC 9420
		/// never lets this step be skipped, only its input be trivial.
		public static func advance(
			_ provider: any CipherSuiteProvider,
			initSecret: Data,
			commitSecret: Data,
			pskSecret: Data,
			groupContext: Data
		) throws -> Epoch {
			let joinerSeed = try provider.kdfExtract(
				salt: initSecret, ikm: commitSecret)
			let joinerSecret = try expandWithLabel(
				provider, secret: joinerSeed, label: "joiner",
				context: groupContext, length: provider.hashSize)

			return try fromJoinerSecret(
				provider, joinerSecret: joinerSecret, pskSecret: pskSecret,
				groupContext: groupContext)
		}

		/// The second half of `advance`, exposed separately because a
		/// joiner reconstructs an epoch from a `Welcome`'s joiner secret
		/// directly — it never sees `initSecret`/`commitSecret`, only what
		/// the Welcome carries.
		public static func fromJoinerSecret(
			_ provider: any CipherSuiteProvider,
			joinerSecret: Data,
			pskSecret: Data,
			groupContext: Data
		) throws -> Epoch {
			let epochSeed = try provider.kdfExtract(salt: joinerSecret, ikm: pskSecret)
			let welcomeSecret = try deriveSecret(
				provider, secret: epochSeed, label: "welcome")
			let epochSecret = try expandWithLabel(
				provider, secret: epochSeed, label: "epoch", context: groupContext,
				length: provider.hashSize)

			func derive(_ label: String) throws -> Data {
				try deriveSecret(provider, secret: epochSecret, label: label)
			}

			let externalSecret = try derive("external")
			let (_, externalPublicKey) = try provider.hpkeDeriveKeyPair(
				ikm: externalSecret)

			return try Epoch(
				joinerSecret: joinerSecret,
				welcomeSecret: welcomeSecret,
				initSecret: derive("init"),
				senderDataSecret: derive("sender data"),
				encryptionSecret: derive("encryption"),
				exporterSecret: derive("exporter"),
				epochAuthenticator: derive("authentication"),
				externalSecret: externalSecret,
				externalPublicKey: externalPublicKey,
				confirmationKey: derive("confirm"),
				membershipKey: derive("membership"),
				resumptionPsk: derive("resumption")
			)
		}

		/// RFC 9420 §8.5's MLS-Exporter: `ExpandWithLabel(DeriveSecret(
		/// exporterSecret, label), "exported", Hash(context), length)`.
		public static func exportSecret(
			_ provider: any CipherSuiteProvider,
			exporterSecret: Data,
			label: String,
			context: Data,
			length: Int
		) throws -> Data {
			let secret = try deriveSecret(
				provider, secret: exporterSecret, label: label)
			let contextHash = try provider.hash(context)
			return try expandWithLabel(
				provider, secret: secret, label: "exported", context: contextHash,
				length: length)
		}

		/// RFC 9420 §8.4's PSK secret: each PSK is folded in with an
		/// independent `Extract`, in order, over an all-zero starting
		/// accumulator — never a plain concatenation, so no PSK's
		/// contribution can be inferred without knowing every other one.
		public static func pskSecret(
			_ provider: any CipherSuiteProvider,
			psks: [(id: Data, nonce: Data, psk: Data)]
		) throws -> Data {
			let zero = Data(repeating: 0, count: provider.hashSize)
			guard let count = UInt16(exactly: psks.count) else {
				throw MLS.CryptoError.invalidKey
			}

			var secret = zero
			for (index, entry) in psks.enumerated() {
				let extracted = try provider.kdfExtract(salt: zero, ikm: entry.psk)
				let label = try pskLabel(
					id: entry.id, nonce: entry.nonce, index: UInt16(index),
					count: count)
				let input = try expandWithLabel(
					provider, secret: extracted, label: "derived psk",
					context: label, length: provider.hashSize)
				secret = try provider.kdfExtract(salt: input, ikm: secret)
			}
			return secret
		}

		/// RFC 9420 §6.3.2: the sender-data key/nonce, derived from the
		/// first `Nh` bytes of the ciphertext itself (or the whole
		/// ciphertext, if shorter) — not from any per-message secret,
		/// since the recipient doesn't know who sent a message, or its
		/// generation, until *after* decrypting the sender data that
		/// names them.
		public static func senderDataKeyNonce(
			_ provider: any CipherSuiteProvider,
			senderDataSecret: Data,
			ciphertext: Data
		) throws -> (key: Data, nonce: Data) {
			let sample = ciphertext.prefix(provider.hashSize)
			let key = try expandWithLabel(
				provider, secret: senderDataSecret, label: "key",
				context: Data(sample), length: provider.aeadKeySize)
			let nonce = try expandWithLabel(
				provider, secret: senderDataSecret, label: "nonce",
				context: Data(sample), length: provider.aeadNonceSize)
			return (key, nonce)
		}
	}
}
