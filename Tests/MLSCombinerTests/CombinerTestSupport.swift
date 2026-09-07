import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import SecretBytes
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// Shared scaffolding for the combiner tests: a curve25519 provider and a `member`
/// builder that produces a really-signed `KeyPackage` + leaf + joiner credentials —
/// ported from the profile's own test helpers (the combiner test target cannot import
/// them). The "PQ" half in these tests uses the same classical suite as the "T" half:
/// the combiner is generic over cipher suites, so its orchestration is exercised
/// without a real PQ suite (which is downstream, twomlspq-swift).
enum CombinerTestSupport {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	static func bytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	struct Member {
		let identity: Data
		let signingKey: MLS.SignatureSecretKey
		let signatureKey: MLS.SignaturePublicKey
		let leafSecretKey: MLS.HpkeSecretKey
		let initSecretKey: MLS.HpkeSecretKey
		let keyPackage: MLS.RFC9420.KeyPackage

		var joinCredentials: MLS.RFC9420.Group.JoinerCredentials {
			.init(
				keyPackage: keyPackage, initKey: initSecretKey,
				encryptionKey: leafSecretKey)
		}
	}

	static func signingKeyPair() -> (MLS.SignatureSecretKey, MLS.SignaturePublicKey) {
		let key = Curve25519.Signing.PrivateKey()
		return (
			MLS.SignatureSecretKey(key.rawRepresentation),
			MLS.SignaturePublicKey(key.publicKey.rawRepresentation)
		)
	}

	static func member(_ name: String) throws -> Member {
		let provider = Self.provider
		let (signingKey, signatureKey) = signingKeyPair()
		let (leafSecret, leafPublic) = try provider.hpkeGenerateKeyPair()
		let (initSecret, initPublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublic, signatureKey: signatureKey,
			credential: .basic(identity: Data(name.utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: .curve25519Aes128, initKey: initPublic,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return Member(
			identity: Data(name.utf8), signingKey: signingKey,
			signatureKey: signatureKey,
			leafSecretKey: leafSecret, initSecretKey: initSecret, keyPackage: keyPackage
		)
	}

	/// A `HalfCreation` for `founder` adding `peer`, with fresh randomness/ids.
	static func halfCreation(founder: Member, peer: Member) throws -> MLS.Combiner.HalfCreation
	{
		MLS.Combiner.HalfCreation(
			groupID: provider.randomBytes(provider.hashSize),
			leafNode: founder.keyPackage.leafNode,
			leafSecretKey: founder.leafSecretKey,
			signingKey: founder.signingKey,
			epochSecret: provider.randomBytes(provider.hashSize),
			randomness: try .generate(provider),
			peerKeyPackage: peer.keyPackage)
	}

	/// Establish a founder+peer pair and join it, returning both sides' groups.
	static func establishedPair(
		founder: Member, peer: Member, codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (founder: MLS.Combiner.CombinerGroup, peer: MLS.Combiner.CombinerGroup) {
		let (group, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: try halfCreation(founder: founder, peer: peer),
			pq: try halfCreation(founder: founder, peer: peer),
			mode: 0,
			classicalProvider: provider, pqProvider: provider, codepoints: codepoints)
		let joined = try MLS.Combiner.CombinerGroup.join(
			welcome: welcome,
			classicalCredentials: peer.joinCredentials,
			pqCredentials: peer.joinCredentials,
			classicalProvider: provider, pqProvider: provider, codepoints: codepoints)
		return (group, joined)
	}

	/// A minimal `RosterEntry` for a Basic identity — for the membership-consistency
	/// checks, which read only `presentation.credential`.
	static func rosterEntry(_ identity: String, leaf: UInt32) -> MLS.RFC9420.RosterEntry {
		let (_, signatureKey) = signingKeyPair()
		return MLS.RFC9420.RosterEntry(
			leaf: MLS.LeafIndex(value: leaf),
			presentation: MLS.RFC9420.CredentialPresentation(
				credential: .basic(identity: Data(identity.utf8)),
				signatureKey: signatureKey))
	}
}
