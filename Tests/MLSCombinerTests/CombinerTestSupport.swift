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
/// them). The "PQ" half in these tests runs a different classical suite from the "T"
/// half, as a conforming pair must: the combiner is generic over cipher suites, so its
/// orchestration is exercised without a real PQ suite (which is downstream,
/// twomlspq-swift). Suites 1 and 3 differ only in AEAD, so this fixture proves
/// suite-id separation, not provider separation.
enum CombinerTestSupport {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!
	static let pqProvider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519ChaCha)!

	/// Which half of a pair a fixture is built for.
	enum Half { case classical, pq }

	static func bytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	struct Member {
		let identity: Data
		let signingKey: MLS.SignatureSecretKey
		let signatureKey: MLS.SignaturePublicKey
		let leafSecretKey: MLS.HpkeSecretKey
		let initSecretKey: MLS.HpkeSecretKey
		let keyPackage: MLS.RFC9420.KeyPackage
		let pqLeafSecretKey: MLS.HpkeSecretKey
		let pqInitSecretKey: MLS.HpkeSecretKey
		let pqKeyPackage: MLS.RFC9420.KeyPackage

		var joinCredentials: MLS.RFC9420.Group.JoinerCredentials {
			.init(
				keyPackage: keyPackage, initKey: initSecretKey,
				encryptionKey: leafSecretKey)
		}

		var pqJoinCredentials: MLS.RFC9420.Group.JoinerCredentials {
			.init(
				keyPackage: pqKeyPackage, initKey: pqInitSecretKey,
				encryptionKey: pqLeafSecretKey)
		}
	}

	static func signingKeyPair() throws -> (MLS.SignatureSecretKey, MLS.SignaturePublicKey) {
		let key = Curve25519.Signing.PrivateKey()
		return (
			try MLS.SignatureSecretKey(key.rawRepresentation),
			MLS.SignaturePublicKey(key.publicKey.rawRepresentation)
		)
	}

	static func member(_ name: String) throws -> Member {
		let (signingKey, signatureKey) = try signingKeyPair()
		let classical = try keyPackage(
			name, provider: provider, signingKey: signingKey, signatureKey: signatureKey)
		let pq = try keyPackage(
			name, provider: pqProvider, signingKey: signingKey, signatureKey: signatureKey)
		return Member(
			identity: Data(name.utf8), signingKey: signingKey,
			signatureKey: signatureKey,
			leafSecretKey: classical.leafSecret, initSecretKey: classical.initSecret,
			keyPackage: classical.keyPackage,
			pqLeafSecretKey: pq.leafSecret, pqInitSecretKey: pq.initSecret,
			pqKeyPackage: pq.keyPackage)
	}

	private static func keyPackage(
		_ name: String, provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey
	) throws -> (
		leafSecret: MLS.HpkeSecretKey, initSecret: MLS.HpkeSecretKey,
		keyPackage: MLS.RFC9420.KeyPackage
	) {
		let (leafSecret, leafPublic) = try provider.hpkeGenerateKeyPair()
		let (initSecret, initPublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublic, signatureKey: signatureKey,
			credential: .basic(identity: Data(name.utf8)),
			capabilities: .init(
				versions: [.mls10],
				cipherSuites: [.curve25519Aes128, .curve25519ChaCha],
				extensions: [], proposals: [.init(.appDataUpdate)],
				credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: provider.cipherSuite, initKey: initPublic,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return (leafSecret, initSecret, keyPackage)
	}

	/// A `HalfCreation` for `founder` adding `peer`, with fresh randomness/ids.
	static func halfCreation(
		founder: Member, peer: Member, half: Half = .classical
	) throws -> MLS.Combiner.HalfCreation {
		let halfProvider = half == .classical ? provider : pqProvider
		return MLS.Combiner.HalfCreation(
			groupID: halfProvider.randomBytes(halfProvider.hashSize),
			leafNode: (half == .classical ? founder.keyPackage : founder.pqKeyPackage)
				.leafNode,
			leafSecretKey: half == .classical
				? founder.leafSecretKey : founder.pqLeafSecretKey,
			signingKey: founder.signingKey,
			epochSecret: SecretBytes(randomByteCount: halfProvider.hashSize),
			randomness: try .generate(halfProvider),
			peerKeyPackage: half == .classical ? peer.keyPackage : peer.pqKeyPackage)
	}

	/// Establish a founder+peer pair and join it, returning both sides' groups.
	static func establishedPair(
		founder: Member, peer: Member, codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (founder: MLS.Combiner.CombinerGroup, peer: MLS.Combiner.CombinerGroup) {
		let (group, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: try halfCreation(founder: founder, peer: peer),
			pq: try halfCreation(founder: founder, peer: peer, half: .pq),
			mode: 0,
			classicalProvider: provider, pqProvider: pqProvider, codepoints: codepoints)
		let joined = try MLS.Combiner.CombinerGroup.join(
			welcome: welcome,
			classicalCredentials: peer.joinCredentials,
			pqCredentials: peer.pqJoinCredentials,
			classicalProvider: provider, pqProvider: pqProvider, codepoints: codepoints)
		return (group, joined)
	}

	/// A Basic credential for `identity` — the membership-consistency checks
	/// compare only these.
	static func credential(_ identity: String) -> MLS.RFC9420.Credential {
		.basic(identity: Data(identity.utf8))
	}
}
