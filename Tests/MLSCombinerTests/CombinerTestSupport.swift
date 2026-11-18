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

	static func member(
		_ name: String, lifetime: MLS.RFC9420.Lifetime = .init(notBefore: 0, notAfter: .max)
	) throws -> Member {
		let (signingKey, signatureKey) = try signingKeyPair()
		let classical = try keyPackage(
			name, provider: provider, signingKey: signingKey,
			signatureKey: signatureKey,
			lifetime: lifetime)
		let pq = try keyPackage(
			name, provider: pqProvider, signingKey: signingKey,
			signatureKey: signatureKey, lifetime: lifetime)
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
		signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey,
		lifetime: MLS.RFC9420.Lifetime
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
			source: .keyPackage(lifetime),
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
			classicalProvider: provider, pqProvider: pqProvider,
			lifetimeCheck: .unchecked,
			codepoints: codepoints)
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

	/// An `APQWelcome` for `peer`, built group by group as `establish` builds it but
	/// with the `APQInfo` and the `apq_psk` binding under the caller's control — the
	/// non-conforming founder cases a conforming `establish` cannot produce. `info`
	/// receives the two group ids and returns the `APQInfo` both halves carry
	/// (default: the truthful one). `pqFounder` founds the PQ half under a different
	/// identity. With `bindApqPsk` false the classical commit
	/// omits the `apq_psk` `PreSharedKey` proposal. Only the Welcomes are built, not
	/// the founder's pair.
	static func welcomePair(
		founder: Member, peer: Member, pqFounder: Member? = nil, bindApqPsk: Bool = true,
		info: ((_ classicalID: Data, _ pqID: Data) -> MLS.Combiner.APQInfo)? = nil
	) throws -> MLS.Combiner.APQWelcome {
		let codepoints = MLS.Combiner.Codepoints.deployed
		return try codepoints.withWireWidth {
			let classicalCreation = try halfCreation(founder: founder, peer: peer)
			let pqCreation = try halfCreation(
				founder: pqFounder ?? founder, peer: peer, half: .pq)
			let apqInfo =
				info?(classicalCreation.groupID, pqCreation.groupID)
				?? MLS.Combiner.APQInfo(
					tSessionGroupID: classicalCreation.groupID,
					pqSessionGroupID: pqCreation.groupID, mode: 0,
					tCipherSuite: provider.cipherSuite,
					pqCipherSuite: pqProvider.cipherSuite, tEpoch: 1, pqEpoch: 1
				)
			let infoExtension = try apqInfo.asExtension(
				type: codepoints.apqInfoExtensionType)
			let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 1)
			let attestationProposal = MLS.RFC9420.ProposalOrRef.proposal(
				try attestation.proposal(componentID: codepoints.apqComponentID))

			let pqEpoch0 = try MLS.RFC9420.Group.create(
				pqProvider, groupID: pqCreation.groupID,
				leafNode: pqCreation.leafNode,
				leafSecretKey: pqCreation.leafSecretKey,
				extensions: [infoExtension], epochSecret: pqCreation.epochSecret,
				lifetimeCheck: .unchecked)
			let pqTransition = try pqEpoch0.committing(
				pqProvider,
				proposals: [
					.proposal(.add(pqCreation.peerKeyPackage)),
					attestationProposal,
				],
				signingKey: pqCreation.signingKey,
				randomness: pqCreation.randomness,
				lifetimeCheck: .unchecked,
				includePath: false, psk: { _ in nil })
			let pqAdopted = pqTransition.group
			let pqSent = pqTransition.takeOutput()
			guard let pqWelcome = pqSent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			var pqGroup = try pqSent.takePending().apply(onto: pqAdopted).group

			var proposals = [
				MLS.RFC9420.ProposalOrRef.proposal(
					.add(classicalCreation.peerKeyPackage))
			]
			var store = MLS.Combiner.PSKStore()
			if bindApqPsk {
				let apqPsk = try MLS.Combiner.ExportedPsk.export(
					from: &pqGroup, pqProvider,
					componentID: codepoints.apqComponentID)
				store.register(apqPsk)
				proposals.append(
					.proposal(
						apqPsk.proposal(
							nonce: provider.randomBytes(
								provider.hashSize))))
			}
			proposals.append(attestationProposal)

			let classicalEpoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: classicalCreation.groupID,
				leafNode: classicalCreation.leafNode,
				leafSecretKey: classicalCreation.leafSecretKey,
				extensions: [infoExtension],
				epochSecret: classicalCreation.epochSecret,
				lifetimeCheck: .unchecked)
			let classicalTransition = try classicalEpoch0.committing(
				provider, proposals: proposals,
				signingKey: classicalCreation.signingKey,
				randomness: classicalCreation.randomness,
				lifetimeCheck: .unchecked, includePath: false,
				psk: store.resolver())
			guard let classicalWelcome = classicalTransition.takeOutput().welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			return MLS.Combiner.APQWelcome(
				tWelcome: classicalWelcome, pqWelcome: pqWelcome)
		}
	}
}
