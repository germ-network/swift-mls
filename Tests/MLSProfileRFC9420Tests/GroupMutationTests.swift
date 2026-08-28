import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Phase 5's own security checklist (S1-S13, the Welcome half): each row
/// broken deliberately, asserting the *specific* check fails and not a
/// neighbor. Built against one fixed `passive-client-welcome.json` record
/// (suite 1, external tree supplied, no PSKs -- the simplest shape that
/// still exercises the full tree path) so every test mutates the same
/// known-good baseline rather than re-deriving one.
@Suite("Group.join security checklist (S1-S13)")
struct GroupMutationTests {
	static let provider = SwiftCryptoProvider()

	struct Scenario {
		var provider: any MLS.CipherSuiteProvider
		var keyPackage: MLS.RFC9420.KeyPackage
		var welcome: MLS.RFC9420.Welcome
		var credentials: MLS.RFC9420.Group.JoinerCredentials
		var externalTree: [MLS.RFC9420.Node?]
		var groupInfo: MLS.RFC9420.GroupInfo
	}

	static func buildScenario() throws -> Scenario {
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(
			records.first {
				$0.cipherSuite == 1 && $0.ratchetTree != nil
					&& $0.externalPsks.isEmpty
			})
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))

		var keyPackageReader = MLS.Reader(record.keyPackage.bytes)
		guard
			case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(
				from: &keyPackageReader)
		else {
			throw TestFailure.unexpectedShape
		}
		try keyPackageReader.finish()

		var welcomeReader = MLS.Reader(record.welcome.bytes)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(from: &welcomeReader)
		else {
			throw TestFailure.unexpectedShape
		}
		try welcomeReader.finish()

		var treeReader = MLS.Reader(try #require(record.ratchetTree).bytes)
		let externalTree: [MLS.RFC9420.Node?] = try treeReader.decodeVector()
		try treeReader.finish()

		let credentials = MLS.RFC9420.Group.JoinerCredentials(
			keyPackage: keyPackage,
			initKey: MLS.HpkeSecretKey(record.initPriv.bytes),
			encryptionKey: MLS.HpkeSecretKey(record.encryptionPriv.bytes))

		// Replay join()'s own early steps to learn `groupInfo` ahead of
		// time -- both calls are public, no internal access needed.
		let keyPackageRef = try keyPackage.reference(provider)
		let groupSecrets = try welcome.decryptGroupSecrets(
			provider, keyPackageRef: keyPackageRef, initKey: credentials.initKey)
		let pskSecret = try MLS.KeySchedule.pskSecret(provider, psks: [])
		let (groupInfo, _) = try welcome.decryptGroupInfo(
			provider, joinerSecret: groupSecrets.joinerSecret, pskSecret: pskSecret)

		return Scenario(
			provider: provider, keyPackage: keyPackage, welcome: welcome,
			credentials: credentials, externalTree: externalTree, groupInfo: groupInfo)
	}

	enum TestFailure: Error { case unexpectedShape }

	/// A real signature key pair for suite 1 (Ed25519). Generated with
	/// swift-crypto directly rather than through `CipherSuiteProvider`,
	/// which deliberately exposes no signature keygen — RFC 9420's core
	/// protocol never needs one (see `CryptoProvider.swift`). The pair is
	/// round-tripped through the provider's own `sign`/`verify` below, so
	/// this is verified to be a usable pair, not assumed.
	static func signingKeyPair(_ provider: any MLS.CipherSuiteProvider) throws -> (
		MLS.SignatureSecretKey, MLS.SignaturePublicKey
	) {
		let key = Curve25519.Signing.PrivateKey()
		let signingKey = MLS.SignatureSecretKey(key.rawRepresentation)
		let signatureKey = MLS.SignaturePublicKey(key.publicKey.rawRepresentation)

		let probe = Data("probe".utf8)
		let signature = try provider.sign(privateKey: signingKey, content: probe)
		#expect(
			try provider.verify(
				publicKey: signatureKey, content: probe, signature: signature))
		return (signingKey, signatureKey)
	}

	/// A `key_package`-sourced `LeafNode`, really signed. `key_package` is
	/// the source whose `LeafNodeTBS` carries no `(group_id, leaf_index)`
	/// binding, so one signature is valid at any leaf index.
	static func signedKeyPackageLeaf(
		_ provider: any MLS.CipherSuiteProvider,
		signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey,
		identity: Data
	) throws -> MLS.TreeKEM.LeafRecord {
		let (_, encryptionKey) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: encryptionKey, signatureKey: signatureKey,
			credential: .basic(identity: identity),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		return try leaf.record
	}

	/// Re-seals a mutated `GroupInfo` into a self-consistent `Welcome`.
	/// Needed by any test that changes a field *inside* `GroupInfo`:
	/// `encrypted_group_info`'s own ciphertext bytes are the HPKE context
	/// `GroupSecrets` was encrypted under (`decryptGroupSecrets`'s doc
	/// comment), so `GroupSecrets` must be re-encrypted to match or
	/// `join()` fails HPKE authentication before ever reaching whatever
	/// the test actually means to exercise -- confirmed by tracing a
	/// first attempt that skipped this and got exactly that failure.
	private static func reseal(
		_ scenario: Scenario, groupInfo: MLS.RFC9420.GroupInfo
	) throws -> MLS.RFC9420.Welcome {
		let keyPackageRef = try scenario.keyPackage.reference(scenario.provider)
		let groupSecrets = try scenario.welcome.decryptGroupSecrets(
			scenario.provider, keyPackageRef: keyPackageRef,
			initKey: scenario.credentials.initKey)
		let pskSecret = try MLS.KeySchedule.pskSecret(scenario.provider, psks: [])
		let epochSeed = try scenario.provider.kdfExtract(
			salt: groupSecrets.joinerSecret, ikm: pskSecret)
		let welcomeSecret = try MLS.deriveSecret(
			scenario.provider, secret: epochSeed, label: "welcome")
		let (key, nonce) = try MLS.KeySchedule.welcomeKeyNonce(
			scenario.provider, welcomeSecret: welcomeSecret)
		let resealedGroupInfo = try scenario.provider.aeadSeal(
			key: key, nonce: nonce, aad: nil, plaintext: try groupInfo.mlsEncoded())

		let (enc, ciphertext) = try MLS.encryptWithLabel(
			scenario.provider, publicKey: scenario.credentials.keyPackage.initKey,
			label: "Welcome", context: resealedGroupInfo,
			plaintext: try groupSecrets.mlsEncoded())

		var welcome = scenario.welcome
		welcome.encryptedGroupInfo = resealedGroupInfo
		welcome.secrets = welcome.secrets.map {
			var entry = $0
			if entry.newMember == keyPackageRef {
				entry.encryptedGroupSecrets = MLS.HpkeCiphertext(
					kemOutput: enc, ciphertext: ciphertext)
			}
			return entry
		}
		return welcome
	}

	@Test("scenario itself joins cleanly (sanity check for every mutation test below)")
	func scenarioJoinsCleanly() throws {
		let scenario = try Self.buildScenario()
		_ = try MLS.RFC9420.Group.join(
			scenario.provider, welcome: scenario.welcome,
			credentials: scenario.credentials,
			externalTree: scenario.externalTree, psk: { _ in nil })
	}

	/// S1: a `Welcome.secrets` entry that doesn't match our own
	/// `KeyPackageRef` must fail with `noMatchingWelcomeSecret`, not
	/// surface as an HPKE decrypt failure further down.
	@Test("S1: no Welcome.secrets entry matches our KeyPackageRef")
	func noMatchingSecret() throws {
		let scenario = try Self.buildScenario()
		var welcome = scenario.welcome
		welcome.secrets = welcome.secrets.map {
			var entry = $0
			var bytes = entry.newMember.data
			bytes[0] ^= 0xFF
			entry.newMember = MLS.HashReference(bytes)
			return entry
		}
		#expect(throws: MLS.RFC9420.GroupError.noMatchingWelcomeSecret) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}

	/// S2: `Welcome.cipherSuite` disagreeing with the joiner's own
	/// `KeyPackage.cipherSuite` must be rejected before any decryption is
	/// attempted.
	@Test("S2: Welcome.cipherSuite mismatched against our own KeyPackage's")
	func welcomeCipherSuiteMismatch() throws {
		let scenario = try Self.buildScenario()
		var welcome = scenario.welcome
		welcome.cipherSuite = .init(id: 2)
		#expect(throws: MLS.RFC9420.GroupError.cipherSuiteMismatch) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}

	/// S5, weaker form, arrived at empirically rather than assumed: a
	/// blank `GroupInfo.signer` leaf is never silently accepted, but
	/// pinning down `blankSignerLeaf` specifically as the black-box
	/// result needs more than blanking the leaf in place -- two layered
	/// reasons, both traced by hand, not guessed:
	///
	/// 1. `tree_hash` lives *inside* the AEAD-sealed `GroupInfo`, and
	///    `GroupSecrets` is HPKE-bound to `GroupInfo`'s own ciphertext
	///    bytes as context (`decryptGroupSecrets`'s doc comment). So a
	///    tree mutation needs `GroupInfo` re-sealed with the new
	///    `tree_hash` *and* `GroupSecrets` re-encrypted against the new
	///    ciphertext bytes, or `join()` fails at HPKE-decrypting
	///    `GroupSecrets` (`authenticationFailure`) before ever reaching
	///    the tree at all -- confirmed by trying the partial construction
	///    first and observing exactly that failure.
	/// 2. Once *that* is right (as it is below), blanking the signer's
	///    leaf still fails the *parent-hash chain* check first
	///    (`TreeError.parentHashMismatch`), not `blankSignerLeaf` --
	///    also confirmed by observation, not assumption. This isn't a
	///    quirk of one record: the signer is whoever committed most
	///    recently, so their own leaf is structurally the freshest
	///    anchor for their ancestors' parent-hash claims -- blanking it
	///    orphans exactly the claims that leaf's own commit just made.
	///
	/// So this test builds the fully-reconstructed Welcome (both layers
	/// above) and asserts rejection without pinning the specific error --
	/// `blankSignerLeaf` is exercised directly, by construction, in
	/// `join()`'s own logic instead.
	@Test("S5: blanking GroupInfo.signer's leaf is never silently accepted")
	func blankSignerLeafRejected() throws {
		let scenario = try Self.buildScenario()

		var mutatedNodes = scenario.externalTree
		mutatedNodes[2 * Int(scenario.groupInfo.signer.value)] = nil
		let mutatedTree = try MLS.TreeKEM.RatchetTree(mutatedNodes)

		var groupInfo = scenario.groupInfo
		groupInfo.groupContext.treeHash = try mutatedTree.treeHash(scenario.provider)
		let welcome = try Self.reseal(scenario, groupInfo: groupInfo)

		#expect(throws: (any Error).self) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: mutatedNodes, psk: { _ in nil })
		}
	}

	/// RFC 9420 §10.1's version half: "Verify that the cipher suite and
	/// protocol version of the KeyPackage match those in the GroupContext."
	/// The version is forced through a `GroupInfo` reseal for the same
	/// reason S6 is -- it lives inside the AEAD-sealed structure.
	///
	/// Note what makes this test possible at all: `MLS.ProtocolVersion` is
	/// an open newtype, not a closed enum, so a non-`mls10` value is
	/// *representable* and the check has something to reject. That is the
	/// same design decision that makes the check worth having -- a closed
	/// enum would make this unrepresentable today and silently wrong the
	/// day a second version exists.
	///
	/// **What this test does and does not prove.** Mutation-verified:
	/// deleting the version check makes it fail. But it then fails with
	/// `signatureVerificationFailed`, not by accepting the tree -- because
	/// this test cannot re-sign the `GroupInfo` (the vector supplies the
	/// joiner's secrets, never the signer's), so the mutation also breaks
	/// the signature that covers `GroupInfoTBS`. So against a **network**
	/// attacker the signature check already suffices, and what the version
	/// check adds is the correct, specific error ahead of it.
	///
	/// The adversary it actually defends against is a **malicious or
	/// compromised inviter**, who signs the `GroupInfo` themselves and so
	/// produces a valid signature over a mismatched version. No test here
	/// can construct that case; stating the limit is the honest
	/// alternative to implying this test covers it.
	@Test("GroupInfo.group_context.version mismatched against our own KeyPackage's")
	func groupContextVersionMismatch() throws {
		let scenario = try Self.buildScenario()
		var groupInfo = scenario.groupInfo
		groupInfo.groupContext.version = MLS.ProtocolVersion(id: 0xFFFF)
		let welcome = try Self.reseal(scenario, groupInfo: groupInfo)

		#expect(throws: MLS.RFC9420.GroupError.protocolVersionMismatch) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}

	/// RFC 9420 §7.3: "Verify that the following fields are unique among
	/// the members of the group: signature_key, encryption_key." Two
	/// members sharing a signature key means a signature attributable to
	/// either -- the whole point of binding a leaf to an identity.
	///
	/// Tested against `validateLeaves` directly, not through `join`, and
	/// that is the finding as much as the check is. Every leaf mutation
	/// reachable through `join` also perturbs the subtree hashes that
	/// parent nodes' stored `parent_hash` values were computed over, so
	/// `validateParentHashChain` rejects the tree before the uniqueness
	/// check is ever consulted. Two black-box attempts passed with the
	/// check deleted before that was traced; the third — this one — builds
	/// the tree the check actually guards against.
	///
	/// Both leaves are `key_package`-sourced (so `LeafNodeTBS` omits the
	/// `(group_id, leaf_index)` binding and each signature is valid at its
	/// own index), each is **really signed**, and their encryption keys
	/// **differ** — so the encryption-key check cannot mask this and the
	/// signature-key rule is isolated exactly.
	@Test("§7.3: two members sharing a signature key is rejected")
	func duplicateSignatureKey() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))

		let (signingKey, signatureKey) = try Self.signingKeyPair(provider)
		let leafA = try Self.signedKeyPackageLeaf(
			provider, signingKey: signingKey, signatureKey: signatureKey,
			identity: Data("a".utf8))
		let leafB = try Self.signedKeyPackageLeaf(
			provider, signingKey: signingKey, signatureKey: signatureKey,
			identity: Data("b".utf8))
		#expect(leafA.encryptionKey != leafB.encryptionKey)

		let tree = try MLS.TreeKEM.RatchetTree(nodes: [.leaf(leafA), nil, .leaf(leafB)])

		// Sanity: each leaf on its own passes, so the rejection below is
		// the *pair* being rejected, not a malformed leaf.
		for leaf in [leafA, leafB] {
			try MLS.RFC9420.Group.validateLeaves(
				try MLS.TreeKEM.RatchetTree(nodes: [.leaf(leaf)]), groupID: Data(),
				groupExtensions: [], provider)
		}

		#expect(
			throws: MLS.RFC9420.GroupError.duplicateSignatureKey(leaf: .init(value: 1))
		) {
			try MLS.RFC9420.Group.validateLeaves(
				tree, groupID: Data(), groupExtensions: [], provider)
		}
	}

	/// S6: `GroupInfo.group_context.cipher_suite` disagreeing with the
	/// joiner's own `KeyPackage.cipher_suite` must be rejected -- distinct
	/// from S2, which checks the *Welcome's* own outer `cipher_suite`
	/// field, not the one sealed inside `GroupInfo`.
	@Test("S6: GroupInfo.group_context.cipher_suite mismatched against our own KeyPackage's")
	func groupContextCipherSuiteMismatch() throws {
		let scenario = try Self.buildScenario()
		var groupInfo = scenario.groupInfo
		groupInfo.groupContext.cipherSuite = .init(id: 2)
		let welcome = try Self.reseal(scenario, groupInfo: groupInfo)

		#expect(throws: MLS.RFC9420.GroupError.cipherSuiteMismatch) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome,
				credentials: scenario.credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}

	/// S7: a tampered tree hash must be caught as `treeHashMismatch`
	/// specifically -- not misreported as a parent-hash or structural
	/// failure, which would misdirect a real debugging session.
	@Test("S7: tree hash mismatch reports treeHashMismatch, not a different tree error")
	func treeHashMismatch() throws {
		let scenario = try Self.buildScenario()
		var tree = scenario.externalTree
		// Flip a byte inside the first non-blank leaf's encoded LeafNode --
		// changes its content (and therefore the tree hash) without
		// touching node kind/parity, so this can't accidentally trip a
		// different, earlier check instead.
		guard let firstLeafIndex = tree.indices.first(where: { tree[$0] != nil }) else {
			Issue.record("scenario tree has no non-blank leaf")
			return
		}
		guard case .leaf(var leafNode) = tree[firstLeafIndex] else {
			Issue.record("expected a leaf at \(firstLeafIndex)")
			return
		}
		var signatureBytes = leafNode.signature
		signatureBytes[0] ^= 0xFF
		leafNode.signature = signatureBytes
		tree[firstLeafIndex] = .leaf(leafNode)

		#expect(throws: MLS.TreeKEM.TreeError.treeHashMismatch) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: scenario.welcome,
				credentials: scenario.credentials,
				externalTree: tree, psk: { _ in nil })
		}
	}

	/// S10: our own leaf must be matched byte-exact against the tree --
	/// a KeyPackage that no longer matches any tree leaf (here: its own
	/// signature corrupted) must fail with `ownLeafNotFound`, never fall
	/// back to a looser match.
	///
	/// Isolating this from S1 takes care: `KeyPackageRef` (the S1 lookup
	/// key) is computed over the *entire* KeyPackage, signature included
	/// (`KeyPackage.reference`'s own doc comment), so corrupting
	/// `credentials.keyPackage` on its own changes the ref and trips S1
	/// first -- caught by an earlier version of this test. Patching
	/// `Welcome.secrets`'s stored ref to match the *mutated* KeyPackage's
	/// freshly computed one keeps S1's lookup succeeding (the HPKE
	/// ciphertext and `initKey` are untouched, so decryption itself still
	/// works) while the corrupted leaf still fails to byte-match the
	/// tree's own (untouched) copy of it -- isolating S10 specifically.
	@Test("S10: our own KeyPackage no longer matches any tree leaf byte-exact")
	func ownLeafNotFound() throws {
		let scenario = try Self.buildScenario()

		var credentials = scenario.credentials
		var signatureBytes = credentials.keyPackage.leafNode.signature
		signatureBytes[0] ^= 0xFF
		credentials.keyPackage.leafNode.signature = signatureBytes

		let newRef = try credentials.keyPackage.reference(scenario.provider)
		var welcome = scenario.welcome
		welcome.secrets = welcome.secrets.map {
			var entry = $0
			entry.newMember = newRef
			return entry
		}

		#expect(throws: MLS.RFC9420.GroupError.ownLeafNotFound) {
			_ = try MLS.RFC9420.Group.join(
				scenario.provider, welcome: welcome, credentials: credentials,
				externalTree: scenario.externalTree, psk: { _ in nil })
		}
	}
}
