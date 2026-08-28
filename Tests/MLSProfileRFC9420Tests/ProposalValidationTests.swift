import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Phase 6a's §12.1/§12.2 validation pass. Every rejection here is reached
/// through the public `processing` API by *supplying* crafted state — the
/// `ProposalStore` route, which disturbs nothing the commit's framing
/// signature covers — or as a direct unit on `validatePolicy` where the
/// group machinery adds nothing. Sixteen of the vectors' commits carry
/// multiple by-reference proposals, which is what makes the two-slot
/// substitutions below possible without a committer's signing key.
@Suite("Proposal validation (§7.3 policy, §10.1, §12.1, §12.2)")
struct ProposalValidationTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	// MARK: fixtures

	/// First fixture whose commit carries at least `minRefs` by-reference
	/// proposals (searching epochs like RetentionTests does).
	static func fixture(minRefs: Int, requirePath: Bool = false) throws
		-> CommitRejectionTests.Fixture
	{
		let records = try VectorFile.load(
			"passive-client-handling-commit", as: [PassiveClientVector].self)
		for record in records where record.cipherSuite == 1 {
			for ei in record.epochs.indices {
				guard
					let f = try? CommitRejectionTests.buildFixture(
						record: record, epochIndex: ei, provider: provider)
				else { continue }
				guard case .commit(let commit) = f.commit.content.content
				else { continue }
				if requirePath && commit.path == nil { continue }
				let refs = commit.proposals.filter {
					if case .reference = $0 { true } else { false }
				}
				if refs.count >= minRefs { return f }
			}
		}
		throw CommitRejectionTests.Failure.shape
	}

	static func refs(of fixture: CommitRejectionTests.Fixture) throws -> [MLS.HashReference] {
		guard case .commit(let commit) = fixture.commit.content.content else {
			throw CommitRejectionTests.Failure.shape
		}
		return commit.proposals.compactMap {
			if case .reference(let ref) = $0 { ref } else { nil }
		}
	}

	static func expectProcessing(
		_ f: CommitRejectionTests.Fixture, store: MLS.RFC9420.ProposalStore,
		throws error: MLS.RFC9420.GroupError
	) {
		#expect(throws: error) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: store, psk: { _ in nil })
		}
	}

	// MARK: §10.1 — the KeyPackage signature reading, settled against vectors

	/// The RFC's literal text says the KeyPackage signature verifies "using
	/// the public key in leaf_node.credential" — which a basic credential
	/// does not contain. This test settles the reading against official
	/// vector bytes: `leaf_node.signature_key` verifies, so that is the
	/// reading this library ships. If this test ever fails, the reading is
	/// wrong — not the test.
	@Test("a vector KeyPackage's signature verifies under leaf_node.signature_key")
	func keyPackageSignatureReading() throws {
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(let kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}
		try kp.verifySignature(Self.provider)

		var tampered = kp
		tampered.signature[0] ^= 1
		#expect(throws: MLS.CryptoError.self) {
			try tampered.verifySignature(Self.provider)
		}
	}

	// MARK: §12.2 list rules, via the store route

	@Test("an Update attributed to the committer is rejected")
	func updateByCommitter() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		let ownLeaf = try #require(f.group.tree.leaf(at: f.group.myLeafIndex))
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .update(try MLS.RFC9420.LeafNode(mlsEncoded: ownLeaf.encoded)),
			sender: .member(committer))
		Self.expectProcessing(f, store: store, throws: .updateByCommitter)
	}

	@Test("a Remove naming the committer is rejected")
	func removeOfCommitter() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .remove(committer), sender: f.commit.content.sender)
		Self.expectProcessing(f, store: store, throws: .removeOfCommitter)
	}

	@Test("two Removes naming one leaf are rejected")
	func duplicateProposalForLeaf() throws {
		let f = try Self.fixture(minRefs: 2, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		// Any member that is neither the committer nor us.
		let victim = try #require(
			f.group.tree.nonBlankLeaves().map(\.0).first {
				$0 != committer && $0 != f.group.myLeafIndex
			})
		var store = f.store
		let refs = try Self.refs(of: f)
		let remove = MLS.RFC9420.StoredProposal(
			proposal: .remove(victim), sender: f.commit.content.sender)
		store[refs[0]] = remove
		store[refs[1]] = remove
		Self.expectProcessing(
			f, store: store, throws: .duplicateProposalForLeaf(leaf: victim))
	}

	@Test("two PreSharedKey proposals naming one id are rejected")
	func duplicatePreSharedKey() throws {
		let f = try Self.fixture(minRefs: 2)
		let psk = MLS.RFC9420.StoredProposal(
			proposal: .preSharedKey(
				.external(
					pskID: Data("id".utf8),
					nonce: Data(repeating: 7, count: Self.provider.hashSize))),
			sender: f.commit.content.sender)
		var store = f.store
		let refs = try Self.refs(of: f)
		store[refs[0]] = psk
		store[refs[1]] = psk
		Self.expectProcessing(f, store: store, throws: .duplicatePreSharedKey)
	}

	@Test("a psk_nonce that isn't KDF.Nh long is rejected")
	func wrongPskNonceLength() throws {
		let f = try Self.fixture(minRefs: 1)
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .preSharedKey(
				.external(pskID: Data("id".utf8), nonce: Data([1, 2, 3]))),
			sender: f.commit.content.sender)
		Self.expectProcessing(
			f, store: store,
			throws: .wrongPskNonceLength(expected: Self.provider.hashSize, actual: 3))
	}

	@Test("two GroupContextExtensions proposals are rejected")
	func multipleGroupContextExtensions() throws {
		let f = try Self.fixture(minRefs: 2, requirePath: true)
		let gce = MLS.RFC9420.StoredProposal(
			proposal: .groupContextExtensions([]), sender: f.commit.content.sender)
		var store = f.store
		let refs = try Self.refs(of: f)
		store[refs[0]] = gce
		store[refs[1]] = gce
		Self.expectProcessing(f, store: store, throws: .multipleGroupContextExtensions)
	}

	// MARK: the authenticity payload — signatures on installed leaves

	@Test("an Add whose KeyPackage signature is tampered is rejected")
	func addSignatureChecked() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		// A genuinely valid KeyPackage from another vector record, so
		// everything *except* the tampered byte would pass.
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(var kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}
		kp.signature[0] ^= 1
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .add(kp), sender: f.commit.content.sender)
		#expect(throws: MLS.CryptoError.self) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: store, psk: { _ in nil })
		}
	}

	/// The harvest defense the `Placement` doc comment demands: a
	/// `key_package`-sourced leaf signs *unbound* bytes, so its signature
	/// verifies at any index in any group — the §7.3 source check is the
	/// only thing standing between a harvested KeyPackage signature and an
	/// Update at an arbitrary leaf.
	@Test("an Update carrying a key_package-sourced leaf is rejected, not verified unbound")
	func updateSourceChecked() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		let sender = try #require(
			f.group.tree.nonBlankLeaves().map(\.0).first { $0 != committer })
		let ownLeaf = try #require(f.group.tree.leaf(at: f.group.myLeafIndex))
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .update(try MLS.RFC9420.LeafNode(mlsEncoded: ownLeaf.encoded)),
			sender: .member(sender))
		Self.expectProcessing(f, store: store, throws: .wrongLeafNodeSource)
	}

	@Test("an Update that reuses the replaced leaf's encryption key is rejected")
	func updateMustChangeEncryptionKey() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		let sender = try #require(
			f.group.tree.nonBlankLeaves().map(\.0).first { $0 != committer })
		let replaced = try MLS.RFC9420.LeafNode(
			mlsEncoded: try #require(f.group.tree.leaf(at: sender)).encoded)

		// A real update-sourced leaf, signed with a fresh key — signature
		// verification uses the *new* leaf's own signature_key, so a test
		// can construct one — deliberately reusing the old encryption key.
		let (signingKey, signatureKey) = try GroupMutationTests.signingKeyPair(f.provider)
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: replaced.encryptionKey, signatureKey: signatureKey,
			credential: .basic(identity: Data("upd".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .update, extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			f.provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(
				placement: .inGroup(
					groupID: f.group.context.groupID, leafIndex: sender)))

		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .update(leaf), sender: .member(sender))
		Self.expectProcessing(f, store: store, throws: .updateDidNotChangeEncryptionKey)
	}

	// MARK: §12.3 provisional wiring — GCE requirements bind same-commit Adds

	/// The §12.3 sentence with teeth: "The new extensions MUST be used when
	/// evaluating other proposals in this list." A GroupContextExtensions
	/// proposal adding a required_capabilities that names a credential type
	/// must reject an Add (in the same commit) whose KeyPackage doesn't
	/// support it. All 28 vector GCEs are empty, so only a synthetic test
	/// can pin this.
	@Test("a same-commit GCE's required_capabilities binds the Add that follows")
	func provisionalRequirementsBindAdds() throws {
		let f = try Self.fixture(minRefs: 2, requirePath: true)
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(let kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}

		var writer = MLS.Writer()
		try writer.encode(
			MLS.RFC9420.RequiredCapabilities(
				credentialTypes: [.init(.x509)]))
		let requirement = MLS.RFC9420.Extension(
			type: .init(.requiredCapabilities), data: Data(writer.bytes))

		// Substitute EVERY slot, not just two -- the fixture's own
		// remaining references may include a GCE of their own, which
		// would trip `multipleGroupContextExtensions` first. Extra slots
		// become distinct, well-formed PSK proposals, which the
		// validation pass waves through (availability comes later and is
		// never reached).
		var store = f.store
		let refs = try Self.refs(of: f)
		store[refs[0]] = .init(
			proposal: .groupContextExtensions([requirement]),
			sender: f.commit.content.sender)
		store[refs[1]] = .init(proposal: .add(kp), sender: f.commit.content.sender)
		for (i, ref) in refs.dropFirst(2).enumerated() {
			store[ref] = .init(
				proposal: .preSharedKey(
					.external(
						pskID: Data("filler-\(i)".utf8),
						nonce: Data(
							repeating: UInt8(i),
							count: Self.provider.hashSize))),
				sender: f.commit.content.sender)
		}
		Self.expectProcessing(f, store: store, throws: .requiredCapabilitiesNotMet)
	}

	// MARK: direct §7.3 policy units

	static func policyLeaf(
		extensions: [MLS.RFC9420.Extension] = [],
		capabilityExtensions: [MLS.RFC9420.ExtensionType] = []
	) -> MLS.RFC9420.LeafNode {
		.init(
			encryptionKey: MLS.HpkePublicKey(Data([1])),
			signatureKey: MLS.SignaturePublicKey(Data([2])),
			credential: .basic(identity: Data([3])),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: capabilityExtensions, proposals: [],
				credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 10, notAfter: 20)),
			extensions: extensions, signature: Data())
	}

	@Test("a non-default leaf extension missing from capabilities is rejected")
	func unsupportedExtension() throws {
		let leaf = Self.policyLeaf(extensions: [
			.init(type: .init(rawValue: 99), data: Data())
		])
		#expect(
			throws: MLS.RFC9420.GroupError.unsupportedExtensionInLeaf(
				.init(rawValue: 99))
		) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [])
		}
	}

	/// The §7.2/§7.3 tension, resolved toward §7.2: a default-type
	/// extension (application_id) is *forbidden* from appearing in
	/// capabilities, so §7.3's subset rule must exempt it or no leaf
	/// carrying one could ever validate. All vector leaf extensions are
	/// empty, so only this test notices the difference.
	@Test("a default-type leaf extension passes without a capabilities listing")
	func defaultExtensionExempt() throws {
		let leaf = Self.policyLeaf(
			extensions: [.init(type: .init(.applicationID), data: Data())])
		try leaf.validatePolicy(
			.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
			memberCapabilities: [])
	}

	@Test(
		"required_capabilities: non-default unmet rejects; default-type requirement is exempt"
	)
	func requiredCapabilitiesExemption() throws {
		let leaf = Self.policyLeaf()
		// Default extension/proposal types: exempt, passes.
		try leaf.validatePolicy(
			.keyPackage,
			groupRequirements: .init(
				extensionTypes: [.init(.ratchetTree)], proposalTypes: [.init(.add)]),
			memberCredentialTypes: [], memberCapabilities: [])
		// Non-default extension type: not exempt.
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			try leaf.validatePolicy(
				.keyPackage,
				groupRequirements: .init(extensionTypes: [.init(rawValue: 99)]),
				memberCredentialTypes: [], memberCapabilities: [])
		}
		// Credential types are never exempt -- §11.1 says so explicitly.
		#expect(throws: MLS.RFC9420.GroupError.requiredCapabilitiesNotMet) {
			try leaf.validatePolicy(
				.keyPackage,
				groupRequirements: .init(credentialTypes: [.init(.x509)]),
				memberCredentialTypes: [], memberCapabilities: [])
		}
	}

	@Test("a leaf whose capabilities omit its own credential type is rejected")
	func ownCredentialCapability() throws {
		var leaf = Self.policyLeaf()
		leaf.capabilities.credentials = []
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeNotInOwnCapabilities) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [])
		}
	}

	@Test("mutual credential support fails in both directions")
	func mutualCredentialSupport() throws {
		let leaf = Self.policyLeaf()
		// A member that doesn't support basic.
		#expect(throws: MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [
					.init(
						versions: [], cipherSuites: [], extensions: [],
						proposals: [], credentials: [.init(.x509)])
				])
		}
		// A credential type in use that this leaf doesn't support.
		#expect(throws: MLS.RFC9420.GroupError.memberCredentialUnsupportedByLeaf) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil,
				memberCredentialTypes: [.init(.x509)], memberCapabilities: [])
		}
	}

	@Test("lifetime bounds fire only when the caller opts in")
	func lifetimeOptIn() throws {
		let leaf = Self.policyLeaf()  // lifetime (10, 20)
		try leaf.validatePolicy(
			.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
			memberCapabilities: [])
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [], currentTime: 30)
		}
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeTooLong) {
			try leaf.validatePolicy(
				.keyPackage, groupRequirements: nil, memberCredentialTypes: [],
				memberCapabilities: [], maxTotalLifetime: 5)
		}
	}

	/// §12.2's closing rule: two Adds, each individually valid, sharing a
	/// signature key. Only the post-application tree can see it -- the
	/// per-proposal pass validates each leaf alone, and join-side
	/// uniqueness runs once, at join.
	@Test("two Adds sharing a signature key are rejected after application")
	func postCommitUniqueness() throws {
		let f = try Self.fixture(minRefs: 2, requirePath: true)
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(let kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}
		let add = MLS.RFC9420.StoredProposal(
			proposal: .add(kp), sender: f.commit.content.sender)
		var store = f.store
		let refs = try Self.refs(of: f)
		store[refs[0]] = add
		store[refs[1]] = add
		#expect {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: store, psk: { _ in nil })
		} throws: { error in
			guard case MLS.RFC9420.GroupError.duplicateSignatureKey = error else {
				return false
			}
			return true
		}
	}

	/// The Update half of the authenticity payload: a leaf whose signature
	/// does not verify must not be installed, however well-formed.
	@Test("an Update whose leaf signature is garbage is rejected")
	func updateSignatureChecked() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		guard case .member(let committer) = f.commit.content.sender else {
			throw CommitRejectionTests.Failure.shape
		}
		let sender = try #require(
			f.group.tree.nonBlankLeaves().map(\.0).first { $0 != committer })
		let (_, signatureKey) = try GroupMutationTests.signingKeyPair(f.provider)
		let leaf = MLS.RFC9420.LeafNode(
			encryptionKey: MLS.HpkePublicKey(Data([9, 9])), signatureKey: signatureKey,
			credential: .basic(identity: Data("upd".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .update, extensions: [], signature: Data("garbage".utf8))
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .update(leaf), sender: .member(sender))
		#expect(throws: MLS.CryptoError.self) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: store, psk: { _ in nil })
		}
	}

	@Test("a KeyPackage whose init_key equals the leaf encryption key is rejected")
	func initKeyReuse() throws {
		let f = try Self.fixture(minRefs: 1, requirePath: true)
		let records = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let record = try #require(records.first { $0.cipherSuite == 1 })
		var reader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(var kp) = try MLS.RFC9420.Message(from: &reader) else {
			throw CommitRejectionTests.Failure.shape
		}
		kp.initKey = kp.leafNode.encryptionKey
		var store = f.store
		store[try Self.refs(of: f)[0]] = .init(
			proposal: .add(kp), sender: f.commit.content.sender)
		Self.expectProcessing(f, store: store, throws: .keyPackageInitKeyReused)
	}
}
