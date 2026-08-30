import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// The rejection branches `Group.processing` grew in 5b. The vector gate
/// proves the **accept** path only — an adversarial review deleted both
/// `checkUpdatePathKeysAreFresh` and the path-required check and all 265
/// vector epochs still passed. Everything here exists because of that.
///
/// **What is coverable without a signing oracle, and what isn't.**
/// `processing` verifies the commit's framing signature at step 5, so any
/// test that *mutates a commit* can only reach checks that run before that
/// point. The rejections below are exactly those, plus one
/// (`unknownProposalReference`) reachable by withholding state rather than
/// altering bytes.
///
/// The rest — `pathRequired`, `removeOfNonMember`,
/// `updatePathLeafNotCommitSource`, `updatePathReusesEncryptionKey`,
/// `removedFromGroup`, `unsupportedReInit`, and the UpdatePath key-freshness
/// check — all sit *after* signature verification and need a commit that is
/// both malformed **and** validly signed by the committer. The vectors
/// supply the joiner's secrets, never a committer's signing key, so no test
/// here can construct one. They rest on reading, and this comment is the
/// honest record of that rather than a silent gap.
@Suite("Commit rejection paths")
struct CommitRejectionTests {
	static let provider = SwiftCryptoProvider()

	struct Fixture {
		var provider: any MLS.CipherSuiteProvider
		var group: MLS.RFC9420.Group
		var commit: MLS.RFC9420.PublicMessage
		var store: MLS.RFC9420.ProposalStore
	}

	/// Every loose proposal in one epoch, keyed by its own `ProposalRef`.
	static func storeFor(
		_ epoch: PassiveClientVector.Epoch, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.ProposalStore {
		var store: MLS.RFC9420.ProposalStore = [:]
		for proposalBytes in epoch.proposals {
			var reader = MLS.Reader(proposalBytes.bytes)
			guard
				case .publicMessage(let message) = try MLS.RFC9420.Message(
					from: &reader)
			else { throw Failure.shape }
			try reader.finish()
			guard case .proposal(let proposal) = message.content.content else {
				throw Failure.shape
			}
			let content = MLS.RFC9420.AuthenticatedContent(
				wireFormat: .publicMessage, content: message.content,
				auth: message.auth)
			store[try MLS.RFC9420.proposalRef(provider, content)] = .init(
				proposal: proposal, sender: message.content.sender)
		}
		return store
	}

	/// A real joined group plus the real first commit that follows it, from
	/// `passive-client-handling-commit.json`. Every test below starts here
	/// and perturbs exactly one thing.
	static func fixture(requiringByReference: Bool = false) throws -> Fixture {
		let records = try VectorFile.load(
			"passive-client-handling-commit", as: [PassiveClientVector].self)
		// Not every commit uses by-reference proposals, and the ones that do
		// are not necessarily in a record's *first* epoch -- so the one test
		// that needs a reference searches (record, epoch) pairs rather than
		// assuming either.
		func usesReference(_ commitBytes: Data) -> Bool {
			var reader = MLS.Reader(commitBytes)
			guard
				case .publicMessage(let message)? = try? MLS.RFC9420.Message(
					from: &reader)
			else { return false }
			return message.content.content.commitProposalsContainReference
		}
		var chosen: (record: PassiveClientVector, epochIndex: Int)?
		for candidate in records where candidate.cipherSuite == 1 {
			guard !candidate.epochs.isEmpty else { continue }
			if !requiringByReference {
				chosen = (candidate, 0)
				break
			}
			if let i = candidate.epochs.indices.first(where: {
				usesReference(candidate.epochs[$0].commit.bytes)
			}) {
				chosen = (candidate, i)
				break
			}
		}
		let (record, epochIndex) = try #require(chosen)
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))

		var kpReader = MLS.Reader(record.keyPackage.bytes)
		guard case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(from: &kpReader)
		else {
			throw Failure.shape
		}
		try kpReader.finish()

		var welcomeReader = MLS.Reader(record.welcome.bytes)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(from: &welcomeReader)
		else {
			throw Failure.shape
		}
		try welcomeReader.finish()

		let externalPsks = Dictionary(
			uniqueKeysWithValues: record.externalPsks.map {
				($0.pskID.bytes, $0.psk.bytes)
			})
		let resolve: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			guard case .external(let pskID, _) = id else { return nil }
			return externalPsks[pskID]
		}

		var externalTree: [MLS.RFC9420.Node?]?
		if let ratchetTree = record.ratchetTree {
			var treeReader = MLS.Reader(ratchetTree.bytes)
			externalTree = try treeReader.decodeVector()
			try treeReader.finish()
		}

		let joined = try MLS.RFC9420.Group.join(
			provider, welcome: welcome,
			credentials: .init(
				keyPackage: keyPackage,
				initKey: MLS.HpkeSecretKey(record.initPriv.bytes),
				encryptionKey: MLS.HpkeSecretKey(record.encryptionPriv.bytes)),
			externalTree: externalTree, psk: resolve)

		// Advance the group to the chosen epoch by processing every commit
		// before it, so the fixture's `group` and `commit` are genuinely
		// consecutive rather than merely both real.
		var group = joined
		for earlier in record.epochs[..<epochIndex] {
			var reader = MLS.Reader(earlier.commit.bytes)
			guard
				case .publicMessage(let message) = try MLS.RFC9420.Message(
					from: &reader)
			else { throw Failure.shape }
			try reader.finish()
			try group.process(
				provider, commit: message,
				proposals: try storeFor(earlier, provider), psk: resolve)
		}

		let epoch = record.epochs[epochIndex]
		let store = try storeFor(epoch, provider)

		var commitReader = MLS.Reader(epoch.commit.bytes)
		guard case .publicMessage(let commit) = try MLS.RFC9420.Message(from: &commitReader)
		else { throw Failure.shape }
		try commitReader.finish()

		return Fixture(provider: provider, group: group, commit: commit, store: store)
	}

	enum Failure: Error { case shape }

	@Test("the fixture itself processes cleanly (baseline for every case below)")
	func baseline() throws {
		let f = try Self.fixture()
		_ = try f.group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
	}

	@Test("a commit for a different epoch is rejected before any tree work")
	func wrongEpoch() throws {
		let f = try Self.fixture()
		var commit = f.commit
		commit.content.epoch += 1
		#expect(
			throws: MLS.RFC9420.GroupError.wrongEpoch(
				expected: f.group.context.epoch, actual: f.group.context.epoch + 1)
		) {
			_ = try f.group.processing(
				f.provider, commit: commit, proposals: f.store, psk: { _ in nil })
		}
	}

	@Test("a commit naming a different group is rejected")
	func wrongGroup() throws {
		let f = try Self.fixture()
		var commit = f.commit
		commit.content.groupID = Data("not this group".utf8)
		#expect(throws: MLS.RFC9420.GroupError.wrongGroup) {
			_ = try f.group.processing(
				f.provider, commit: commit, proposals: f.store, psk: { _ in nil })
		}
	}

	@Test("a PublicMessage that isn't a commit is rejected")
	func notACommit() throws {
		let f = try Self.fixture()
		var notCommit = f.commit
		notCommit.content.content = .application(Data("hello".utf8))
		#expect(throws: MLS.RFC9420.GroupError.notACommit) {
			_ = try f.group.processing(
				f.provider, commit: notCommit, proposals: f.store, psk: { _ in nil }
			)
		}
	}

	/// External commits and external senders are deferred project-wide, so
	/// this must be an explicit rejection rather than a path that limps on.
	@Test(
		"a non-member sender is rejected, not silently mishandled",
		arguments: [
			MLS.Sender.external(0), .newMemberCommit, .newMemberProposal,
		])
	func unsupportedSender(_ sender: MLS.Sender) throws {
		let f = try Self.fixture()
		var commit = f.commit
		commit.content.sender = sender
		#expect(throws: MLS.RFC9420.GroupError.unsupportedSender) {
			_ = try f.group.processing(
				f.provider, commit: commit, proposals: f.store, psk: { _ in nil })
		}
	}

	@Test("a commit whose sender leaf is blank is rejected")
	func blankSenderLeaf() throws {
		let f = try Self.fixture()
		guard case .member(let senderIndex) = f.commit.content.sender else {
			Issue.record("expected a member sender")
			return
		}
		var group = f.group
		group.tree.setLeaf(senderIndex, to: nil)
		#expect(throws: MLS.RFC9420.GroupError.blankSenderLeaf) {
			_ = try group.processing(
				f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
		}
	}

	/// S22. Reached by *withholding* state rather than altering bytes, so
	/// no signature is disturbed — the one post-framing rejection a test can
	/// construct without a committer's signing key.
	///
	/// An unresolvable reference must be an error, never a skip: applying a
	/// commit with a shorter proposal list than its sender used would
	/// diverge state silently, which is far worse than a hard failure.
	@Test("a by-reference proposal missing from the store is an error, not a skip")
	func unknownProposalReference() throws {
		let f = try Self.fixture(requiringByReference: true)
		try #require(f.commit.content.content.commitProposalsContainReference)

		#expect(throws: MLS.RFC9420.GroupError.unknownProposalReference) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: [:], psk: { _ in nil })
		}
	}
}

extension MLS.RFC9420.Content {
	fileprivate var commitProposalsContainReference: Bool {
		guard case .commit(let commit) = self else { return false }
		return commit.proposals.contains { if case .reference = $0 { true } else { false } }
	}
}
