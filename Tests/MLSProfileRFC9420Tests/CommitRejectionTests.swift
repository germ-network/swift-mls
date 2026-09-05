import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// The rejection branches `Group.processing` grew in 5b. The vector gate
/// proves the **accept** path only — an adversarial review deleted both
/// `checkUpdatePathKeysAreFresh` and the path-required check and all 330
/// commit epochs still passed (65 records x 2 epochs from
/// `passive-client-handling-commit` after the cipher-suite filter -- the
/// file carries 91 records, and a revision of this header briefly
/// "corrected" 330 to 382 by counting the 26 X448 records the tests never
/// run -- plus 200 from `passive-client-random`). Everything here exists
/// because of that.
///
/// **What is coverable without a signing oracle, and what isn't.**
/// `processing` can throw dozens of distinct `GroupError` cases (the
/// exact count lives in `spec/conformance.md`, recounted per phase). It verifies the
/// commit's framing signature at step 5, so a test that *mutates a commit*
/// can only reach checks running before that point — but mutation is not
/// the only route, and treating it as though it were is how this suite's
/// own accounting went wrong twice.
///
/// **Eight are covered here.** Five by mutation (`wrongEpoch`, `wrongGroup`,
/// `notACommit`, `unsupportedSender`, `blankSenderLeaf`) and three by
/// *supplying or withholding caller state*, which disturbs no signature at
/// all because `processing` takes the `ProposalStore` and the PSK resolver
/// on trust: `unknownProposalReference`, `unresolvedPreSharedKey`, and
/// `updateFromNonMember`.
///
/// That second route kept being missed. The phase-5 conformance audit's
/// first pass counted six covered rejections; adding `unresolvedPreSharedKey`
/// made seven; the stage-5 review then found that the store also carries an
/// unchecked *sender*, which was a live process-abort bug, not merely an
/// untested branch. Anything reachable by handing `processing` crafted state
/// should be assumed reachable until checked.
///
/// **The six that needed a validly-signed-but-malformed commit** —
/// `pathRequired`, `removeOfNonMember`, `updatePathLeafNotCommitSource`,
/// `updatePathReusesEncryptionKey`, `removedFromGroup`,
/// `unsupportedReInit` — rested on reading until phase 6b's `create`
/// supplied a committer signing key; they now live in
/// `ConstructedRejectionTests` (and the backbone, for `removedFromGroup`).
/// The two former holes closed with them: `confirmationTagMismatch`
/// (whose naive version dies at the membership MAC — the real test
/// recomputes that tag, which is exactly what a malicious member can do)
/// and `unsupportedResumptionUsage`. Nothing on the commit path is
/// untested-by-necessity any more; `spec/conformance.md` carries the full
/// accounting.
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
		_ epoch: PassiveClientVector.Epoch, in group: MLS.RFC9420.Group,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.ProposalStore {
		var store = MLS.RFC9420.ProposalStore()
		for proposalBytes in epoch.proposals {
			var reader = MLS.Reader(proposalBytes.bytes)
			guard
				case .publicMessage(let message) = try MLS.RFC9420.Message(
					from: &reader)
			else { throw Failure.shape }
			try reader.finish()
			guard case .proposal = message.content.content else {
				throw Failure.shape
			}
			// These are real vector proposals; `verify` authenticates the
			// framing (as a live receiver does) before the store accepts it.
			try store.insert(
				try group.verifying(provider, proposal: message), provider)
		}
		return store
	}

	/// A real joined group plus the real first commit that follows it, from
	/// `passive-client-handling-commit.json`. Every test below starts here
	/// and perturbs exactly one thing.
	/// What a test needs from its fixture epoch beyond "it is real".
	enum Requirement {
		case none
		/// The commit references at least one proposal by `ProposalRef`.
		case byReference
		/// As `byReference`, and the commit also carries an `UpdatePath`.
		/// Needed by any test that substitutes an Update or Remove into the
		/// store: doing so makes the commit path-required, and §12.4's
		/// path-required check runs *before* proposal application, so a
		/// pathless fixture would fail with `pathRequired` and never reach
		/// the rejection under test.
		case byReferenceWithPath
		/// The commit carries a PreSharedKey proposal, by value or by
		/// reference -- the epoch a withheld-PSK test needs.
		case preSharedKey
	}

	static func fixture(_ requirement: Requirement = .none) throws -> Fixture {
		let records = try VectorFile.load(
			"passive-client-handling-commit", as: [PassiveClientVector].self)
		// Not every commit uses by-reference proposals or PSKs, and the ones
		// that do are not necessarily in a record's *first* epoch -- so tests
		// with a requirement search (record, epoch) pairs rather than
		// assuming either.
		func satisfies(_ epoch: PassiveClientVector.Epoch) -> Bool {
			var reader = MLS.Reader(epoch.commit.bytes)
			guard
				case .publicMessage(let message)? = try? MLS.RFC9420.Message(
					from: &reader)
			else { return false }
			switch requirement {
			case .none:
				return true
			case .byReference:
				return message.content.content.commitProposalsContainReference
			case .byReferenceWithPath:
				guard case .commit(let commit) = message.content.content else {
					return false
				}
				return commit.path != nil
					&& message.content.content.commitProposalsContainReference
			case .preSharedKey:
				// By value: read straight off the commit. By reference: the
				// referenced proposal lives in the epoch's loose-proposal
				// list, so check both rather than only the commit body.
				if message.content.content.commitProposalsContainPsk { return true }
				return epoch.proposals.contains { bytes in
					var r = MLS.Reader(bytes.bytes)
					guard
						case .publicMessage(let m)? = try? MLS.RFC9420
							.Message(from: &r),
						case .proposal(let proposal) = m.content.content
					else { return false }
					if case .preSharedKey = proposal { return true }
					return false
				}
			}
		}
		var chosen: (record: PassiveClientVector, epochIndex: Int)?
		for candidate in records where candidate.cipherSuite == 1 {
			guard !candidate.epochs.isEmpty else { continue }
			if let i = candidate.epochs.indices.first(where: {
				satisfies(candidate.epochs[$0])
			}) {
				chosen = (candidate, i)
				break
			}
		}
		let (record, epochIndex) = try #require(chosen)
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))
		return try buildFixture(record: record, epochIndex: epochIndex, provider: provider)
	}

	static func buildFixture(
		record: PassiveClientVector, epochIndex: Int,
		provider: any MLS.CipherSuiteProvider
	) throws -> Fixture {

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
				proposals: try storeFor(earlier, in: group, provider),
				psk: resolve)
		}

		let epoch = record.epochs[epochIndex]
		let store = try storeFor(epoch, in: group, provider)

		var commitReader = MLS.Reader(epoch.commit.bytes)
		guard case .publicMessage(let commit) = try MLS.RFC9420.Message(from: &commitReader)
		else { throw Failure.shape }
		try commitReader.finish()

		return Fixture(provider: provider, group: group, commit: commit, store: store)
	}

	enum Failure: Error { case shape }

	@Test("the fixture itself processes cleanly (baseline for every case below)")
	func baseline() throws {
		let f = try Self.fixture(.none)
		_ = try f.group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
	}

	@Test("a commit for a different epoch is rejected before any tree work")
	func wrongEpoch() throws {
		let f = try Self.fixture(.none)
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
		let f = try Self.fixture(.none)
		var commit = f.commit
		commit.content.groupID = Data("not this group".utf8)
		#expect(throws: MLS.RFC9420.GroupError.wrongGroup) {
			_ = try f.group.processing(
				f.provider, commit: commit, proposals: f.store, psk: { _ in nil })
		}
	}

	@Test("a PublicMessage that isn't a commit is rejected")
	func notACommit() throws {
		let f = try Self.fixture(.none)
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
		let f = try Self.fixture(.none)
		var commit = f.commit
		commit.content.sender = sender
		#expect(throws: MLS.RFC9420.GroupError.unsupportedSender) {
			_ = try f.group.processing(
				f.provider, commit: commit, proposals: f.store, psk: { _ in nil })
		}
	}

	@Test("a commit whose sender leaf is blank is rejected")
	func blankSenderLeaf() throws {
		let f = try Self.fixture(.none)
		guard case .member(let senderIndex) = f.commit.content.sender else {
			Issue.record("expected a member sender")
			return
		}
		var group = f.group
		try group.tree.setLeaf(senderIndex, to: nil)
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
		let f = try Self.fixture(.byReference)
		try #require(f.commit.content.content.commitProposalsContainReference)

		#expect(throws: MLS.RFC9420.GroupError.unknownProposalReference) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: .init(), psk: { _ in nil })
		}
	}

	/// S13, commit half. The second rejection reachable by *withholding*
	/// state rather than altering bytes, and so the second that needs no
	/// committer signing key -- the conformance audit's first accounting of
	/// this suite missed it and counted six reachable rejections where there
	/// are seven.
	///
	/// RFC 9420 §12.4.2 makes PSK availability its own step, five bullets
	/// before the tree is touched: "Verify that all PreSharedKey proposals in
	/// the proposals vector are available." An unavailable PSK must fail the
	/// commit, never derive a key schedule from a shorter PSK list than the
	/// sender used -- that would diverge silently, and the epoch
	/// authenticator would be the first thing to notice, one epoch too late.
	/// The third rejection reachable by supplying state rather than mutating
	/// bytes. The route matters: `processing` looks a by-reference proposal
	/// up in the caller-supplied `ProposalStore` and takes both the proposal
	/// *and its sender* from whatever it finds there, with no signature of
	/// its own to check. Substituting one entry therefore disturbs nothing
	/// the commit's own framing signature covers.
	///
	/// This is not hypothetical. `LeafIndex` is bounded only by its own 2^24
	/// ceiling, never against the tree it indexes, and `setLeaf` grows the
	/// backing array to reach whatever index it is handed. Before the guard,
	/// an Update naming leaf 2^23 padded the array toward 2^25 entries one
	/// `nil` at a time and then aborted the process on
	/// `RatchetTree.leafCount`'s `try!` — verified by direct repro, not
	/// inferred. Indices in roughly 2^20…2^23 instead allocated hundreds of
	/// megabytes and carried on. Hence the `.timeLimit`: the pre-fix failure
	/// mode at the smaller indices is a very slow test, not a fast one.
	/// Migrated off the vector fixture: `ProposalStore.insert` now derives
	/// a proposal's ref from its own framed content, so a fake sender can
	/// no longer be planted at a *real* vector commit's existing ref (that
	/// ref-vs-value mismatch is exactly what the structural store rules
	/// out). What the rule itself still lets through — `insert` records
	/// whatever `Sender` the framing claims without checking it names an
	/// actual member, and neither does the commit's own framing signature
	/// — is reachable the same way `ProposalValidationTests` reaches every
	/// other §12.1/§12.2 rule post-refactor: a synthetic committer
	/// (`ConstructedRejectionTests.pair`) frames a real commit referencing
	/// a proposal whose claimed sender is fabricated.
	@Test(
		"an Update whose sender occupies no leaf is rejected, not applied by growing the tree",
		.timeLimit(.minutes(1)))
	func updateFromNonMember() throws {
		let pair = try ConstructedRejectionTests.pair()
		// The second index is the one that historically trapped (see the
		// class doc comment); the first just needs to be out of range.
		for leafIndex in [pair.groupA.tree.leafCount.value, UInt32(1) << 23] {
			try Self.expectUpdateRejected(pair, from: leafIndex)
		}
	}

	private static func expectUpdateRejected(
		_ pair: ConstructedRejectionTests.Pair, from leafIndex: UInt32
	) throws {
		// A well-formed Update body — the committer's own current leaf —
		// framed under a sender that occupies no leaf. The store gate now
		// rejects it at `verify`: the sender leaf is blank, so a forged
		// non-member proposal can never enter the store. (Before the gate,
		// `insert` took it unchecked and only `validateProposalList`'s
		// `updateFromNonMember` caught it downstream — which is now
		// unreachable via the store and stands as defense in depth.)
		let ownLeaf = try #require(pair.groupA.tree.leaf(at: pair.groupA.myLeafIndex))
		let sender = MLS.LeafIndex(value: leafIndex)
		let forged = MLS.RFC9420.PublicMessage(
			content: .init(
				groupID: pair.groupA.context.groupID,
				epoch: pair.groupA.context.epoch, sender: .member(sender),
				authenticatedData: Data(),
				content: .proposal(
					.update(
						try MLS.RFC9420.LeafNode(
							mlsEncoded: ownLeaf.encoded)))
			),
			auth: .init(signature: MLS.Signature(Data()), confirmationTag: nil),
			membershipTag: nil)

		#expect(throws: MLS.RFC9420.GroupError.blankSenderLeaf) {
			_ = try pair.groupB.verifying(
				ConstructedRejectionTests.provider, proposal: forged)
		}
	}

	@Test("a PreSharedKey the caller cannot resolve fails the commit, not the key schedule")
	func unresolvedPreSharedKey() throws {
		let f = try Self.fixture(.preSharedKey)
		// The fixture joined and replayed earlier commits with the real
		// resolver; only this call withholds, so nothing else is perturbed.
		#expect(throws: MLS.RFC9420.GroupError.unresolvedPreSharedKey) {
			_ = try f.group.processing(
				f.provider, commit: f.commit, proposals: f.store,
				psk: { _ in nil })
		}
	}
}

extension MLS.RFC9420.Content {
	fileprivate var commitProposalsContainReference: Bool {
		guard case .commit(let commit) = self else { return false }
		return commit.proposals.contains { if case .reference = $0 { true } else { false } }
	}

	fileprivate var commitProposalsContainPsk: Bool {
		guard case .commit(let commit) = self else { return false }
		return commit.proposals.contains {
			guard case .proposal(let proposal) = $0 else { return false }
			if case .preSharedKey = proposal { return true }
			return false
		}
	}
}
