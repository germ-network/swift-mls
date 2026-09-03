import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSTreeMath
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §9.2 / §7.5 retention behavior added by phase-5-retention.
/// What is *not* tested here is deliberate: the dropped `EpochSecrets`
/// fields need no runtime test — they are absent from the type, so
/// retaining them does not compile.
@Suite("Retention (§9.2 deletion schedule, §7.5 held-key pruning)")
struct RetentionTests {
	/// The vectors only ever reference the immediately preceding epoch
	/// (measured: max gap 1 across both passive-client suites), so the
	/// default depth of 3 must keep both entries the fixture can produce.
	@Test("default depth retains the join epoch across the next commit")
	func defaultDepthRetains() throws {
		let f = try CommitRejectionTests.fixture()
		let joinEpoch = f.group.context.epoch
		let updated = try f.group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
		#expect(updated.resumptionPsks.keys.sorted() == [joinEpoch, joinEpoch + 1])
	}

	/// Depth 0 keeps only the current epoch's resumption PSK. Pruning runs
	/// against the *new* epoch, after that epoch's own insert — with the
	/// eviction reverted this holds two entries and fails.
	@Test("depth 0 evicts everything but the new epoch")
	func depthZeroEvicts() throws {
		let f = try CommitRejectionTests.fixture()
		var group = f.group
		group.retention = .init(resumptionPskDepth: 0)
		// Setting the policy prunes immediately -- but the only entry is
		// the current epoch's, which depth 0 retains.
		#expect(group.resumptionPsks.count == 1)
		let updated = try group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
		#expect(updated.resumptionPsks.keys.sorted() == [updated.context.epoch])
	}

	/// Lowering the policy on a group that never processes another commit
	/// must still shed history — eviction cannot wait for a commit that
	/// may never come.
	@Test("lowering the policy prunes immediately, not at the next commit")
	func policyChangePrunesImmediately() throws {
		let f = try CommitRejectionTests.fixture()
		var group = try f.group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
		#expect(group.resumptionPsks.count == 2)
		group.retention = .init(resumptionPskDepth: 0)
		#expect(group.resumptionPsks.keys.sorted() == [group.context.epoch])
	}

	/// §7.5: "After processing the update, each recipient MUST delete
	/// outdated key material." A held key on a node an Update proposal
	/// blanks must be gone afterward. The node is chosen so nothing else
	/// can mask the check: off the committer's path (decap will not
	/// reinstall it) and outside every copath resolution decap scans
	/// before finding its real decryption key (an injected key there
	/// would shadow it — `decapCommitPath` takes the *first* held key it
	/// meets). No vector fixture holds such a key legitimately, so one is
	/// injected; the search below replicates decap's scan to prove the
	/// injection is inert.
	@Test("a held key on an update-blanked node off the committer's path is dropped")
	func prunesHeldKeyOnBlankedNode() throws {
		let records = try VectorFile.load(
			"passive-client-handling-commit", as: [PassiveClientVector].self)
		let top = SwiftCryptoProvider()
		var found: (fixture: CommitRejectionTests.Fixture, node: UInt32)?
		search: for record in records {
			guard
				let provider = top.cipherSuiteProvider(
					for: .init(id: record.cipherSuite))
			else { continue }
			for ei in record.epochs.indices {
				guard
					let g = try? CommitRejectionTests.buildFixture(
						record: record, epochIndex: ei, provider: provider)
				else { continue }
				guard case .commit(let commit) = g.commit.content.content,
					case .member(let committer) = g.commit.content.sender
				else { continue }
				let updaters = commit.proposals.compactMap {
					entry -> MLS.LeafIndex? in
					guard case .reference(let ref) = entry,
						let s = g.store[ref],
						case .update = s.proposal,
						case .member(let u) = s.sender
					else { return nil }
					return u
				}
				guard !updaters.isEmpty else { continue }
				let tree = g.group.tree
				let lc = tree.leafCount
				func path(_ l: MLS.LeafIndex) -> Set<UInt32> {
					Set(
						MLS.TreeMath.directPath(
							from: 2 * l.value, leafCount: lc
						).map(\.path))
				}
				// Which resolutions decap will visit before it breaks on
				// its real decryption key, given the current held keys.
				let steps = zip(
					MLS.TreeMath.directPath(
						from: 2 * committer.value, leafCount: lc),
					try tree.filteredDirectPath(from: committer)
				).filter { !$0.1 }.map(\.0)
				var scanned: Set<UInt32> = []
				for step in steps {
					let res = tree.resolution(of: step.sibling)
					scanned.formUnion(res)
					if res.contains(where: { g.group.secretKeys[$0] != nil }) {
						break
					}
				}
				for u in updaters {
					if let node = path(u).subtracting(path(committer))
						.subtracting(scanned)
						.filter({ g.group.secretKeys[$0] == nil })
						.sorted().first
					{
						found = (g, node)
						break search
					}
				}
			}
		}
		let (f, node) = try #require(
			found, "no vector fixture offers an inert injection node")

		var group = f.group
		group.secretKeys[node] = MLS.HpkeSecretKey(Data("stale sentinel".utf8))
		let updated = try group.processing(
			f.provider, commit: f.commit, proposals: f.store, psk: { _ in nil })
		#expect(updated.secretKeys[node] == nil)
	}
}
