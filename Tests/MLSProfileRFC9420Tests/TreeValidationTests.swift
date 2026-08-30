import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `tree-validation.json`'s `resolutions` and `tree_hashes` fields, and
/// the structural mutation tests this phase's own S1/S2/S14 checks call
/// for. Parent-hash coverage from the same vector file lands separately
/// once that algorithm exists.
@Suite("tree-validation.json (mlswg/mls-implementations, official) — resolutions")
struct TreeValidationTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"tree-validation", as: [TreeValidationVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	private static func decodeTree(_ record: TreeValidationVector) throws
		-> MLS.TreeKEM.RatchetTree
	{
		var reader = MLS.Reader(record.tree.bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return try MLS.TreeKEM.RatchetTree(nodes)
	}

	@Test("every node index's resolution matches the vector's own", arguments: records)
	func resolutionsMatchVector(_ record: TreeValidationVector) throws {
		let tree = try Self.decodeTree(record)
		for (index, expected) in record.resolutions.enumerated() {
			#expect(tree.resolution(of: UInt32(index)) == expected)
		}
	}

	@Test("every node index's tree hash matches the vector's own", arguments: records)
	func treeHashesMatchVector(_ record: TreeValidationVector) throws {
		let tree = try Self.decodeTree(record)
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		for (index, expected) in record.treeHashes.enumerated() {
			#expect(try tree.treeHash(at: UInt32(index), provider) == expected.bytes)
		}
	}

	@Test(
		"every vector tree has correctly-parity-matched node kinds and no trailing blank",
		arguments: records)
	func vectorTreesAreStructurallyWellFormed(_ record: TreeValidationVector) throws {
		let tree = try Self.decodeTree(record)
		#expect(throws: Never.self) { try tree.validateNodeKinds() }
		#expect(throws: Never.self) { try tree.validateNoTrailingBlank() }
	}

	@Test("every vector tree's parent-hash chain validates cleanly", arguments: records)
	func vectorTreesHaveValidParentHashChains(_ record: TreeValidationVector) throws {
		let tree = try Self.decodeTree(record)
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		#expect(throws: Never.self) { try tree.validateParentHashChain(provider) }
	}

	@Test(
		"S2: a ParentNode at a leaf-parity index is rejected, not silently read as blank",
		arguments: records)
	func rejectsWrongNodeKind(_ record: TreeValidationVector) throws {
		var tree = try Self.decodeTree(record)
		// Put a parent at node index 0 (always a leaf slot).
		tree.setParent(
			0,
			to: .init(
				encryptionKey: .init(Data()), parentHash: Data(), unmergedLeaves: []
			))
		#expect(throws: MLS.TreeKEM.TreeError.wrongNodeKind(index: 0)) {
			try tree.validateNodeKinds()
		}
	}

	/// The record from "a tree with unmerged leaves" (`test-vectors.md`'s
	/// own description): 8 leaves, node 11 non-blank with a real unmerged
	/// leaf and a non-empty `parent_hash`, reached by three separate
	/// leaves' chains (9, 12, and 14) during validation -- a node
	/// guaranteed to actually matter, not a first-match guess.
	private static func unmergedLeavesRecord() throws -> TreeValidationVector {
		try #require(
			Self.records.first {
				$0.cipherSuite == 1
					&& $0.resolutions == [
						[0], [1], [2], [3], [4], [5], [6], [7], [8], [9],
						[10], [11, 14], [12],
						[12, 14], [14],
					]
			})
	}

	/// S4: corrupting node 11's `parent_hash` (flipping a byte, not
	/// blanking it -- an *empty* parent_hash legitimately means "no claim
	/// to check" and wouldn't exercise this at all) must break every
	/// chain that used to validate against it.
	@Test("S4: corrupting a covered parent's parent_hash breaks validation")
	func mutationCorruptingParentHashBreaksChain() throws {
		var tree = try Self.decodeTree(try Self.unmergedLeavesRecord())
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))
		try tree.validateParentHashChain(provider)  // sanity: valid before mutation

		var p = try #require(tree.parent(at: 11))
		try #require(!p.parentHash.isEmpty)
		p.parentHash[p.parentHash.startIndex] ^= 0xFF
		tree.setParent(11, to: p)

		#expect(throws: (any Error).self) { try tree.validateParentHashChain(provider) }
	}

	/// S6: an extra unmerged-leaf entry at node 11 changes what its
	/// filtered ("original") tree hash covers when a descendant's chain
	/// checks against it, so the previously-valid chain now mismatches --
	/// this is exactly the resolution-membership rule GER-2295 exists for.
	@Test("S6: an extra unmerged leaf breaks validation")
	func mutationExtraUnmergedLeafBreaksChain() throws {
		var tree = try Self.decodeTree(try Self.unmergedLeavesRecord())
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))
		try tree.validateParentHashChain(provider)  // sanity: valid before mutation

		var p = try #require(tree.parent(at: 11))
		// Must be a leaf within node 11's own subtree (leaves 4-7) for the
		// mutation to actually change any hash computation -- a leaf
		// outside it (e.g. leaf 0) would just get filtered away as "not a
		// descendant" by the very check this is meant to break.
		let bogus = MLS.LeafIndex(value: 4)
		try #require(!p.unmergedLeaves.contains(bogus))
		p.unmergedLeaves.append(bogus)
		tree.setParent(11, to: p)

		#expect(throws: (any Error).self) { try tree.validateParentHashChain(provider) }
	}

	/// The node at the top of a parent-hash chain legitimately carries an
	/// empty `parent_hash` — there is nothing above it to chain from. That
	/// says nothing about whether anything chains *up to* it, which is
	/// what RFC 9420 §7.9.2's "all non-blank parent nodes are covered by
	/// exactly one such chain" actually requires. Swapping such a node's
	/// encryption key leaves its own (empty) hash field untouched while
	/// breaking every descendant chain's claim against it, so the only
	/// thing that can catch it is the coverage sweep.
	@Test("a chain-topmost node's encryption key can't be swapped undetected")
	func mutationSwappingTopmostNodeKeyBreaksCoverage() throws {
		var tree = try Self.decodeTree(try Self.unmergedLeavesRecord())
		let provider = try #require(Self.provider.cipherSuiteProvider(for: .init(id: 1)))
		try tree.validateParentHashChain(provider)  // sanity: valid before mutation

		let topmost = try #require(
			stride(from: UInt32(1), to: tree.physicalNodeCount, by: 2).first {
				tree.parent(at: $0)?.parentHash.isEmpty == true
			})
		var p = try #require(tree.parent(at: topmost))
		// Any *other* node's key works as the substitute -- a well-formed
		// HPKE key that simply isn't the one the chain below committed to.
		let donor = try #require(
			stride(from: UInt32(1), to: tree.physicalNodeCount, by: 2).lazy
				.compactMap { tree.parent(at: $0)?.encryptionKey }
				.first { $0 != p.encryptionKey })
		p.encryptionKey = donor
		tree.setParent(topmost, to: p)

		#expect(throws: MLS.TreeKEM.TreeError.parentHashMismatch) {
			try tree.validateParentHashChain(provider)
		}
	}

	@Test("S14: a trailing blank leaf is rejected, not silently trimmed", arguments: records)
	func rejectsTrailingBlank(_ record: TreeValidationVector) throws {
		var reader = MLS.Reader(record.tree.bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		// Every vector tree already has no trailing blank (confirmed by
		// `vectorTreesAreStructurallyWellFormed` above) — appending one
		// explicit blank slot is a deliberate, direct mutation, not
		// something insertLeaf or any other real operation would produce.
		let tree = try MLS.TreeKEM.RatchetTree(nodes + [nil])
		#expect(throws: MLS.TreeKEM.TreeError.trailingBlankLeaves) {
			try tree.validateNoTrailingBlank()
		}
	}
}
