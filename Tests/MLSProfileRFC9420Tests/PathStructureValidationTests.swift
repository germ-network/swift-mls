import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// GER-2295's own headline requirement: the explicit path-structure
/// validation `Commit.path`'s wire types (`UpdatePath`/`UpdatePathNode`)
/// were split out to require, since `MLSFraming`'s opaque wrapper has no
/// tree to check against. "Gets its own test" — this file is that test,
/// against a real tree and a real `UpdatePath` from `treekem.json` rather
/// than a hand-built one, so the counts being checked are genuine.
@Suite("Path-structure validation (S9/S10)")
struct PathStructureValidationTests {
	static let provider = SwiftCryptoProvider()

	private static func loadRecord() throws -> (
		tree: MLS.TreeKEM.RatchetTree, sender: MLS.LeafIndex,
		wirePath: MLS.RFC9420.UpdatePath
	) {
		let records = try VectorFile.load("treekem", as: [TreeKemVector].self)

		var best:
			(
				tree: MLS.TreeKEM.RatchetTree, sender: MLS.LeafIndex,
				wirePath: MLS.RFC9420.UpdatePath
			)?
		for record in records where record.cipherSuite == 1 {
			var treeReader = MLS.Reader(record.ratchetTree.bytes)
			let nodes: [MLS.RFC9420.Node?] = try treeReader.decodeVector()
			try treeReader.finish()
			let tree = try MLS.TreeKEM.RatchetTree(nodes)

			for update in record.updatePaths {
				var pathReader = MLS.Reader(update.updatePath.bytes)
				let wirePath = try MLS.RFC9420.UpdatePath(from: &pathReader)
				try pathReader.finish()
				// Need at least 2 path nodes so dropping one still leaves a
				// non-empty (and thus meaningfully comparable) path.
				if wirePath.nodes.count > 1 {
					best = (tree, MLS.LeafIndex(value: update.sender), wirePath)
					break
				}
			}
			if best != nil { break }
		}
		return try #require(best)
	}

	@Test("a genuine treekem.json UpdatePath validates cleanly")
	func genuinePathValidates() throws {
		let (tree, sender, wirePath) = try Self.loadRecord()
		#expect(throws: Never.self) {
			try tree.validatePathStructure(
				sender: sender,
				nodeCiphertextCounts: wirePath.nodes.map(
					\.encryptedPathSecret.count),
				excluding: [])
		}
	}

	/// S9: dropping the last `UpdatePathNode` must be rejected — the
	/// exact case mls-rs itself doesn't check eagerly (a short path is a
	/// bare out-of-bounds index at the point it's used), so this is
	/// stricter than the reference implementation on purpose.
	@Test("S9: a short path (one node dropped) is rejected")
	func rejectsShortPath() throws {
		let (tree, sender, wirePath) = try Self.loadRecord()
		let counts = wirePath.nodes.dropLast().map(\.encryptedPathSecret.count)
		#expect(
			throws: MLS.TreeKEM.TreeError.wrongPathNodeCount(
				expected: wirePath.nodes.count, actual: wirePath.nodes.count - 1)
		) {
			try tree.validatePathStructure(
				sender: sender, nodeCiphertextCounts: Array(counts), excluding: [])
		}
	}

	/// S9, the other direction: an extra node appended must also be
	/// rejected, not just a short path.
	@Test("S9: a long path (one extra node) is rejected")
	func rejectsLongPath() throws {
		let (tree, sender, wirePath) = try Self.loadRecord()
		let counts = wirePath.nodes.map(\.encryptedPathSecret.count) + [0]
		#expect(
			throws: MLS.TreeKEM.TreeError.wrongPathNodeCount(
				expected: wirePath.nodes.count, actual: wirePath.nodes.count + 1)
		) {
			try tree.validatePathStructure(
				sender: sender, nodeCiphertextCounts: counts, excluding: [])
		}
	}

	/// S10: one node's ciphertext count not matching its copath
	/// resolution's size must be rejected — the check this file exists
	/// for, per GER-2295's description directly.
	@Test("S10: a wrong ciphertext count at one node is rejected")
	func rejectsWrongCiphertextCount() throws {
		let (tree, sender, wirePath) = try Self.loadRecord()
		try #require(!wirePath.nodes.isEmpty)
		var counts = wirePath.nodes.map(\.encryptedPathSecret.count)
		counts[0] += 1  // one too many ciphertexts at the first path node
		#expect(throws: MLS.TreeKEM.TreeError.self) {
			try tree.validatePathStructure(
				sender: sender, nodeCiphertextCounts: counts, excluding: [])
		}
	}
}
