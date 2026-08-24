import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `tree-operations.json`: the cheapest real (non-structural) signal in
/// phase 4 — applies one already-decoded `Proposal` to `tree_before` and
/// checks the result is byte-identical to `tree_after`, with both tree
/// hashes matching too. Trimming trailing blanks after every edit is
/// load-bearing for the byte-identity check, not incidental.
@Suite("tree-operations.json (mlswg/mls-implementations, official)")
struct TreeOperationsTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"tree-operations", as: [TreeOperationsVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	private static func decodeTree(_ bytes: Data) throws -> MLS.TreeKEM.RatchetTree {
		var reader = MLS.Reader(bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return try MLS.TreeKEM.RatchetTree(nodes)
	}

	@Test(
		"applying the vector's proposal to tree_before reproduces tree_after byte-for-byte, both tree hashes matching",
		arguments: records)
	func applyingProposalMatchesVector(_ record: TreeOperationsVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		var tree = try Self.decodeTree(record.treeBefore.bytes)
		#expect(try tree.treeHash(provider) == record.treeHashBefore.bytes)

		let proposal = try MLS.RFC9420.Proposal(mlsEncoded: record.proposal.bytes)
		try tree.apply(proposal, sender: .init(value: record.proposalSender))

		var writer = MLS.Writer()
		try writer.encodeVector(try tree.nodes)
		#expect(Data(writer.bytes) == record.treeAfter.bytes)
		#expect(try tree.treeHash(provider) == record.treeHashAfter.bytes)
	}
}
