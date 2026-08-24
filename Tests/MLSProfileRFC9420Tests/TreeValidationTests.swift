import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `tree-validation.json`'s `resolutions` field, and the structural
/// mutation tests this phase's own S1/S2/S14 checks call for. Tree-hash
/// and parent-hash coverage from the same vector file lands separately
/// once those algorithms exist.
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

	@Test(
		"every vector tree has correctly-parity-matched node kinds and no trailing blank",
		arguments: records)
	func vectorTreesAreStructurallyWellFormed(_ record: TreeValidationVector) throws {
		let tree = try Self.decodeTree(record)
		#expect(throws: Never.self) { try tree.validateNodeKinds() }
		#expect(throws: Never.self) { try tree.validateNoTrailingBlank() }
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
