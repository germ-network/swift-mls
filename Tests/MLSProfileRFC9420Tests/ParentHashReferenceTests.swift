import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420
@testable import MLSTreeKEM

/// `validateParentHashChain` must give the same verdict, and the same error,
/// as `validateUnmergedLeaves()` followed by the straightforward
/// implementation of RFC 9420 §7.9.2's bottom-up procedure. The reference is
/// self-contained: its own filtered tree hash (the §7.9 original sibling tree
/// hash), parent-hash input encoding and recursive descendant walk, over
/// public tree accessors and the provider only. It is slow by design, so the
/// mutation test runs only on small trees.
@Suite("Parent-hash validation agrees with the reference implementation")
struct ParentHashReferenceTests {
	static let provider = SwiftCryptoProvider()

	private static func decodeTree(_ record: TreeValidationVector) throws
		-> MLS.TreeKEM.RatchetTree
	{
		var reader = MLS.Reader(record.tree.bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return try MLS.TreeKEM.RatchetTree(nodes)
	}

	private static func cipherSuiteProvider(_ record: TreeValidationVector) throws
		-> any MLS.CipherSuiteProvider
	{
		try #require(provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
	}

	/// The verdict as a comparable value: `nil` for accepted, else the error.
	private static func verdict(_ body: () throws -> Void) -> String? {
		do {
			try body()
			return nil
		} catch {
			return String(reflecting: error)
		}
	}

	private static func expectAgreement(
		_ tree: MLS.TreeKEM.RatchetTree, _ provider: any MLS.CipherSuiteProvider,
		_ context: @autoclosure () -> String,
		_ location: SourceLocation = #_sourceLocation
	) {
		let expected = verdict { try Reference.validate(tree, provider) }
		let actual = verdict { try tree.validateParentHashChain(provider) }
		#expect(actual == expected, Comment(rawValue: context()), sourceLocation: location)
	}

	@Test("every tree-validation vector tree gets the same result from both")
	func vectorTreesAgree() throws {
		for record in TreeValidationTests.records {
			let tree = try Self.decodeTree(record)
			Self.expectAgreement(
				tree, try Self.cipherSuiteProvider(record),
				"suite \(record.cipherSuite)")
		}
	}

	@Test("every single-node mutation of a vector tree gets the same result from both")
	func mutatedVectorTreesAgree() throws {
		var mutations = 0
		for record in TreeValidationTests.records
		where record.cipherSuite == 1 && record.resolutions.count <= 31 {
			let tree = try Self.decodeTree(record)
			let provider = try Self.cipherSuiteProvider(record)
			for variant in try Self.singleNodeMutations(of: tree) {
				Self.expectAgreement(variant.tree, provider, variant.name)
				mutations += 1
			}
		}
		#expect(mutations > 500)
	}

	private static func singleNodeMutations(of tree: MLS.TreeKEM.RatchetTree) throws
		-> [(name: String, tree: MLS.TreeKEM.RatchetTree)]
	{
		var variants: [(name: String, tree: MLS.TreeKEM.RatchetTree)] = []
		for index in 0..<tree.serializedNodeCount {
			guard let node = tree.node(at: index) else { continue }
			var blanked = tree
			try blanked.setNode(at: index, to: nil)
			variants.append(("blank node \(index)", blanked))

			switch node {
			case .leaf(let record):
				guard let parentHash = record.parentHash, !parentHash.isEmpty else {
					continue
				}
				var flipped = parentHash
				flipped[flipped.startIndex] ^= 0x01
				var variant = tree
				try variant.setLeaf(
					MLS.LeafIndex(value: index / 2),
					to: MLS.TreeKEM.LeafRecord(
						encryptionKey: record.encryptionKey,
						parentHash: flipped,
						encoded: record.encoded))
				variants.append(("flip leaf \(index) parent_hash", variant))
			case .parent(let parentNode):
				if !parentNode.parentHash.isEmpty {
					var flipped = parentNode
					flipped.parentHash[flipped.parentHash.startIndex] ^= 0x01
					var variant = tree
					try variant.setParent(index, to: flipped)
					variants.append(
						("flip parent \(index) parent_hash", variant))
				}
				for entry in parentNode.unmergedLeaves.indices {
					var removed = parentNode
					removed.unmergedLeaves.remove(at: entry)
					var variant = tree
					try variant.setParent(index, to: removed)
					variants.append(
						("remove unmerged \(entry) at \(index)", variant))
				}
				for leaf in 0..<tree.leafCount.value {
					let added = MLS.LeafIndex(value: leaf)
					guard !parentNode.unmergedLeaves.contains(added) else {
						continue
					}
					var extended = parentNode
					extended.unmergedLeaves.append(added)
					extended.unmergedLeaves.sort()
					var variant = tree
					try variant.setParent(index, to: extended)
					variants.append(
						("add unmerged \(leaf) at \(index)", variant))
				}
			}
		}
		return variants
	}

	/// `validateUnmergedLeaves()` followed by RFC 9420 §7.9.2's bottom-up
	/// procedure written out directly: every non-blank parent must be covered
	/// by exactly one chain, and a chain ends at the first node whose
	/// `parent_hash` doesn't match.
	private enum Reference {
		static func validate(
			_ tree: MLS.TreeKEM.RatchetTree, _ provider: any MLS.CipherSuiteProvider
		) throws {
			try tree.validateUnmergedLeaves()
			var toValidate = Set<UInt32>()
			for i in stride(from: UInt32(1), to: tree.serializedNodeCount, by: 2)
			where tree.parent(at: i) != nil {
				toValidate.insert(i)
			}
			for (leafIndex, _) in tree.nonBlankLeaves() {
				try validateChain(
					from: 2 * leafIndex.value, tree, provider, &toValidate)
			}
			guard toValidate.isEmpty else {
				throw MLS.TreeKEM.TreeError.parentHashMismatch
			}
		}

		private static func validateChain(
			from origin: UInt32, _ tree: MLS.TreeKEM.RatchetTree,
			_ provider: any MLS.CipherSuiteProvider, _ toValidate: inout Set<UInt32>
		) throws {
			let leafCount = tree.leafCount
			var n = origin
			while let immediate = MLS.TreeMath.parent(n, leafCount: leafCount) {
				var ancestor = immediate
				var copath = MLS.TreeMath.sibling(n, leafCount: leafCount)!
				while tree.isBlank(at: ancestor) {
					guard
						let next = MLS.TreeMath.parent(
							ancestor, leafCount: leafCount)
					else { return }
					copath = MLS.TreeMath.sibling(
						ancestor, leafCount: leafCount)!
					ancestor = next
				}
				guard let ancestorNode = tree.parent(at: ancestor) else {
					throw MLS.TreeKEM.TreeError.notAMember
				}
				let claimed =
					MLS.TreeMath.isLeaf(n)
					? tree.leaf(at: .init(value: n / 2))?.parentHash
					: tree.parent(at: n)?.parentHash

				let siblingHash = try treeHash(
					tree, copath, filter: Set(ancestorNode.unmergedLeaves),
					provider)
				var input = MLS.Writer()
				try ancestorNode.encryptionKey.encode(to: &input)
				try input.writeOpaque(ancestorNode.parentHash)
				try input.writeOpaque(siblingHash)
				let calculated = try provider.hash(Data(input.bytes))
				guard claimed == calculated else { return }

				guard let c = MLS.TreeMath.sibling(copath, leafCount: leafCount)
				else {
					throw MLS.TreeKEM.TreeError.parentHashMismatch
				}
				var resolution = Set(tree.resolution(of: c))
				guard resolution.remove(n) != nil else {
					throw MLS.TreeKEM.TreeError.parentHashMismatch
				}
				let unmergedInSubtree = Set(
					ancestorNode.unmergedLeaves.map { 2 * $0.value }.filter {
						isDescendant($0, of: c)
					})
				guard resolution == unmergedInSubtree else {
					throw MLS.TreeKEM.TreeError.parentHashMismatch
				}
				guard toValidate.remove(ancestor) != nil else {
					throw MLS.TreeKEM.TreeError.parentHashCoveredTwice
				}
				n = ancestor
			}
		}

		/// RFC 9420 §7.8 over the tree as it was before `filter`'s leaves
		/// were added: those leaves hash as blank and no parent lists them.
		private static func treeHash(
			_ tree: MLS.TreeKEM.RatchetTree, _ index: UInt32,
			filter: Set<MLS.LeafIndex>, _ provider: any MLS.CipherSuiteProvider
		) throws -> Data {
			var writer = MLS.Writer()
			if MLS.TreeMath.isLeaf(index) {
				writer.writeUInt8(1)
				let leafIndex = MLS.LeafIndex(value: index / 2)
				try leafIndex.encode(to: &writer)
				let record =
					filter.contains(leafIndex) ? nil : tree.leaf(at: leafIndex)
				writer.writeUInt8(record == nil ? 0 : 1)
				if let record { writer.writeBytes(record.encoded) }
			} else {
				writer.writeUInt8(2)
				var parentNode = tree.parent(at: index)
				parentNode?.unmergedLeaves.removeAll { filter.contains($0) }
				try writer.encodeOptional(parentNode)
				let left = try treeHash(
					tree, MLS.TreeMath.left(index), filter: filter, provider)
				let right = try treeHash(
					tree, MLS.TreeMath.right(index), filter: filter, provider)
				try writer.writeOpaque(left)
				try writer.writeOpaque(right)
			}
			return try provider.hash(Data(writer.bytes))
		}

		private static func isDescendant(_ node: UInt32, of root: UInt32) -> Bool {
			if node == root { return true }
			guard !MLS.TreeMath.isLeaf(root) else { return false }
			return isDescendant(node, of: MLS.TreeMath.left(root))
				|| isDescendant(node, of: MLS.TreeMath.right(root))
		}
	}
}
