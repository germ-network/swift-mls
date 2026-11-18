import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSTreeMath
import Testing

@testable import MLSProfileRFC9420

/// A ratchet tree from any source holds at most `maxRatchetTreeNodeCount`
/// nodes, each costing one word of storage in the decoded array and in the
/// tree. Serialized: the over-maximum cases each allocate about 134 MB.
@Suite("Ratchet tree size bounds", .serialized)
struct RatchetTreeDecodeLimitTests {
	@Test("a decoded profile node costs one word in an array")
	func decodedNodeIsCompact() throws {
		#expect(
			MemoryLayout<MLS.RFC9420.Node?>.stride == MemoryLayout<Int>.stride)
	}

	@Test("a tree node costs one word in a ratchet tree's storage")
	func treeNodeIsCompact() throws {
		#expect(
			MemoryLayout<MLS.TreeKEM.TreeNode?>.stride == MemoryLayout<Int>.stride)
	}

	@Test("maxRatchetTreeNodeCount is the longest array LeafCount admits")
	func maxNodeCountMatchesLeafCountCeiling() throws {
		let limit = MLS.RFC9420.maxRatchetTreeNodeCount
		#expect(limit == (1 << 24) - 1)
		#expect(throws: Never.self) { _ = try MLS.LeafCount(nodeArrayCount: limit) }
		#expect(throws: MLS.TreeMathError.invalidLeafCount(1 << 24)) {
			_ = try MLS.LeafCount(nodeArrayCount: limit + 1)
		}
	}

	@Test("bytes after a complete ratchet_tree encoding are rejected")
	func trailingBytesAfterTreeAreRejected() throws {
		var writer = MLS.Writer()
		try writer.writeOpaque([UInt8(0)])
		writer.writeUInt8(0)
		#expect(throws: MLS.CodecError.trailingBytes(1)) {
			_ = try MLS.RFC9420.decodeRatchetTree(Data(writer.bytes))
		}
	}

	@Test("a ratchet_tree one node over the maximum is rejected while decoding")
	func overlongTreeRejectedWhileDecoding() throws {
		let encoded = Self.overlongTreeEncoding()
		#expect(
			throws: MLS.CodecError.vectorElementLimitExceeded(
				limit: MLS.RFC9420.maxRatchetTreeNodeCount)
		) {
			_ = try MLS.RFC9420.decodeRatchetTree(encoded)
		}
	}

	@Test("a GroupInfo ratchet_tree one node over the maximum is rejected while decoding")
	func overlongGroupInfoTreeRejected() throws {
		var groupInfo = try GroupMutationTests.buildScenario().groupInfo
		groupInfo.extensions = [
			MLS.RFC9420.Extension(
				type: MLS.RFC9420.ExtensionType(.ratchetTree),
				data: Self.overlongTreeEncoding())
		]
		#expect(
			throws: MLS.CodecError.vectorElementLimitExceeded(
				limit: MLS.RFC9420.maxRatchetTreeNodeCount)
		) {
			_ = try groupInfo.ratchetTreeExtension()
		}
	}

	@Test("a snapshot ratchet tree one node over the maximum is rejected while decoding")
	func overlongSnapshotTreeRejected() throws {
		let group = try SelfInteropTests.createGroup(try SelfInteropTests.member("solo"))
		var snapshot = try group.makeSnapshot()
		snapshot.core.ratchetTree = Self.overlongTreeEncoding()
		#expect(
			throws: MLS.CodecError.vectorElementLimitExceeded(
				limit: MLS.RFC9420.maxRatchetTreeNodeCount)
		) {
			_ = try MLS.RFC9420.Group.restore(from: snapshot, SelfInteropTests.provider)
		}
	}

	@Test("a node array one over the maximum is rejected with invalidLeafCount")
	func overlongNodeArrayRejectedWithInvalidLeafCount() throws {
		// Index 0's leaf cannot be encoded (its credential identity is past the
		// largest opaque length), so converting it would throw a different
		// error; only a length check ahead of the conversion yields
		// `invalidLeafCount`. The identity bytes are never touched.
		let unencodable = MLS.RFC9420.LeafNode(
			encryptionKey: .init(Data()), signatureKey: .init(Data()),
			credential: .basic(identity: Data(count: 1 << 30)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [], proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		var nodes = [MLS.RFC9420.Node?](
			repeating: nil, count: MLS.RFC9420.maxRatchetTreeNodeCount + 1)
		nodes[0] = .leaf(unencodable)
		#expect(throws: MLS.TreeMathError.invalidLeafCount(1 << 24)) {
			_ = try MLS.TreeKEM.RatchetTree(nodes)
		}
	}

	/// `optional<Node> ratchet_tree<V>` with one blank node past the maximum.
	private static func overlongTreeEncoding() -> Data {
		var writer = MLS.Writer()
		try! writer.writeOpaque(
			[UInt8](repeating: 0, count: MLS.RFC9420.maxRatchetTreeNodeCount + 1))
		return Data(writer.bytes)
	}
}
