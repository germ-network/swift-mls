import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import Testing

@testable import MLSProfileRFC9420

@Suite("LeafNodeTBS context/source consistency")
struct LeafNodeTests {
	static func leafNode(source: MLS.RFC9420.LeafNodeSource) -> MLS.RFC9420.LeafNode {
		MLS.RFC9420.LeafNode(
			encryptionKey: MLS.HpkePublicKey(Data()),
			signatureKey: MLS.SignaturePublicKey(Data()),
			credential: .basic(identity: Data()),
			capabilities: MLS.RFC9420.Capabilities(
				versions: [], cipherSuites: [], extensions: [], proposals: [],
				credentials: []),
			source: source, extensions: [], signature: Data())
	}

	static let context: (groupID: Data, leafIndex: MLS.LeafIndex) = (
		Data(), MLS.LeafIndex(value: 0)
	)

	@Test("a keyPackage source rejects a supplied groupContext")
	func keyPackageRejectsContext() {
		let node = Self.leafNode(
			source: .keyPackage(MLS.RFC9420.Lifetime(notBefore: 0, notAfter: 0)))
		#expect(throws: MLS.RFC9420.WireError.leafNodeTBSContextMismatch) {
			try node.toBeSigned(groupContext: Self.context)
		}
	}

	@Test("an update source requires a groupContext")
	func updateRequiresContext() {
		let node = Self.leafNode(source: .update)
		#expect(throws: MLS.RFC9420.WireError.leafNodeTBSContextMismatch) {
			try node.toBeSigned(groupContext: nil)
		}
	}

	@Test("a commit source requires a groupContext")
	func commitRequiresContext() {
		let node = Self.leafNode(source: .commit(parentHash: Data()))
		#expect(throws: MLS.RFC9420.WireError.leafNodeTBSContextMismatch) {
			try node.toBeSigned(groupContext: nil)
		}
	}

	@Test("matching source/context pairs succeed")
	func matchingPairsSucceed() throws {
		_ = try Self.leafNode(
			source: .keyPackage(MLS.RFC9420.Lifetime(notBefore: 0, notAfter: 0))
		).toBeSigned(groupContext: nil)
		_ = try Self.leafNode(source: .update).toBeSigned(groupContext: Self.context)
		_ = try Self.leafNode(source: .commit(parentHash: Data())).toBeSigned(
			groupContext: Self.context)
	}
}
