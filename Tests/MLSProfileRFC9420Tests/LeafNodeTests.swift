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

	static let inGroup = MLS.RFC9420.LeafNode.Placement.inGroup(
		groupID: Data("g".utf8), leafIndex: MLS.LeafIndex(value: 0))

	/// RFC 9420 §10: "The field leaf_node.leaf_node_source of the LeafNode
	/// in a KeyPackage MUST be set to key_package." Both non-key_package
	/// sources bind a `(group_id, leaf_index)` a KeyPackage cannot supply,
	/// so this is caught at TBS assembly rather than by a failed signature.
	@Test(
		"a leaf found in a KeyPackage must be keyPackage-sourced",
		arguments: [
			MLS.RFC9420.LeafNodeSource.update, .commit(parentHash: Data()),
		])
	func keyPackagePlacementRejectsGroupSource(_ source: MLS.RFC9420.LeafNodeSource) {
		#expect(throws: MLS.RFC9420.WireError.leafNodeSourceNotKeyPackage) {
			try Self.leafNode(source: source).toBeSigned(placement: .keyPackage)
		}
	}

	/// The case that used to be an error and is not one. A member added by
	/// an Add proposal and never since updated carries the `key_package`
	/// source its KeyPackage had, and a joiner meets it *in the tree* —
	/// `.inGroup`. §7.2's `select (LeafNodeTBS.leaf_node_source)` keys the
	/// binding off the source alone, so that leaf signs unbound, and
	/// rejecting the pair would have made every such tree unverifiable.
	@Test("a keyPackage-sourced leaf in a tree signs without the group binding")
	func keyPackageSourceInGroupOmitsBinding() throws {
		let node = Self.leafNode(
			source: .keyPackage(MLS.RFC9420.Lifetime(notBefore: 0, notAfter: 0)))
		#expect(
			try node.toBeSigned(placement: Self.inGroup)
				== (try node.toBeSigned(placement: .keyPackage)))
	}

	/// The binding is the whole point: two leaves identical except for the
	/// group they sit in must not produce the same signed bytes, or a
	/// signature would transplant between groups.
	@Test(
		"an update/commit source binds group_id and leaf_index into the TBS",
		arguments: [
			MLS.RFC9420.LeafNodeSource.update, .commit(parentHash: Data()),
		])
	func groupSourceBindsPlacement(_ source: MLS.RFC9420.LeafNodeSource) throws {
		let node = Self.leafNode(source: source)
		let here = try node.toBeSigned(placement: Self.inGroup)
		let elsewhere = try node.toBeSigned(
			placement: .inGroup(
				groupID: Data("other".utf8), leafIndex: MLS.LeafIndex(value: 0)))
		let otherLeaf = try node.toBeSigned(
			placement: .inGroup(
				groupID: Data("g".utf8), leafIndex: MLS.LeafIndex(value: 1)))
		#expect(here != elsewhere)
		#expect(here != otherLeaf)
	}
}
