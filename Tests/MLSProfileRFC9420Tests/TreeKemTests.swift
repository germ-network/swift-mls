import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeKEM
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// `treekem.json`: the strongest signal in this phase and the only one
/// exercising real HPKE — for each `update_paths` entry, every *other*
/// non-blank leaf decrypts its assigned path secret and derives forward,
/// and the resulting `commit_secret` must match. This is decap's actual
/// round trip against a sender it never coordinated with directly, using
/// only its own leaf's stored HPKE key — no separately-tracked ancestor
/// key store, matching what every `leaves_private` entry in this vector
/// actually provides.
@Suite("treekem.json (mlswg/mls-implementations, official)")
struct TreeKemTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load("treekem", as: [TreeKemVector].self)
		.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	private static func decodeTree(_ bytes: Data) throws -> MLS.TreeKEM.RatchetTree {
		var reader = MLS.Reader(bytes)
		let nodes: [MLS.RFC9420.Node?] = try reader.decodeVector()
		try reader.finish()
		return try MLS.TreeKEM.RatchetTree(nodes)
	}

	/// The `GroupContext` bytes used as `EncryptWithLabel`'s `info` for
	/// every `UpdatePathNode` ciphertext in this vector — pinned by trial
	/// against a real record rather than guessed, per the plan's own
	/// note that upstream's prose is ambiguous here. Confirmed: it's the
	/// tree hash *after* the committer's new leaf/path is merged in
	/// (`tree_hash_after`), re-encoded as a `GroupContext` with the
	/// vector's own `group_id`/`epoch`/`confirmed_transcript_hash` and
	/// empty extensions.
	private static func groupContextBytes(_ record: TreeKemVector, treeHashAfter: Data) throws
		-> Data
	{
		let context = MLS.RFC9420.GroupContext(
			version: .mls10, cipherSuite: .init(id: record.cipherSuite),
			groupID: record.groupID.bytes, epoch: record.epoch, treeHash: treeHashAfter,
			confirmedTranscriptHash: record.confirmedTranscriptHash.bytes,
			extensions: [])
		return try context.mlsEncoded()
	}

	@Test(
		"every other non-blank leaf decrypts its assigned path secret and recovers the same commit_secret",
		arguments: records)
	func decapRecoversCommitSecret(_ record: TreeKemVector) throws {
		let tree = try Self.decodeTree(record.ratchetTree.bytes)
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))

		// Every key a leaf currently holds: its own leaf key at its own
		// node index, plus whatever ancestor keys `path_secrets` says it
		// already derived (an earlier commit installed a shared key at
		// some non-blank ancestor covering it -- `resolution` reports
		// that ancestor's own node in that case, not the individual
		// leaves under it, so a receiver needs more than just its own
		// leaf key to find where it can decrypt).
		let heldKeysByLeaf = try Dictionary(
			uniqueKeysWithValues: record.leavesPrivate.map { lp in
				var keys: [UInt32: MLS.HpkeSecretKey] = try [
					2 * lp.index: MLS.HpkeSecretKey(lp.encryptionPriv.bytes)
				]
				for entry in lp.pathSecrets {
					let secretKey = try MLS.TreeKEM.nodeKeyPair(
						provider, pathSecret: entry.pathSecret.bytes
					).secretKey
					keys[entry.node] = secretKey
				}
				return (MLS.LeafIndex(value: lp.index), keys)
			})

		for update in record.updatePaths {
			let sender = MLS.LeafIndex(value: update.sender)
			var reader = MLS.Reader(update.updatePath.bytes)
			let wirePath = try MLS.RFC9420.UpdatePath(from: &reader)
			try reader.finish()
			let pathNodes = wirePath.nodes.map(\.pathNode)

			let groupContext = try Self.groupContextBytes(
				record, treeHashAfter: update.treeHashAfter.bytes)

			for (leafIndex, heldKeys) in heldKeysByLeaf where leafIndex != sender {
				guard tree.leaf(at: leafIndex) != nil else { continue }
				let result = try tree.decapCommitPath(
					heldSecretKeys: heldKeys, sender: sender,
					pathNodes: pathNodes,
					groupContext: groupContext, provider)
				#expect(
					result.commitSecret == update.commitSecret.bytes,
					"leaf \(leafIndex.value) decapsulating sender \(sender.value)'s path"
				)
			}
		}
	}
}
