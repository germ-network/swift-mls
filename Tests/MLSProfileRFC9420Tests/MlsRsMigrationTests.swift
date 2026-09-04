import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import MLSVectorSupport
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// Cross-implementation migration: ingest the deployed Rust peer's plaintext
/// format-1 export (`mls-rs-pq` `Group::export_for_swift()`) via the
/// `SecretArchive` plaintext-ingress SPI and restore it as a swift
/// `MLS.RFC9420.Group`. This is the migration path a live mls-rs session takes
/// onto swift-mls; the fixture is a 2-member `P256_AES128` group carrying both a
/// ratchet chain and a secret-tree frontier (see `Vectors/README.md`).
///
/// Scope: this proves the *structural* mapping — the schema decodes, and the
/// restored ratchet tree hashes to the value the restored group_context commits
/// to. It does NOT verify secret *values*: the fixture is randomly keyed with no
/// live counterpart, so `init_secret`, `node_secrets`, chain `head_secret`, etc.
/// are checked only for presence and length, not against ground truth. The
/// honest end-to-end proof — decrypting the member-1 application message the
/// export's ratchet position points at — needs the Rust side to also emit that
/// ciphertext, and is a tracked follow-up.
@Suite("mls-rs → swift-mls format-1 migration")
struct MlsRsMigrationTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .p256Aes128)!

	@Test("the Rust plaintext export ingests and restores a consistent group")
	func rustExportRestores() throws {
		let provider = Self.provider
		let bytes = try VectorFile.rawBytes(
			"mls-rs-export-p256-classical", withExtension: "cbor")

		// The ingress the migration needed: plaintext CBOR → SecretArchive →
		// restore. Without `decodingPlaintext` the peer's bytes had no path in.
		let archive = SecretArchive(decodingPlaintext: bytes)
		let group = try MLS.RFC9420.Group.restore(from: archive, provider)

		// Structural mapping.
		#expect(group.context.cipherSuite == .p256Aes128)
		#expect(group.tree.leafCount.value == 2)
		#expect(group.myLeafIndex.value == 0)

		// Self-consistency: the restored ratchet tree hashes to the value the
		// restored group_context commits to. `restore` does not cross-check these
		// (tree_hash is parsed from the group_context wire bytes, recomputed from
		// the separately-decoded ratchet_tree), so this catches a misparse of
		// either — the strongest check available without a live counterpart.
		#expect(try group.tree.treeHash(provider) == group.context.treeHash)

		// The fatal-if-wrong assertion (archive-migration-format-notes §3): the
		// current epoch's message-secret store must carry BOTH a populated
		// ratchet chain (member 1's application message advanced one) AND a
		// secret-tree `node_secrets` frontier (reaching that leaf split the
		// interior). Losing either silently drops in-flight decryptability.
		let store = try #require(group.messageSecrets[group.context.epoch])
		#expect(!store.chains.isEmpty)
		#expect(!store.tree.nodeSecrets.isEmpty)
	}
}
