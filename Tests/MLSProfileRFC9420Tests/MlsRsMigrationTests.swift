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

	/// spec/snapshot.md §4.7 reconstruct rule: format-1 restore lifts the current
	/// epoch's own-leaf chains into `Membership.own_send`, so a migrated member
	/// that had already sent resumes at its recorded generation instead of
	/// re-seeding at 0 (which would throw `subtreeExhausted` against the
	/// §9.2-deleted leaf secret). Transcribe a live 2-member group that has sent
	/// into a format-1 archive, restore, and prove the resumed member keeps
	/// sending in generation order to a co-member.
	@Test("format-1 restore reconstructs own_send so a member that had sent resumes")
	func format1ReconstructsOwnSend() throws {
		typealias G = MLS.RFC9420.Group
		let provider = SelfInteropTests.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		var groupB = try G.join(
			provider, welcome: try #require(add.welcome),
			credentials: bob.joinCredentials, psk: { _ in nil })

		// Alice sends in the current epoch → her own send ratchets seed; Bob
		// consumes generation 0, and the own application chain head advances to 1.
		let m0 = try groupA.protect(
			provider, applicationData: Data("m0".utf8), signingKey: alice.signingKey)
		_ = try groupB.unprotect(provider, message: m0)

		// Transcribe groupA's format-2 snapshot into a format-1 archive: the
		// current epoch's own_send chains move into the store's `chains` at the
		// own-leaf keys, with own_next_generation set from their heads (the shape
		// an mls-rs export carries).
		let snap = try groupA.makeSnapshot()
		let leaf = UInt64(groupA.myLeafIndex.value)
		let currentEpoch = groupA.context.epoch
		let membership = try #require(snap.memberships.entries[leaf])
		let ownSend = try #require(membership.ownSend)

		var stores: [UInt64: G.MessageSecretStoreFormat1Archive] = [:]
		for (epoch, store) in snap.core.messageSecrets.entries {
			var chains = store.chains.entries
			var ownNext = G.OwnNextGenerationArchive(handshake: 0, application: 0)
			if epoch == currentEpoch {
				chains[(leaf << 1) | 0] = ownSend.handshakeChain
				chains[(leaf << 1) | 1] = ownSend.applicationChain
				ownNext = G.OwnNextGenerationArchive(
					handshake: ownSend.handshakeChain.headGeneration,
					application: ownSend.applicationChain.headGeneration)
			}
			stores[epoch] = G.MessageSecretStoreFormat1Archive(
				groupContext: store.groupContext,
				senderDataSecret: store.senderDataSecret,
				signatureKeys: store.signatureKeys,
				secretTree: store.secretTree,
				chains: MLS.RFC9420.IntegerKeyedMap(chains),
				ownNextGeneration: ownNext)
		}

		let format1 = G.SnapshotFormat1(
			format: 1,
			groupContext: snap.core.groupContext,
			ratchetTree: snap.core.ratchetTree,
			interimTranscriptHash: snap.core.interimTranscriptHash,
			myLeafIndex: UInt32(leaf),
			epochSecrets: snap.core.epochSecrets,
			treeSecretKeys: membership.treeSecretKeys,
			resumptionPsks: snap.core.resumptionPsks,
			messageSecrets: MLS.RFC9420.IntegerKeyedMap(stores),
			retention: snap.core.retention,
			config: snap.core.config,
			exporterTree: snap.core.exporterTree)

		var restoredA = try G.restore(
			from: try SecretArchive(encoding: format1), provider)

		// The reconstructed own_send resumes at generation 1: Alice sends again and
		// Bob — who consumed generation 0 — decrypts it. A re-seed at 0 (the discard
		// path) would throw `subtreeExhausted` here against the consumed leaf secret.
		let m1 = try restoredA.protect(
			provider, applicationData: Data("m1".utf8), signingKey: alice.signingKey)
		let opened = try groupB.unprotect(provider, message: m1)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("m1".utf8))
	}
}
