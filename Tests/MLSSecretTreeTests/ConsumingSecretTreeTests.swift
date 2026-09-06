import Foundation
import MLSCodec
import MLSCrypto
import MLSKeySchedule
import MLSSecretTree
import SecretBytes
import Testing

/// The relocated consuming secret-tree mechanism (RFC 9420 §9.2 deletion
/// schedule), differentially tested against `MLSKeySchedule`'s stateless
/// `leafSecret` oracle — the reference the walker must agree with. Homed in
/// `MLSSecretTree`, beside the mechanism it exercises.
@Suite("ConsumingSecretTree (RFC 9420 §9.2 deletion schedule)")
struct ConsumingSecretTreeTests {
	static let provider = SwiftCryptoProvider()

	/// The consuming walker against the stateless vector-pinned oracle:
	/// every leaf of an 8-leaf tree, derived in adversarial order, must equal
	/// `leafSecret`. The oracle (`MLSKeySchedule.leafSecret`) walks from the
	/// root every time; the walker deletes each path node and caches copath
	/// siblings, yet must land on the same per-leaf secret.
	@Test("the consuming secret tree agrees with the stateless oracle on every leaf")
	func consumingTreeMatchesOracle() throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .curve25519Aes128))
		let encryptionSecret = provider.randomBytes(provider.hashSize)
		let leafCount = try MLS.LeafCount(validating: 8)
		var tree = try MLS.SecretTree.ConsumingSecretTree(
			encryptionSecret: encryptionSecret, leafCount: leafCount)
		for leaf in [5, 0, 7, 2, 6, 1, 3, 4] {
			let index = MLS.LeafIndex(value: UInt32(leaf))
			let consumed = try tree.consumeLeafSecret(for: index, provider)
			let oracle = try MLS.KeySchedule.leafSecret(
				provider, encryptionSecret: encryptionSecret,
				leafIndex: UInt32(leaf), numLeaves: leafCount)
			#expect(consumed.withUnsafeBytes { Data($0) } == oracle, "leaf \(leaf)")
		}
		// And the root is long gone: no leaf can be derived twice.
		#expect(throws: MLS.SecretTree.SecretTreeError.self) {
			_ = try tree.consumeLeafSecret(for: .init(value: 3), provider)
		}
	}
}
