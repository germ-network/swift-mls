import Foundation
import MLSCodec
import MLSCrypto
import MLSSecretTree
import MLSTreeMath
import SecretBytes

extension MLS.Extensions {
	/// draft-ietf-mls-extensions §4.4 (Exported Secrets). The Exporter Tree
	/// is the RFC 9420 §9 Secret Tree with three changes: it always has 2^16
	/// leaves, its root is the `application_export_secret`
	/// (`DeriveSecret(epoch_secret, "application_export")`), and its leaves are
	/// indexed by a `ComponentID` rather than a member `LeafIndex`. Node
	/// derivation (`ExpandWithLabel(parent, "tree", "left"/"right", Nh)`) and the
	/// §9.2 deletion schedule are identical — so this composes `MLSSecretTree`'s
	/// `ConsumingSecretTree` verbatim, only fixing the leaf count and swapping
	/// the root.
	///
	/// `SafeExportSecret(component_id)` is the leaf secret at `component_id`,
	/// **consumed** on export: a `(group, epoch, component)` triple exports at
	/// most once (forward secrecy), which is why export mutates. Distinct
	/// components stay independently exportable — consuming one caches its copath
	/// siblings, never stranding another's subtree.
	///
	/// The tree is indexed by a `ComponentID` (a `UInt16`, tracking draft-09 — see
	/// that type). Its 2^16 leaves are exactly the 16 bits of a `ComponentID`, so
	/// every id names a distinct valid leaf and none is out of range.
	public struct ExporterTree: Sendable {
		/// The fixed 2^16-leaf count — the 16 bits of a `ComponentID`.
		public static let leafCount = try! MLS.LeafCount(validating: 1 << 16)

		private var tree: MLS.SecretTree.ConsumingSecretTree

		/// Roots the tree at the epoch's `application_export_secret`
		/// (`EpochFanOut.applicationExportSecret`).
		public init(applicationExportSecret: some ContiguousBytes) throws {
			self.tree = try MLS.SecretTree.ConsumingSecretTree(
				encryptionSecret: applicationExportSecret, leafCount: Self.leafCount
			)
		}

		/// The surviving node secrets — the §9.2 frontier after any consumption.
		/// Persisting *this* (not the root) is what lets a restored tree keep its
		/// forward secrecy: a consumed component's path nodes are absent here, so
		/// it cannot be re-derived. Retaining the root instead would re-derive
		/// every component, defeating the consume-once deletion.
		///
		/// Sparse, not 2^16: the tree materializes nodes on demand, so an
		/// unexported tree holds one secret (the root), and each export leaves at
		/// most one copath sibling per level — `O(exports × log2(2^16) = 16)`,
		/// less with the overlap of nearby component ids. So this is what the
		/// archive carries: a handful of secrets, never a leaf per component.
		public var frontier: [UInt32: SecretBytes] { tree.nodeSecrets }

		/// Restores a tree from a persisted `frontier`, at the fixed 2^16 leaves.
		/// The root is *not* an input — an already-consumed component stays
		/// unrecoverable, unlike a root-seeded rebuild.
		public init(restoringFrontier frontier: [UInt32: SecretBytes]) {
			self.tree = MLS.SecretTree.ConsumingSecretTree(
				restoringNodeSecrets: frontier, leafCount: Self.leafCount)
		}

		public enum ExportError: Error, Sendable, Equatable {
			/// This component's secret was already exported (and deleted) this
			/// epoch — a re-export/replay signal, not a derivation failure.
			case componentSecretConsumed(ComponentID)
		}

		/// `SafeExportSecret(component_id)` — the component's leaf secret, of
		/// length `KDF.Nh`. Consumes the leaf: exporting the same component again
		/// this epoch throws `componentSecretConsumed`. Every `ComponentID` (a
		/// `uint16`) names a valid leaf of the 2^16-leaf tree, so there is no
		/// out-of-range case.
		public mutating func safeExportSecret(
			_ provider: any MLS.CipherSuiteProvider, componentID: ComponentID
		) throws -> SecretBytes {
			do {
				return try tree.consumeLeafSecret(
					for: MLS.LeafIndex(value: UInt32(componentID.rawValue)),
					provider)
			} catch MLS.SecretTree.SecretTreeError.subtreeExhausted {
				throw ExportError.componentSecretConsumed(componentID)
			}
		}
	}
}
