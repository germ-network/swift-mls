import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath
import SecretBytes

extension MLS.KeySchedule {
	/// draft-ietf-mls-extensions-08 §4.4 (Exported Secrets). The Exporter Tree
	/// is the RFC 9420 §9 Secret Tree with three changes: it always has 2^16
	/// leaves, its root is the `application_export_secret`
	/// (`DeriveSecret(epoch_secret, "application_export")`), and its leaves are
	/// indexed by a `ComponentID` rather than a member `LeafIndex`. Node
	/// derivation (`ExpandWithLabel(parent, "tree", "left"/"right", Nh)`) and the
	/// §9.2 deletion schedule are identical — so this composes the
	/// `ConsumingSecretTree` verbatim, only fixing the leaf count and swapping
	/// the root.
	///
	/// `SafeExportSecret(component_id)` is the leaf secret at `component_id`,
	/// **consumed** on export: a `(group, epoch, component)` triple exports at
	/// most once (forward secrecy), which is why export mutates. Distinct
	/// components stay independently exportable — consuming one caches its copath
	/// siblings, never stranding another's subtree.
	///
	/// The draft types `ComponentID` as `uint32` while giving the tree only 2^16
	/// leaves; draft-09 narrows the type to `uint16`. We keep `UInt32` at the API
	/// and reject ids ≥ 2^16 rather than truncating (which would collide distinct
	/// components onto one leaf) — matching the deployed fork.
	public struct ExporterTree: Sendable {
		/// The fixed 2^16-leaf count — the 16 bits of a `ComponentID`.
		public static let leafCount = try! MLS.LeafCount(validating: 1 << 16)

		private var tree: ConsumingSecretTree

		/// Roots the tree at the epoch's `application_export_secret`
		/// (`EpochFanOut.applicationExportSecret`).
		public init(applicationExportSecret: some ContiguousBytes) throws {
			self.tree = try ConsumingSecretTree(
				encryptionSecret: applicationExportSecret, leafCount: Self.leafCount
			)
		}

		/// The surviving node secrets — the §9.2 frontier after any consumption.
		/// Persisting *this* (not the root) is what lets a restored tree keep its
		/// forward secrecy: a consumed component's path nodes are absent here, so
		/// it cannot be re-derived. Retaining the root instead would re-derive
		/// every component, defeating the consume-once deletion.
		public var frontier: [UInt32: SecretBytes] { tree.nodeSecrets }

		/// Restores a tree from a persisted `frontier`, at the fixed 2^16 leaves.
		/// The root is *not* an input — an already-consumed component stays
		/// unrecoverable, unlike a root-seeded rebuild.
		public init(restoringFrontier frontier: [UInt32: SecretBytes]) {
			self.tree = ConsumingSecretTree(
				restoringNodeSecrets: frontier, leafCount: Self.leafCount)
		}

		public enum ExportError: Error, Sendable, Equatable {
			/// `component_id ≥ 2^16` — outside the Exporter Tree's leaf range.
			case invalidComponentID(UInt32)
			/// This component's secret was already exported (and deleted) this
			/// epoch — a re-export/replay signal, not a derivation failure.
			case componentSecretConsumed(UInt32)
		}

		/// `SafeExportSecret(component_id)` — the component's leaf secret, of
		/// length `KDF.Nh`. Consumes the leaf: exporting the same component again
		/// this epoch throws `componentSecretConsumed`. `component_id ≥ 2^16`
		/// throws `invalidComponentID`.
		public mutating func safeExportSecret(
			_ provider: any MLS.CipherSuiteProvider, componentID: UInt32
		) throws -> SecretBytes {
			guard componentID < Self.leafCount.value else {
				throw ExportError.invalidComponentID(componentID)
			}
			do {
				return try tree.consumeLeafSecret(
					for: MLS.LeafIndex(value: componentID), provider)
			} catch SecretTreeError.subtreeExhausted {
				throw ExportError.componentSecretConsumed(componentID)
			}
		}
	}
}
