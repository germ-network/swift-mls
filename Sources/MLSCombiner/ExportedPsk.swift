import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

extension MLS.Combiner {
	/// A draft-02 `application` PSK exported from a group's exporter tree
	/// (draft-ietf-mls-combiner-02 §6.2): the `component_id` and `psk_id` that name it
	/// in a commit's `PreSharedKey` proposal, the local `storage_id` its value is
	/// looked up under, and the value itself.
	///
	/// The crypto is the reused `MLSExtensions` / profile substrate — a single
	/// `SafeExportSecret(component_id)` (consuming the epoch's exporter-tree leaf) then
	/// `DeriveSecret(exporter, "psk_id")` and `DeriveSecret(exporter, "psk")`. This
	/// descriptor only bundles the results and the commit/store plumbing; it adds no
	/// derivation of its own. Both parties on the same `(group, epoch, component)`
	/// derive an identical `ExportedPsk`.
	public struct ExportedPsk: Sendable {
		/// The component id naming this application PSK in a commit.
		public let componentID: MLS.Extensions.ComponentID
		/// The opaque `psk_id` naming this application PSK in a commit.
		public let pskID: Data
		/// The store key the PSK value is installed under —
		/// `0x03 ‖ component_id ‖ psk_id<V>` with a `uint16` component id
		/// (`PreSharedKeyIdentifier.applicationStorageID`). Deliberately width-pinned
		/// and purely local: it never crosses the wire, so it is stable across a
		/// `componentIDWireWidth` switch (a PSK derived outside a `.uint32` scope still
		/// resolves against a fork commit processed inside one).
		public let storageID: Data
		/// The PSK value, zeroizing end-to-end: the profile's PSK ingress is
		/// `(PreSharedKeyIdentifier) -> SecretBytes?`, so this never copies to `Data`.
		public let psk: SecretBytes
		// The memberwise initializer is intentionally internal (synthesized): callers
		// outside the module build an `ExportedPsk` only via `export`/`fromParts`.
	}
}

extension MLS.Combiner.ExportedPsk {
	/// The local store key for `(component_id, psk_id)` — the encoded `application`
	/// identity without the nonce, `uint16`-pinned. Shared by `export` and
	/// `fromParts` so both key the store identically.
	static func storageID(
		componentID: MLS.Extensions.ComponentID, pskID: Data
	) throws -> Data {
		let identifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: pskID, nonce: Data())
		guard let storageID = try identifier.applicationStorageID() else {
			// Unreachable: `.application` always yields a storage id.
			throw MLS.Combiner.Error.internalInconsistency
		}
		return storageID
	}

	/// Derive the `apq_psk` for `group`'s current epoch and the given component: one
	/// consuming `safeExportSecret` then the `"psk_id"`/`"psk"` derivations
	/// (`Group.deriveApplicationPSK`). The exporter leaf is **consumed**, so a given
	/// `(group, epoch, component)` exports at most once — hence `inout` — and a caller
	/// that needs the value again must hold onto the returned descriptor.
	public static func export(
		from group: inout MLS.RFC9420.Group,
		_ provider: any MLS.CipherSuiteProvider,
		componentID: MLS.Extensions.ComponentID
	) throws -> MLS.Combiner.ExportedPsk {
		let (pskID, psk) = try group.deriveApplicationPSK(
			provider, componentID: componentID)
		return MLS.Combiner.ExportedPsk(
			componentID: componentID,
			pskID: pskID,
			storageID: try storageID(componentID: componentID, pskID: pskID),
			psk: psk)
	}

	/// Reconstruct an `ExportedPsk` from archived parts, recomputing the store key.
	/// The value is not re-derived from any group (the exporter leaf is long
	/// consumed) — this is how restored state recovers a ledgered PSK.
	public static func fromParts(
		componentID: MLS.Extensions.ComponentID, pskID: Data, psk: SecretBytes
	) throws -> MLS.Combiner.ExportedPsk {
		MLS.Combiner.ExportedPsk(
			componentID: componentID,
			pskID: pskID,
			storageID: try storageID(componentID: componentID, pskID: pskID),
			psk: psk)
	}

	/// The `PreSharedKeyID` naming this PSK in a commit, with a caller-supplied
	/// `psk_nonce` (RFC 9420 §8.4: "a fresh random value of length KDF.Nh"). Its
	/// `component_id` encodes at the ambient `componentIDWireWidth`; encode/commit
	/// under the [`Codepoints`] wire-width scope for deployed interop.
	public func preSharedKeyID(nonce: Data) -> MLS.RFC9420.PreSharedKeyIdentifier {
		.application(componentID: componentID, pskID: pskID, nonce: nonce)
	}

	/// The `.preSharedKey` proposal referencing this PSK, for a commit's proposal list.
	public func proposal(nonce: Data) -> MLS.RFC9420.Proposal {
		.preSharedKey(preSharedKeyID(nonce: nonce))
	}
}

extension MLS.Combiner {
	/// The combiner's PSK store: the values a group's commit/join operations resolve
	/// `application` PSKs from, keyed by the local `storage_id`. It backs the
	/// resolver the combiner passes to `committing`/`joining`/`validating`, and is
	/// held on the `CombinerGroup` rather than on either half — the profile has no
	/// per-group PSK store (resolution is a closure), and a construction-time value
	/// (the `apq_psk`) must outlive any later client rotation.
	public struct PSKStore: Sendable {
		private var entries: [Data: SecretBytes] = [:]

		public init() {}

		/// Install an exported PSK's value under its store key.
		public mutating func register(_ exported: ExportedPsk) {
			entries[exported.storageID] = exported.psk
		}

		/// Remove a PSK once the commit that referenced it has been applied (or it has
		/// been retired), keeping the store bounded by what the caller still vouches for.
		/// A downstream seam: not exercised within this module, since the store is
		/// ephemeral — a live `apq_psk` is already folded into the epoch secrets once
		/// its referencing commit is applied, with nothing left here to forget.
		public mutating func forget(storageID: Data) {
			entries[storageID] = nil
		}

		/// A resolver over a snapshot of this store, for one commit/join/validate call.
		/// It maps an `application` `PreSharedKeyID` to its value by the same
		/// `uint16`-pinned `storage_id` `register` keyed it under, handing back the
		/// zeroizing value directly (the profile's PSK ingress is `SecretBytes?`).
		/// Non-`application` ids resolve to `nil` — the combiner injects only
		/// `application` PSKs.
		public func resolver()
			-> (MLS.RFC9420.PreSharedKeyIdentifier) throws -> SecretBytes?
		{
			let snapshot = entries
			return { identifier in
				guard let storageID = try identifier.applicationStorageID(),
					let secret = snapshot[storageID]
				else { return nil }
				return secret
			}
		}

		/// What a [`recordingResolver`] observed during one commit/join/validate call:
		/// the storage ids it actually resolved a value for. A successful resolution is
		/// the only evidence that (a) the commit's proposal list referenced that PSK,
		/// and (b) we held its value — so this is how a caller confirms, after the
		/// call, that a specific PSK (e.g. the `apq_psk` of the current PQ epoch) was
		/// really folded in, rather than merely present in the store.
		///
		/// Deliberately NOT `Sendable`: resolution happens synchronously, inline,
		/// within a single `committing`/`joining`/`validating` call on the thread
		/// that made it — the profile's PSK closure is not `@Sendable` and is never
		/// invoked concurrently — so there is nothing here to synchronize, and
		/// claiming `Sendable` would advertise safety for the unsynchronized
		/// `resolvedStorageIDs` mutation that does not hold.
		public final class ResolutionRecord {
			private var resolvedStorageIDs: Set<Data> = []

			fileprivate func note(_ id: Data) { resolvedStorageIDs.insert(id) }

			/// Whether `storageID` was resolved (to a non-nil secret) during the call
			/// this record came from.
			public func resolved(_ storageID: Data) -> Bool {
				resolvedStorageIDs.contains(storageID)
			}
		}

		/// Like [`resolver`], but also records every storage id it successfully
		/// resolves into the returned `ResolutionRecord` — recorded only on a
		/// non-nil resolution, since that is what proves the PSK was both referenced
		/// by the commit and held by us. Pass the resolver to `joining`/`validating`;
		/// inspect the record afterward.
		public func recordingResolver()
			-> (
				resolver: (MLS.RFC9420.PreSharedKeyIdentifier) throws ->
					SecretBytes?,
				record: ResolutionRecord
			)
		{
			let snapshot = entries
			let record = ResolutionRecord()
			let resolver: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> SecretBytes? =
				{
					identifier in
					guard let storageID = try identifier.applicationStorageID(),
						let secret = snapshot[storageID]
					else { return nil }
					record.note(storageID)
					return secret
				}
			return (resolver, record)
		}
	}
}
