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
		/// The PSK value, zeroizing. Copied to `Data` only at the resolver boundary
		/// (the profile's only PSK ingress is `(PreSharedKeyIdentifier) -> Data?`).
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
			throw MLS.Combiner.Error.apqInfoMismatch
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
		public mutating func forget(storageID: Data) {
			entries[storageID] = nil
		}

		/// A resolver over a snapshot of this store, for one commit/join/validate call.
		/// It maps an `application` `PreSharedKeyID` to its value by the same
		/// `uint16`-pinned `storage_id` `register` keyed it under, copying the
		/// zeroizing value to `Data` at this boundary (the profile's PSK ingress type).
		/// Non-`application` ids resolve to `nil` — the combiner injects only
		/// `application` PSKs.
		public func resolver() -> (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? {
			let snapshot = entries
			return { identifier in
				guard let storageID = try identifier.applicationStorageID(),
					let secret = snapshot[storageID]
				else { return nil }
				return secret.withUnsafeBytes { Data($0) }
			}
		}
	}
}
