import Foundation
import MLSCodec
import SecretBytes

extension MLS.RFC9420 {
	/// Errors from snapshot encode/decode and restore validation. Kept apart
	/// from `GroupError`: those are the live join/commit pipeline's; these are
	/// the persistence boundary's, and a caller restoring a snapshot catches a
	/// different failure set than one processing a commit.
	public enum SnapshotError: Error, Sendable, Equatable {
		/// `format` is neither 2 (what this build encodes and decodes) nor 1 (the
		/// legacy flat shape, decode-only). spec/snapshot.md §5: an unknown
		/// `format` is a decode error, never a silent reinterpretation.
		case unsupportedFormat(UInt64)
		/// A `config` section was present. spec/snapshot.md §4.5: format 1
		/// defines no config keys, so the section MUST be absent — a group is
		/// never silently restored under rules it was not persisted under.
		case unexpectedConfig
		/// The restoring provider's cipher suite differs from the one named in
		/// `group_context` (spec/snapshot.md §4.1: `group_context` is the single
		/// source of truth for the suite).
		case cipherSuiteMismatch
		/// A length-constrained byte string (spec/snapshot.md §3.1) was the
		/// wrong length for the suite: `Nh`/`Nk`/`Nn`.
		case wrongLength(field: String, expected: Int, actual: Int)
		/// A `{ + uint => ... }` map the schema marks "never empty" was empty
		/// (spec/snapshot.md §4.1/§4.3).
		case unexpectedlyEmpty(field: String)
		/// An integer map key exceeded the addressable range (`Int`), so it
		/// could neither be emitted as a CBOR integer key nor round-tripped.
		/// Unreachable for real state (epochs and packed chain keys stay far
		/// below `Int.max`); a guard, not a path.
		case integerKeyUnrepresentable(UInt64)
		/// A `Chain` violated spec/snapshot.md §4.3's retirement rule:
		/// `head_secret` present with `head_generation == 2^32`, or absent with
		/// `head_generation != 2^32`.
		case malformedChainRetirement(headGeneration: UInt64, headSecretPresent: Bool)
		/// A skipped-key generation was ≥ the chain's `head_generation`
		/// (spec/snapshot.md §4.3: `skipped` keys MUST be < `head_generation`).
		case skippedGenerationNotBelowHead(generation: UInt64, headGeneration: UInt64)
		/// `own_next_generation` was `2^32` (spec/snapshot.md §4.3's "exhausted"
		/// sentinel). Legal in the format but unrepresentable in this build's
		/// `UInt32` own-generation counters; a peer emitting it cannot be
		/// restored here. Self-produced archives never emit it.
		case ownGenerationUnrepresentable(handshake: UInt64, application: UInt64)
		/// A `Retention` value was ≥ 2^32 (spec/snapshot.md §4.4: each < 2^32).
		case retentionValueOutOfRange(field: String, value: UInt64)
		/// A store's key packing, index bound, epoch key, or `group_context`
		/// consistency failed a spec/snapshot.md §4.3 cross-consistency MUST.
		case inconsistentStore(String)
		/// `tree_secret_keys` named a node that is not on the member's own
		/// direct path, is blank, or is out of range (spec/snapshot.md §4.1
		/// key 6).
		case treeSecretKeyOffDirectPath(node: UInt32)
		/// `my_leaf_index` did not name a non-blank leaf (spec/snapshot.md §4.1
		/// key 4 / ratchet_tree).
		case myLeafIndexBlank(UInt32)
		/// Retained for compatibility, no longer thrown: format 1 had no
		/// `pending_updates` field, so `makeSnapshot()` refused a `Group` holding
		/// an uncommitted self-proposed Update rather than silently dropping its
		/// leaf secret. Format 2 persists pending Updates per membership (and is
		/// what `makeSnapshot()` now emits), so this case is unreachable; format 1
		/// is decode-only and never encoded.
		case pendingUpdatesUnsupported
	}
}

extension MLS.RFC9420 {
	/// A CBOR **integer**-keyed map, for the `{ + uint => … }` / `{ * uint => … }`
	/// sub-maps of spec/snapshot.md §4. A plain stdlib `[UInt64: V]` cannot be
	/// used: through `Codable` its keys encode as **text** (see
	/// swift-secret-bytes `ArchiveIntegerCodingKey` — stdlib dictionary keys
	/// never conform), and the schema mandates integer keys. This coder routes
	/// every entry through a dynamic `ArchiveIntegerCodingKey`, so the values
	/// (including `SecretField` secrets) ride the archive funnel unchanged.
	///
	/// Decode reads only the integer wire keys the encoder emits. Rejecting the
	/// stray text / negative / duplicate keys a *hostile* archive could carry is
	/// the deferred §8 hostile-decode suite's job, not a round-trip obligation:
	/// this coder's output is post-AEAD-authenticated and integer-keyed by
	/// construction.
	struct IntegerKeyedMap<Value> {
		var entries: [UInt64: Value]

		init(_ entries: [UInt64: Value]) { self.entries = entries }

		/// Dynamic integer coding key. `intValue` is the map entry's key; a
		/// `stringValue`-based construction is refused so a text wire key never
		/// resolves to an entry.
		struct Key: ArchiveIntegerCodingKey {
			let value: UInt64
			init(_ value: UInt64) { self.value = value }
			var intValue: Int? { Int(exactly: value) }
			var stringValue: String { String(value) }
			init?(intValue: Int) {
				guard let value = UInt64(exactly: intValue) else { return nil }
				self.value = value
			}
			init?(stringValue: String) { nil }
		}
	}
}

extension MLS.RFC9420.IntegerKeyedMap: Encodable where Value: Encodable {
	func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: Key.self)
		for (key, value) in entries {
			// A key past Int.max would encode as a *text* key (its `intValue`
			// is nil), silently breaking the integer-keyed schema. Refuse it.
			guard Int(exactly: key) != nil else {
				throw MLS.RFC9420.SnapshotError.integerKeyUnrepresentable(key)
			}
			try container.encode(value, forKey: Key(key))
		}
	}
}

extension MLS.RFC9420.IntegerKeyedMap: Decodable where Value: Decodable {
	init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: Key.self)
		var entries: [UInt64: Value] = [:]
		for key in container.allKeys {
			entries[key.value] = try container.decode(Value.self, forKey: key)
		}
		self.entries = entries
	}
}

extension MLS.RFC9420.IntegerKeyedMap: Sendable where Value: Sendable {}
extension MLS.RFC9420.IntegerKeyedMap: Equatable where Value: Equatable {}
