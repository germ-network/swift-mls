import MLSCodec

extension MLS.Extensions {
	/// draft-ietf-mls-extensions-09 §4.1's `ComponentID` — "a two-byte value that
	/// uniquely identifies a component"; `uint16 ComponentID`. The Exporter Tree
	/// (§4.4) indexes its 2^16 leaves by one.
	///
	/// draft-08 typed it `uint32` while giving the tree only 2^16 leaves; -09
	/// narrows it to `uint16`, which we track: a `ComponentID` is exactly the 16
	/// bits of the tree's leaf range, so every value names a valid leaf and no
	/// runtime range check is needed. The deployed fork still encodes `u32` on the
	/// wire (it tracks -08); reconciling that is a **downstream** concern — swift-
	/// mls stays -09-clean and never carries the u32 form.
	///
	/// This is the draft-level *type* only. §7.5 registers component types
	/// (`app_components`, `safe_aad`, `content_media_types`,
	/// `last_resort_key_package`, `app_ack`) but swift-mls implements none of them,
	/// and an application's own ids are the adopter's — declared as `static let`s
	/// at the layer that owns them — so this type defines no cases.
	public struct ComponentID: Sendable, Equatable, Hashable, RawRepresentable {
		public let rawValue: UInt16

		public init(rawValue: UInt16) {
			self.rawValue = rawValue
		}

		public init(_ rawValue: UInt16) {
			self.rawValue = rawValue
		}
	}
}

extension MLS.Extensions.ComponentID: ExpressibleByIntegerLiteral {
	public init(integerLiteral value: UInt16) {
		self.rawValue = value
	}
}
