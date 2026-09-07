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

extension MLS.Extensions {
	/// The on-wire width of a `ComponentID`. draft-09/-10 §4.1 makes it a
	/// `uint16`, which swift-mls emits by default; the deployed fork and draft-08
	/// §4.1 encode it as a `uint32`. The two widths are indistinguishable from the
	/// bytes, so a peer speaks one width for a whole session — hence an ambient
	/// setting (`ComponentID.componentIDWireWidth`), not a per-message flag.
	public enum ComponentIDWireWidth: Sendable {
		case uint16
		case uint32
	}
}

extension MLS.Extensions.ComponentID {
	public enum WireError: Error, Sendable, Equatable {
		/// A `uint32`-form `component_id ≥ 2^16` — it has no Exporter Tree leaf and
		/// cannot fit the -09 `uint16 ComponentID`, so decode rejects it rather
		/// than truncating.
		case overflowsUInt16(UInt32)
	}

	/// The single "which width does this session speak" ambient, shared by every
	/// `ComponentID` that crosses the wire — the application-PSK arm (§4.5) and the
	/// `AppDataUpdate` proposal (§4.7) alike, since both encode the *same*
	/// `ComponentID` type and a peer tracks one draft revision. Defaults to the -09
	/// `uint16`; scope `$componentIDWireWidth.withValue(.uint32) { … }` around a
	/// whole operation (encode, the peer's decode, and any label that binds the
	/// encoded id) to interoperate with a fork/-08 peer.
	@TaskLocal
	public static var componentIDWireWidth: MLS.Extensions.ComponentIDWireWidth = .uint16

	/// Encodes the id at `width`, big-endian (RFC 9420 §2.1).
	public func encode(
		to writer: inout MLS.Writer, width: MLS.Extensions.ComponentIDWireWidth
	) {
		switch width {
		case .uint16: writer.writeUInt16(rawValue)
		case .uint32: writer.writeUInt32(UInt32(rawValue))
		}
	}

	/// Decodes an id at `width`. A `uint32` form ≥ 2^16 has no leaf and cannot fit
	/// the -09 `uint16`, so it throws `WireError.overflowsUInt16` rather than
	/// truncating.
	public init(
		from reader: inout MLS.Reader, width: MLS.Extensions.ComponentIDWireWidth
	) throws {
		switch width {
		case .uint16:
			self.init(rawValue: try reader.readUInt16())
		case .uint32:
			let wide = try reader.readUInt32()
			guard let narrow = UInt16(exactly: wide) else {
				throw WireError.overflowsUInt16(wide)
			}
			self.init(rawValue: narrow)
		}
	}
}
