import MLSCodec

extension MLS.KeySchedule {
	/// draft-ietf-mls-extensions-08 §4.4's `ComponentID` — the identifier that
	/// indexes the Exporter Tree (`SafeExportSecret(ComponentID)`).
	///
	/// draft-08 types it `uint32`, while giving the tree only 2^16 leaves;
	/// draft-09 resolves that by narrowing `ComponentID` to `uint16`. We track
	/// -08 and match the deployed fork (`type ComponentID = u32`, which keeps the
	/// u32 type and rejects ids ≥ 2^16): so this is `UInt32`, and
	/// `ExporterTree.safeExportSecret` rejects any id outside the tree's leaf
	/// range rather than truncating it onto a colliding leaf.
	///
	/// This is the draft-level *type* only. Specific component assignments are
	/// the adopter's — e.g. an application's private-use ids — declared as
	/// `static let`s on this type at the layer that owns them; none are
	/// IETF-registered, so this type defines no cases.
	public struct ComponentID: Sendable, Equatable, Hashable, RawRepresentable {
		public let rawValue: UInt32

		public init(rawValue: UInt32) {
			self.rawValue = rawValue
		}

		public init(_ rawValue: UInt32) {
			self.rawValue = rawValue
		}
	}
}

extension MLS.KeySchedule.ComponentID: ExpressibleByIntegerLiteral {
	public init(integerLiteral value: UInt32) {
		self.rawValue = value
	}
}
