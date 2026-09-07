import MLSCodec
import MLSExtensions
import MLSProfileRFC9420

extension MLS.Combiner {
	/// The combiner's code points, parameterized so a future IANA assignment is a
	/// one-line change, and defaulting to the deployed TwoMLSPQ values so the
	/// module is wire-compatible with that deployment with no configuration.
	///
	/// draft-ietf-mls-combiner-02 leaves these TODO/IANA (§6 marks the `APQInfo`
	/// extension type symbolic and the `apq_psk` component id `XXX`); TwoMLSPQ
	/// ships private-range values. This module tracks the newest revision and owns
	/// its own compat, so it selects the deployed values as defaults rather than
	/// baking them in.
	///
	/// The `AppDataUpdate` proposal type (`0x0008`) is NOT here: it is fixed by
	/// draft-ietf-mls-extensions §7.2.1 (`MLS.Extensions.AppDataUpdate.proposalType`),
	/// not a combiner choice. The `apq_psk` derive labels (`"psk_id"`/`"psk"`,
	/// draft §6.2 Figure 3) and the exporter-tree root label (`"application_export"`,
	/// the `MLSExtensions` substrate) are likewise fixed by the reused primitives and
	/// not parameterized.
	public struct Codepoints: Sendable, Equatable {
		/// The `APQInfo` GroupContext extension type. Deployed: `0xF0A1` (RFC 9420
		/// §17.3 private-use range).
		public var apqInfoExtensionType: MLS.RFC9420.ExtensionType

		/// The `apq_psk` application-PSK component id. Deployed: `0xFF01`. Must fit
		/// the 2^16-leaf Exporter Tree (`MLS.Extensions.ComponentID` is a `uint16`),
		/// which every value does.
		public var apqComponentID: MLS.Extensions.ComponentID

		/// The on-wire width of every `ComponentID` the combiner encodes — the
		/// `apq_psk` `PreSharedKeyID`'s and the `AppDataUpdate` proposal's alike, since
		/// both encode the same `ComponentID` type and a peer speaks one width for a
		/// whole session. Deployed: `.uint32` (the deployed fork tracks
		/// draft-ietf-mls-extensions-08). A draft-09/-10 peer selects `.uint16`. The
		/// combiner scopes its operations under this via
		/// `MLS.Extensions.ComponentID.$componentIDWireWidth`.
		public var componentIDWireWidth: MLS.Extensions.ComponentIDWireWidth

		public init(
			apqInfoExtensionType: MLS.RFC9420.ExtensionType,
			apqComponentID: MLS.Extensions.ComponentID,
			componentIDWireWidth: MLS.Extensions.ComponentIDWireWidth
		) {
			self.apqInfoExtensionType = apqInfoExtensionType
			self.apqComponentID = apqComponentID
			self.componentIDWireWidth = componentIDWireWidth
		}

		/// The deployed TwoMLSPQ values: `APQInfo` = `0xF0A1`, `apq_psk` component id
		/// = `0xFF01`, component-id wire width = `uint32` (draft-08). Wire-compatible
		/// with the deployed combiner with no configuration.
		public static let deployed = Codepoints(
			apqInfoExtensionType: MLS.RFC9420.ExtensionType(rawValue: 0xF0A1),
			apqComponentID: MLS.Extensions.ComponentID(rawValue: 0xFF01),
			componentIDWireWidth: .uint32)

		/// Run `body` with this configuration's component-id wire width installed as
		/// the ambient, so every `ComponentID` encode/decode inside — the wire bytes
		/// AND the `PSKLabel` binding they feed — agrees on the width.
		func withWireWidth<T>(_ body: () throws -> T) rethrows -> T {
			try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(
				componentIDWireWidth, operation: body)
		}
	}
}
