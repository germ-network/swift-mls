import Foundation
import MLSCodec

extension MLS.Extensions {
	/// draft-ietf-mls-extensions-09 §4.7's `AppDataUpdateOperation`. The draft
	/// enumerates `invalid(0), update(1), remove(2), (255)`; the reserved `invalid`
	/// sentinel is dropped here — as RFC 9420's `reserved(0)` is for `PSKType` and
	/// `ResumptionPSKUsage` — so `0` and any value ≥ 3 reject uniformly as
	/// `CodecError.unknownEnumValue`. `MLSClosedEnum` is correct because `op` is a
	/// `select` discriminant whose arms carry no length prefix of their own: an
	/// unknown op leaves the rest of the struct unparseable, so there is nothing to
	/// skip to.
	public enum AppDataUpdateOperation: UInt8, MLSClosedEnum {
		case update = 1
		case remove = 2
	}

	/// draft-ietf-mls-extensions-09 §4.7 (text identical in -10; -08 §4.7 differs
	/// only in the `uint32` ComponentID width — see `ComponentIDWireWidth`):
	/// ```
	/// struct { ComponentID component_id; AppDataUpdateOperation op;
	///          select (AppDataUpdate.op) {
	///            case update: opaque update<V>;
	///            case remove: struct{};
	///          }; } AppDataUpdate;
	/// ```
	/// A generic Safe-Extensions envelope: it names a component and either sets
	/// (`update`) or clears (`remove`) that component's application state. This is
	/// the envelope ONLY. The §4.7 processing that mutates the `app_data_dictionary`
	/// GroupContext extension, and any component-specific `update` payload (an APQ
	/// combiner's, say), belong above the substrate — to a profile or the adopter —
	/// not here.
	///
	/// `component_id` rides the ambient `ComponentID.componentIDWireWidth` (`uint16`
	/// by default; `uint32` for a fork/-08 peer). The `MLSCodable` conformance reads
	/// that ambient; `encode(to:componentIDWidth:)` / `init(from:componentIDWidth:)`
	/// take the width explicitly.
	public struct AppDataUpdate: Sendable, Equatable {
		/// `select (op)` — the two valid arms. Storing only these makes an
		/// op/payload disagreement unconstructable, and keeps
		/// `AppDataUpdateOperation`'s dropped `invalid` value unreachable here by
		/// construction.
		public enum Operation: Sendable, Equatable {
			case update(Data)
			case remove
		}

		public let componentID: ComponentID
		public let operation: Operation

		public init(componentID: ComponentID, operation: Operation) {
			self.componentID = componentID
			self.operation = operation
		}

		/// The `app_data_update` proposal type — draft-09 §7.2.1, "Value: 0x0008
		/// (suggested)", Path Required N. The substrate holds only the number; the
		/// extensible `ProposalType` enum lives in a profile.
		public static let proposalType: UInt16 = 0x0008

		/// The `op` discriminant for `operation`.
		public var op: AppDataUpdateOperation {
			switch operation {
			case .update: .update
			case .remove: .remove
			}
		}
	}
}

extension MLS.Extensions.AppDataUpdate: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try encode(
			to: &writer,
			componentIDWidth: MLS.Extensions.ComponentID.componentIDWireWidth)
	}

	public init(from reader: inout MLS.Reader) throws {
		try self.init(
			from: &reader,
			componentIDWidth: MLS.Extensions.ComponentID.componentIDWireWidth)
	}

	/// `component_id ‖ op ‖ (update: opaque update<V> | remove: ∅)`, with
	/// `component_id` at an explicit `width`.
	public func encode(
		to writer: inout MLS.Writer,
		componentIDWidth width: MLS.Extensions.ComponentIDWireWidth
	) throws {
		componentID.encode(to: &writer, width: width)
		try writer.encode(op)
		switch operation {
		case .update(let data): try writer.writeOpaque(data)
		case .remove: break
		}
	}

	public init(
		from reader: inout MLS.Reader,
		componentIDWidth width: MLS.Extensions.ComponentIDWireWidth
	) throws {
		let componentID = try MLS.Extensions.ComponentID(from: &reader, width: width)
		let operation: Operation
		switch try MLS.Extensions.AppDataUpdateOperation(from: &reader) {
		case .update: operation = .update(Data(try reader.readOpaque()))
		case .remove: operation = .remove
		}
		self.init(componentID: componentID, operation: operation)
	}
}

extension MLS.Extensions.AppDataUpdate {
	public enum ValidityError: Error, Sendable, Equatable {
		/// §4.7: "A proposal list is invalid if it includes multiple AppDataUpdate
		/// proposals that remove state for the same component_id."
		case multipleRemoves(MLS.Extensions.ComponentID)
		/// §4.7: "... or proposals that both update and remove state for the same
		/// component_id."
		case updateAndRemove(MLS.Extensions.ComponentID)
	}

	/// draft-ietf-mls-extensions-09 §4.7's list-level validity rule: "for a given
	/// component_id, a proposal list is valid only if it contains (a) a single
	/// remove operation or (b) one or more update operations." Pure and stateless.
	/// The other two §4.7 clauses — a `component_id` unknown to the application,
	/// and removing state that is not present — depend on the `app_data_dictionary`
	/// state a profile owns, and are deliberately NOT checked here.
	public static func validateProposalList(
		_ updates: some Sequence<MLS.Extensions.AppDataUpdate>
	) throws {
		var removed: Set<MLS.Extensions.ComponentID> = []
		var updated: Set<MLS.Extensions.ComponentID> = []
		for update in updates {
			switch update.operation {
			case .remove:
				guard removed.insert(update.componentID).inserted else {
					throw ValidityError.multipleRemoves(update.componentID)
				}
			case .update:
				updated.insert(update.componentID)
			}
		}
		for id in removed where updated.contains(id) {
			throw ValidityError.updateAndRemove(id)
		}
	}
}
