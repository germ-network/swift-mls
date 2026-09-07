import Foundation
import MLSCodec
import Testing

@testable import MLSExtensions

/// draft-ietf-mls-extensions-09 §4.7's `AppDataUpdate` envelope: the wire shape at
/// both ComponentID widths, and the §4.7 list-validity rule. Wire bytes are
/// cross-checked against the two reference implementations — OpenMLS
/// (`AppDataUpdateProposal`, `component_id: u16`) and the deployed TwoMLSPQ apq
/// crate (`AppDataUpdateWire`, `component_id: u32`) — which agree on
/// `component_id ‖ op(u8) ‖ (update: opaque<V> | remove: ∅)`.
@Suite("AppDataUpdate envelope (draft-ietf-mls-extensions §4.7)")
struct AppDataUpdateTests {
	typealias AppDataUpdate = MLS.Extensions.AppDataUpdate
	typealias ComponentID = MLS.Extensions.ComponentID

	private func encoded(
		_ update: AppDataUpdate, width: MLS.Extensions.ComponentIDWireWidth
	) throws -> [UInt8] {
		var writer = MLS.Writer()
		try update.encode(to: &writer, componentIDWidth: width)
		return writer.bytes
	}

	private func decoded(
		_ bytes: [UInt8], width: MLS.Extensions.ComponentIDWireWidth
	) throws -> AppDataUpdate {
		var reader = MLS.Reader(bytes)
		let update = try AppDataUpdate(from: &reader, componentIDWidth: width)
		try reader.finish()
		return update
	}

	@Test("proposal type is 0x0008 (§7.2.1)")
	func proposalTypeConstant() {
		#expect(AppDataUpdate.proposalType == 0x0008)
	}

	// MARK: exact wire bytes vs the reference implementations

	/// `update`, uint16 id — matches OpenMLS `AppDataUpdateProposal.update`:
	/// `component_id(2) ‖ op=1 ‖ opaque update<V>`.
	@Test("uint16 update encodes component_id ‖ 0x01 ‖ opaque<V>")
	func uint16UpdateBytes() throws {
		let update = AppDataUpdate(
			componentID: 0x0102, operation: .update(Data([0xAA, 0xBB])))
		#expect(
			try encoded(update, width: .uint16) == [0x01, 0x02, 0x01, 0x02, 0xAA, 0xBB])
	}

	/// `remove`, uint16 id — the `struct{}` arm adds zero trailing bytes:
	/// `component_id(2) ‖ op=2`.
	@Test("uint16 remove encodes component_id ‖ 0x02 and nothing more")
	func uint16RemoveBytes() throws {
		let update = AppDataUpdate(componentID: 0x0102, operation: .remove)
		#expect(try encoded(update, width: .uint16) == [0x01, 0x02, 0x02])
	}

	/// `update`, uint32 id — matches the deployed apq `AppDataUpdateWire`:
	/// `component_id(4) ‖ op=1 ‖ opaque update<V>`.
	@Test("uint32 update widens component_id to four bytes")
	func uint32UpdateBytes() throws {
		let update = AppDataUpdate(
			componentID: 0x0102, operation: .update(Data([0xAA, 0xBB])))
		#expect(
			try encoded(update, width: .uint32)
				== [0x00, 0x00, 0x01, 0x02, 0x01, 0x02, 0xAA, 0xBB])
	}

	@Test("uint32 remove widens component_id to four bytes")
	func uint32RemoveBytes() throws {
		let update = AppDataUpdate(componentID: 0x0102, operation: .remove)
		#expect(try encoded(update, width: .uint32) == [0x00, 0x00, 0x01, 0x02, 0x02])
	}

	// MARK: round-trips at both widths

	@Test("round-trips update and remove at both widths, explicit")
	func roundTripBothWidthsExplicit() throws {
		for width in [MLS.Extensions.ComponentIDWireWidth.uint16, .uint32] {
			for op in [AppDataUpdate.Operation.update(Data([1, 2, 3])), .remove] {
				let update = AppDataUpdate(componentID: 0xBEEF, operation: op)
				#expect(
					try decoded(encoded(update, width: width), width: width)
						== update)
			}
		}
	}

	/// The ambient `ComponentID.componentIDWireWidth` drives the `MLSCodable`
	/// conformance. Default is uint16 (a two-byte id); a `.uint32` scope widens it,
	/// and the two encodings differ by exactly the two extra leading zero bytes.
	@Test("MLSCodable follows the ambient width; default is uint16")
	func ambientWidthDefaultsUInt16() throws {
		let update = AppDataUpdate(
			componentID: 0x0102, operation: .update(Data([0xAA, 0xBB])))

		let defaultBytes = try update.mlsEncoded()
		#expect(Array(defaultBytes) == [0x01, 0x02, 0x01, 0x02, 0xAA, 0xBB])
		#expect(try AppDataUpdate(mlsEncoded: defaultBytes) == update)

		try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
			let wideBytes = try update.mlsEncoded()
			#expect(
				Array(wideBytes) == [
					0x00, 0x00, 0x01, 0x02, 0x01, 0x02, 0xAA, 0xBB,
				])
			#expect(try AppDataUpdate(mlsEncoded: wideBytes) == update)
		}
	}

	/// A `uint32`-form `component_id ≥ 2^16` has no Exporter Tree leaf and cannot
	/// fit the -09 `uint16`, so decode rejects it rather than truncating.
	@Test("a uint32 component_id at or above 2^16 is rejected on decode")
	func uint32ComponentIDOverflowRejected() throws {
		// component_id 0x00010000 (= 2^16), op=2 (remove).
		#expect(throws: ComponentID.WireError.overflowsUInt16(0x0001_0000)) {
			try decoded([0x00, 0x01, 0x00, 0x00, 0x02], width: .uint32)
		}
	}

	// MARK: operation discriminant

	/// The reserved `invalid(0)` and any value ≥ 3 are not modeled cases, so both
	/// reject uniformly as `CodecError.unknownEnumValue` — one rejection path.
	@Test("op 0 (invalid) and op ≥ 3 both reject as unknownEnumValue")
	func invalidAndUnknownOperationsRejected() throws {
		#expect(throws: MLS.CodecError.unknownEnumValue(0)) {
			try decoded([0x01, 0x02, 0x00], width: .uint16)
		}
		#expect(throws: MLS.CodecError.unknownEnumValue(3)) {
			try decoded([0x01, 0x02, 0x03], width: .uint16)
		}
	}

	@Test("op accessor reflects the stored operation")
	func opAccessor() {
		#expect(
			AppDataUpdate(componentID: 1, operation: .update(Data())).op == .update)
		#expect(AppDataUpdate(componentID: 1, operation: .remove).op == .remove)
	}

	// MARK: §4.7 list-validity rule

	@Test("valid lists: single remove, one update, many updates, distinct ids")
	func validProposalLists() throws {
		try AppDataUpdate.validateProposalList([])
		try AppDataUpdate.validateProposalList([
			AppDataUpdate(componentID: 7, operation: .remove)
		])
		try AppDataUpdate.validateProposalList([
			AppDataUpdate(componentID: 7, operation: .update(Data([1]))),
			AppDataUpdate(componentID: 7, operation: .update(Data([2]))),
		])
		// A remove of one component and updates of another are independent.
		try AppDataUpdate.validateProposalList([
			AppDataUpdate(componentID: 7, operation: .remove),
			AppDataUpdate(componentID: 8, operation: .update(Data([1]))),
			AppDataUpdate(componentID: 8, operation: .update(Data([2]))),
		])
	}

	@Test("two removes for one component_id are rejected")
	func multipleRemovesRejected() {
		#expect(throws: AppDataUpdate.ValidityError.multipleRemoves(7)) {
			try AppDataUpdate.validateProposalList([
				AppDataUpdate(componentID: 7, operation: .remove),
				AppDataUpdate(componentID: 7, operation: .remove),
			])
		}
	}

	@Test("update and remove for one component_id are rejected")
	func updateAndRemoveRejected() {
		#expect(throws: AppDataUpdate.ValidityError.updateAndRemove(7)) {
			try AppDataUpdate.validateProposalList([
				AppDataUpdate(componentID: 7, operation: .update(Data([1]))),
				AppDataUpdate(componentID: 7, operation: .remove),
			])
		}
	}
}
