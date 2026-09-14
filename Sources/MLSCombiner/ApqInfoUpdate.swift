import Foundation
import MLSCodec
import MLSExtensions
import MLSProfileRFC9420

extension MLS.Combiner {
	/// The combiner's `AppDataUpdate` payload (draft-ietf-mls-combiner-02 §6.1): the
	/// **absolute** epochs of both halves after a FULL commit.
	/// ```
	/// struct { uint64 t_epoch; uint64 pq_epoch; } ApqInfoUpdate
	/// ```
	/// Receivers verify these against each half's actual post-commit epoch (absolute,
	/// so any number of intervening PARTIALs reconciles with no extra machinery).
	///
	/// **Why this shape, not the draft's.** draft-02 §6.1 does not define an
	/// `AppDataUpdate` proposal struct (it defers to draft-ietf-mls-extensions'
	/// `AppDataUpdate`, code point `0x0008` — the `MLSExtensions` dependency), and its
	/// own `APQInfoUpdate` enum as published is malformed (a duplicate enum value plus
	/// a `select` on an undefined case). So §6.1 is not directly implementable; this
	/// two-absolute-epochs payload is the deployed resolution and the interop target,
	/// carried in the extensions `AppDataUpdate`'s `update<V>` field. A compat choice
	/// this module owns.
	public struct ApqInfoUpdate: Sendable, Equatable, MLSCodable {
		public var tEpoch: UInt64
		public var pqEpoch: UInt64

		public init(tEpoch: UInt64, pqEpoch: UInt64) {
			self.tEpoch = tEpoch
			self.pqEpoch = pqEpoch
		}

		public func encode(to writer: inout MLS.Writer) throws {
			writer.writeUInt64(tEpoch)
			writer.writeUInt64(pqEpoch)
		}

		public init(from reader: inout MLS.Reader) throws {
			tEpoch = try reader.readUInt64()
			pqEpoch = try reader.readUInt64()
		}
	}
}

extension MLS.Combiner.ApqInfoUpdate {
	/// Wrap as the extensions `AppDataUpdate(op = update)` envelope for the combiner
	/// component — the value that rides the profile's `.appDataUpdate` proposal arm.
	/// The `component_id` is encoded at the ambient `ComponentID.componentIDWireWidth`
	/// when the enclosing proposal is serialized, so build/commit under the
	/// [`Codepoints`] wire-width scope for deployed interop.
	public func appDataUpdate(
		componentID: MLS.Extensions.ComponentID
	) throws -> MLS.Extensions.AppDataUpdate {
		MLS.Extensions.AppDataUpdate(
			componentID: componentID, operation: .update(try mlsEncoded()))
	}

	/// The `.appDataUpdate` proposal carrying this attestation for the combiner
	/// component — dropped into a FULL commit's proposal list on each half.
	public func proposal(
		componentID: MLS.Extensions.ComponentID
	) throws -> MLS.RFC9420.Proposal {
		.appDataUpdate(try appDataUpdate(componentID: componentID))
	}

	/// Strictly decode a combiner attestation out of an extensions `AppDataUpdate`:
	/// the component id must be the combiner's, `op` must be `update`, and the
	/// `update<V>` payload must decode to an `ApqInfoUpdate` with no trailing bytes.
	/// A well-typed but wrong-component / wrong-op / undecodable `AppDataUpdate` is an
	/// attack or a bug, never ignorable — it throws rather than returning `nil`.
	public static func decode(
		from appDataUpdate: MLS.Extensions.AppDataUpdate,
		componentID: MLS.Extensions.ComponentID
	) throws -> MLS.Combiner.ApqInfoUpdate {
		guard appDataUpdate.componentID == componentID,
			case .update(let payload) = appDataUpdate.operation
		else {
			throw MLS.Combiner.Error.attestationMismatch
		}
		var reader = MLS.Reader(payload)
		let update = try MLS.Combiner.ApqInfoUpdate(from: &reader)
		do {
			try reader.finish()
		} catch {
			throw MLS.Combiner.Error.attestationMismatch
		}
		return update
	}

	/// The single combiner attestation carried by a processed commit's effects, if
	/// any. `nil` when the commit carried none (a PARTIAL, or a non-attesting commit);
	/// throws `attestationMismatch` if it carried more than one `AppDataUpdate` (the
	/// draft caps it at one) or a malformed / wrong-component one. Accepts the
	/// attestation from either the typed `.appDataUpdate` effect or, when a receiver
	/// has opted `AppDataUpdate`'s proposal type into `customProposalTypes`, the
	/// wrapped `.customProposal(type: .appDataUpdate, body:)` effect it sees instead.
	public static func extract(
		from effects: MLS.RFC9420.CommitEffects,
		componentID: MLS.Extensions.ComponentID
	) throws -> MLS.Combiner.ApqInfoUpdate? {
		var found: MLS.Combiner.ApqInfoUpdate?
		for event in effects.events {
			let appDataUpdate: MLS.Extensions.AppDataUpdate
			switch event {
			case .appDataUpdate(let value):
				appDataUpdate = value
			case .customProposal(let type, let body)
			where type == MLS.RFC9420.ProposalType(.appDataUpdate):
				var reader = MLS.Reader(body)
				let value = try MLS.Extensions.AppDataUpdate(from: &reader)
				do {
					try reader.finish()
				} catch {
					throw MLS.Combiner.Error.attestationMismatch
				}
				appDataUpdate = value
			default:
				continue
			}
			guard found == nil else { throw MLS.Combiner.Error.attestationMismatch }
			found = try decode(from: appDataUpdate, componentID: componentID)
		}
		return found
	}
}

extension MLS.Combiner {
	/// Verify a FULL commit's epoch attestation (draft §6.1): each half's commit
	/// carries exactly one combiner `AppDataUpdate`, the two copies agree, and each
	/// attests the actual post-commit epochs of both halves. Pass the two halves'
	/// applied `CommitEffects` and the halves' observed new epochs; returns the
	/// verified `ApqInfoUpdate`.
	///
	/// The attestation is absolute, so it reconciles against the observed epochs
	/// directly regardless of intervening PARTIALs. This is the draft-generic
	/// attestation check; the 2-party proposal whitelist and the FULL/PARTIAL commit
	/// *shape* policy live downstream.
	public static func verifyFullCommitAttestation(
		classicalEffects: MLS.RFC9420.CommitEffects,
		pqEffects: MLS.RFC9420.CommitEffects,
		classicalEpoch: UInt64,
		pqEpoch: UInt64,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.Combiner.ApqInfoUpdate {
		guard
			let classical = try ApqInfoUpdate.extract(
				from: classicalEffects, componentID: codepoints.apqComponentID),
			let pq = try ApqInfoUpdate.extract(
				from: pqEffects, componentID: codepoints.apqComponentID)
		else {
			throw MLS.Combiner.Error.attestationMismatch
		}
		// Both halves attest the same pair, and it is the actual post-commit epochs.
		guard classical == pq,
			classical.tEpoch == classicalEpoch,
			classical.pqEpoch == pqEpoch
		else {
			throw MLS.Combiner.Error.attestationMismatch
		}
		return classical
	}
}
