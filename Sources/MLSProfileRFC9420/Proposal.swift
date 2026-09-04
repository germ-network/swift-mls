import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSTreeMath

extension MLS.RFC9420 {
	/// `enum { reserved(0), external(1), resumption(2), (255) } PSKType;` —
	/// draft-ietf-mls-extensions-08 §4.5 adds `application(3)` for the PSKs a
	/// Safe Extensions component derives (an Exporter Tree leaf → `psk_id`/`psk`).
	public enum PSKType: UInt8, MLSClosedEnum {
		case external = 1
		case resumption = 2
		case application = 3
	}

	/// `enum { reserved(0), application(1), reinit(2), branch(3), (255) }
	/// ResumptionPSKUsage;`
	public enum ResumptionPSKUsage: UInt8, MLSClosedEnum {
		case application = 1
		case reinit = 2
		case branch = 3
	}

	/// RFC 9420 has no separate `ResumptionPSK` struct — §8.4 inlines these
	/// three fields directly in `PreSharedKeyID`'s `resumption` select arm
	/// (`ResumptionPSKUsage usage; opaque psk_group_id<V>; uint64
	/// psk_epoch;`). Grouped into a type here purely for a nameable Swift
	/// case payload; the wire bytes are identical either way.
	public struct ResumptionPSK: Sendable, Equatable, MLSCodable {
		public var usage: ResumptionPSKUsage
		public var groupID: Data
		public var epoch: UInt64

		public init(usage: ResumptionPSKUsage, groupID: Data, epoch: UInt64) {
			self.usage = usage
			self.groupID = groupID
			self.epoch = epoch
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encode(usage)
			try writer.writeOpaque(groupID)
			writer.writeUInt64(epoch)
		}

		public init(from reader: inout MLS.Reader) throws {
			usage = try ResumptionPSKUsage(from: &reader)
			groupID = Data(try reader.readOpaque())
			epoch = try reader.readUInt64()
		}
	}

	/// `struct { PSKType psktype; select (PreSharedKeyID.psktype) { case
	/// external: opaque psk_id<V>; case resumption: ResumptionPSKUsage
	/// usage; opaque psk_group_id<V>; uint64 psk_epoch; }; opaque
	/// psk_nonce<V>; } PreSharedKeyID;` — `psk_nonce` is a sibling of
	/// `psktype`, appended after the select resolves, not nested inside
	/// either arm.
	public enum PreSharedKeyIdentifier: Sendable, Equatable {
		case external(pskID: Data, nonce: Data)
		case resumption(ResumptionPSK, nonce: Data)
		/// draft-ietf-mls-extensions-08 §4.5's application PSK: the `application`
		/// select arm is `ComponentID component_id; opaque psk_id<V>;`, so on the
		/// wire this is `component_id` (a §4.1 `uint32`) followed by `psk_id`. Like
		/// the other arms, `psk_nonce` follows the select. Domain-separates a
		/// component's PSKs from the core protocol's and from other components'.
		case application(componentID: MLS.KeySchedule.ComponentID, pskID: Data, nonce: Data)
	}

	/// `struct { opaque kem_output<V>; } ExternalInit;`
	public struct ExternalInitProposal: Sendable, Equatable, MLSCodable {
		public var kemOutput: Data
		public init(kemOutput: Data) { self.kemOutput = kemOutput }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(kemOutput)
		}
		public init(from reader: inout MLS.Reader) throws {
			kemOutput = Data(try reader.readOpaque())
		}
	}

	/// `struct { opaque group_id<V>; ProtocolVersion version; CipherSuite
	/// cipher_suite; Extension extensions<V>; } ReInit;`
	public struct ReInitProposal: Sendable, Equatable, MLSCodable {
		public var groupID: Data
		public var version: MLS.ProtocolVersion
		public var cipherSuite: MLS.CipherSuite
		public var extensions: [Extension]

		public init(
			groupID: Data, version: MLS.ProtocolVersion, cipherSuite: MLS.CipherSuite,
			extensions: [Extension]
		) {
			self.groupID = groupID
			self.version = version
			self.cipherSuite = cipherSuite
			self.extensions = extensions
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(groupID)
			try writer.encode(version)
			try writer.encode(cipherSuite)
			try writer.encodeVector(extensions)
		}

		public init(from reader: inout MLS.Reader) throws {
			groupID = Data(try reader.readOpaque())
			version = try MLS.ProtocolVersion(from: &reader)
			cipherSuite = try MLS.CipherSuite(from: &reader)
			extensions = try reader.decodeVector()
		}
	}

	/// RFC 9420 §12.1's seven proposal bodies. `Proposal`'s own encoding
	/// writes the `ProposalType` tag then the body directly — no extra
	/// opaque wrapping, so an unrecognized proposal type is not skippable
	/// purely from the wire (same caveat as `Credential`). This enum has
	/// no `.other` fallback case: mls-rs's own `CustomProposal` convention
	/// decodes an unrecognized type's body by *assuming* it's `opaque<V>`
	/// — a peer choice, not something the wire format guarantees, and one
	/// that would silently mis-decode a foreign proposal type whose body
	/// isn't shaped that way. We don't inherit that assumption: an
	/// unrecognized proposal type is a hard decode error here instead.
	public enum Proposal: Sendable, Equatable {
		case add(KeyPackage)
		case update(LeafNode)
		case remove(MLS.LeafIndex)
		case preSharedKey(PreSharedKeyIdentifier)
		case reInit(ReInitProposal)
		case externalInit(ExternalInitProposal)
		case groupContextExtensions([Extension])
	}

	/// `struct { ProposalOrRefType type; select (ProposalOrRef.type) {
	/// case proposal: Proposal proposal; case reference: ProposalRef
	/// reference; }; } ProposalOrRef;`, where `ProposalOrRefType` is
	/// `enum { reserved(0), proposal(1), reference(2), (255) }` — hence
	/// the hardcoded tag values 1/2 below.
	public enum ProposalOrRef: Sendable, Equatable {
		case proposal(Proposal)
		case reference(MLS.HashReference)
	}
}

extension MLS.RFC9420.PreSharedKeyIdentifier {
	/// The `psk_nonce` common to every arm — RFC 9420 §8.4 requires it "a fresh
	/// random value of length KDF.Nh" (§12.1.4 validates the length on receipt).
	public var nonce: Data {
		switch self {
		case .external(_, let nonce): nonce
		case .resumption(_, let nonce): nonce
		case .application(_, _, let nonce): nonce
		}
	}

	/// The `psktype` + type-specific select fields, *without* the trailing
	/// `psk_nonce` — the identity `encode(to:)` prepends before the nonce, and the
	/// key an application PSK's value is stored under (see `applicationStorageID`).
	func encodeIdentity(to writer: inout MLS.Writer) throws {
		switch self {
		case .external(let pskID, _):
			try writer.encode(MLS.RFC9420.PSKType.external)
			try writer.writeOpaque(pskID)
		case .resumption(let resumption, _):
			try writer.encode(MLS.RFC9420.PSKType.resumption)
			try writer.encode(resumption)
		case .application(let componentID, let pskID, _):
			try writer.encode(MLS.RFC9420.PSKType.application)
			writer.writeUInt32(componentID.rawValue)
			try writer.writeOpaque(pskID)
		}
	}

	/// The key an application PSK's value is looked up under — the encoded
	/// identity *without* the `psk_nonce`, `0x03 ‖ component_id ‖ psk_id<V>`
	/// (draft-ietf-mls-extensions-08 §4.5; matches the deployed fork's
	/// `storage_id`). `nil` for non-application ids. Shares `encodeIdentity`, so
	/// it cannot drift from the wire encoding.
	public func applicationStorageID() throws -> Data? {
		guard case .application = self else { return nil }
		var writer = MLS.Writer()
		try encodeIdentity(to: &writer)
		return Data(writer.bytes)
	}
}

extension MLS.RFC9420.PreSharedKeyIdentifier: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try encodeIdentity(to: &writer)
		try writer.writeOpaque(nonce)
	}

	public init(from reader: inout MLS.Reader) throws {
		switch try MLS.RFC9420.PSKType(from: &reader) {
		case .external:
			let pskID = Data(try reader.readOpaque())
			self = .external(pskID: pskID, nonce: Data(try reader.readOpaque()))
		case .resumption:
			let resumption = try MLS.RFC9420.ResumptionPSK(from: &reader)
			self = .resumption(resumption, nonce: Data(try reader.readOpaque()))
		case .application:
			let componentID = MLS.KeySchedule.ComponentID(
				rawValue: try reader.readUInt32())
			let pskID = Data(try reader.readOpaque())
			self = .application(
				componentID: componentID, pskID: pskID,
				nonce: Data(try reader.readOpaque()))
		}
	}
}

extension MLS.RFC9420.Proposal {
	var type: MLS.RFC9420.ProposalType {
		switch self {
		case .add: .init(.add)
		case .update: .init(.update)
		case .remove: .init(.remove)
		case .preSharedKey: .init(.preSharedKey)
		case .reInit: .init(.reInit)
		case .externalInit: .init(.externalInit)
		case .groupContextExtensions: .init(.groupContextExtensions)
		}
	}
}

extension MLS.RFC9420.Proposal: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		try writer.encode(type)
		switch self {
		case .add(let keyPackage): try writer.encode(keyPackage)
		case .update(let leafNode): try writer.encode(leafNode)
		case .remove(let leafIndex): try writer.encode(leafIndex)
		case .preSharedKey(let psk): try writer.encode(psk)
		case .reInit(let reInit): try writer.encode(reInit)
		case .externalInit(let externalInit): try writer.encode(externalInit)
		case .groupContextExtensions(let extensions): try writer.encodeVector(extensions)
		}
	}
}

extension MLS.RFC9420.Proposal: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		let type = try MLS.RFC9420.ProposalType(from: &reader)
		switch type {
		case .known(.add): self = .add(try MLS.RFC9420.KeyPackage(from: &reader))
		case .known(.update): self = .update(try MLS.RFC9420.LeafNode(from: &reader))
		case .known(.remove): self = .remove(try MLS.LeafIndex(from: &reader))
		case .known(.preSharedKey):
			self = .preSharedKey(try MLS.RFC9420.PreSharedKeyIdentifier(from: &reader))
		case .known(.reInit): self = .reInit(try MLS.RFC9420.ReInitProposal(from: &reader))
		case .known(.externalInit):
			self = .externalInit(try MLS.RFC9420.ExternalInitProposal(from: &reader))
		case .known(.groupContextExtensions):
			self = .groupContextExtensions(try reader.decodeVector())
		case .unknown(let raw): throw MLS.RFC9420.WireError.unknownProposalType(raw)
		}
	}
}

extension MLS.RFC9420.ProposalOrRef: MLSEncodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .proposal(let proposal):
			writer.writeUInt8(1)
			try writer.encode(proposal)
		case .reference(let ref):
			writer.writeUInt8(2)
			try writer.encode(ref)
		}
	}
}

extension MLS.RFC9420.ProposalOrRef: MLSDecodable {
	public init(from reader: inout MLS.Reader) throws {
		switch try reader.readUInt8() {
		case 1: self = .proposal(try MLS.RFC9420.Proposal(from: &reader))
		case 2: self = .reference(try MLS.HashReference(from: &reader))
		case let other: throw MLS.RFC9420.WireError.unknownProposalOrRefType(other)
		}
	}
}
