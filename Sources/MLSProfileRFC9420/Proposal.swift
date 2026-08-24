import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420 {
	/// `enum { reserved(0), external(1), resumption(2), (255) } PSKType;`
	public enum PSKType: UInt8, MLSClosedEnum {
		case external = 1
		case resumption = 2
	}

	/// `enum { reserved(0), application(1), reinit(2), branch(3), (255) }
	/// ResumptionPSKUsage;`
	public enum ResumptionPSKUsage: UInt8, MLSClosedEnum {
		case application = 1
		case reinit = 2
		case branch = 3
	}

	/// `struct { ResumptionPSKUsage usage; opaque psk_group_id<V>; uint64
	/// psk_epoch; } ResumptionPSK;`
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
			try usage.encode(to: &writer)
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
	/// external: opaque psk_id<V>; case resumption: ResumptionPSK
	/// resumption; }; opaque psk_nonce<V>; } PreSharedKeyID;`
	public enum PreSharedKeyIdentifier: Sendable, Equatable {
		case external(pskID: Data, nonce: Data)
		case resumption(ResumptionPSK, nonce: Data)
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
			try version.encode(to: &writer)
			try cipherSuite.encode(to: &writer)
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
	/// purely from the wire (same caveat as `Credential`), which is why
	/// this enum has no `.other` fallback case: unlike `Credential`,
	/// mls-rs's own extensibility story for proposals (`CustomProposal`)
	/// requires the *caller* to already know the type to interpret it, so
	/// there is nothing generic to preserve here.
	public enum Proposal: Sendable, Equatable {
		case add(KeyPackage)
		case update(LeafNode)
		case remove(MLS.LeafIndex)
		case preSharedKey(PreSharedKeyIdentifier)
		case reInit(ReInitProposal)
		case externalInit(ExternalInitProposal)
		case groupContextExtensions([Extension])
	}

	/// `struct { uint8 proposal_or_ref_type; select (...) { case proposal:
	/// Proposal proposal; case reference: ProposalRef reference; }; }
	/// ProposalOrRef;`
	public enum ProposalOrRef: Sendable, Equatable {
		case proposal(Proposal)
		case reference(MLS.HashReference)
	}
}

extension MLS.RFC9420.PreSharedKeyIdentifier: MLSCodable {
	public func encode(to writer: inout MLS.Writer) throws {
		switch self {
		case .external(let pskID, let nonce):
			try MLS.RFC9420.PSKType.external.encode(to: &writer)
			try writer.writeOpaque(pskID)
			try writer.writeOpaque(nonce)
		case .resumption(let resumption, let nonce):
			try MLS.RFC9420.PSKType.resumption.encode(to: &writer)
			try resumption.encode(to: &writer)
			try writer.writeOpaque(nonce)
		}
	}

	public init(from reader: inout MLS.Reader) throws {
		switch try MLS.RFC9420.PSKType(from: &reader) {
		case .external:
			let pskID = Data(try reader.readOpaque())
			self = .external(pskID: pskID, nonce: Data(try reader.readOpaque()))
		case .resumption:
			let resumption = try MLS.RFC9420.ResumptionPSK(from: &reader)
			self = .resumption(resumption, nonce: Data(try reader.readOpaque()))
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
		try type.encode(to: &writer)
		switch self {
		case .add(let keyPackage): try keyPackage.encode(to: &writer)
		case .update(let leafNode): try leafNode.encode(to: &writer)
		case .remove(let leafIndex): try leafIndex.encode(to: &writer)
		case .preSharedKey(let psk): try psk.encode(to: &writer)
		case .reInit(let reInit): try reInit.encode(to: &writer)
		case .externalInit(let externalInit): try externalInit.encode(to: &writer)
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
			try proposal.encode(to: &writer)
		case .reference(let ref):
			writer.writeUInt8(2)
			try ref.encode(to: &writer)
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
