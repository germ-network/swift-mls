import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §13.4: "Any field containing a list of extensions MUST NOT have more
/// than one extension of any given type." Such a list fails to decode, and the
/// library refuses to build one, so everything it sends decodes.
@Suite("Duplicate extension types are rejected (RFC 9420 §13.4)")
struct DuplicateExtensionTypeTests {
	private static let marker = MLS.RFC9420.Extension(
		type: .known(.applicationID), data: Data([0xDE, 0xAD, 0xBE]))

	private static func encoded(_ value: some MLSEncodable) throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(value)
		return Data(writer.bytes)
	}

	/// Hand-writes the wire bytes of a structure whose extension list holds
	/// `marker` twice: encodes it with one `marker` and doubles the vector. The
	/// encoders must not be relied on to produce the duplicate.
	private static func doubled(_ value: some MLSEncodable) throws -> Data {
		var oneMarker = MLS.Writer()
		try oneMarker.encode(marker)
		let entry = Data(oneMarker.bytes)
		var single = MLS.Writer()
		try single.writeOpaque(entry)
		var twice = MLS.Writer()
		try twice.writeOpaque(entry + entry)

		let bytes = try encoded(value)
		let needle = Data(single.bytes)
		let matches = bytes.indices.filter {
			$0 + needle.count <= bytes.count && bytes[$0..<$0 + needle.count] == needle
		}
		let at = try #require(matches.first)
		#expect(matches.count == 1)
		return bytes[..<at] + Data(twice.bytes) + bytes[(at + needle.count)...]
	}

	private static func leafNode(extensions: [MLS.RFC9420.Extension]) -> MLS.RFC9420.LeafNode {
		.init(
			encryptionKey: .init(Data(repeating: 1, count: 32)),
			signatureKey: .init(Data(repeating: 2, count: 32)),
			credential: .basic(identity: Data("a".utf8)),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [.curve25519Aes128],
				extensions: [],
				proposals: [], credentials: []),
			source: .update, extensions: extensions, signature: Data([9]))
	}

	private static func keyPackage(
		extensions: [MLS.RFC9420.Extension], leafExtensions: [MLS.RFC9420.Extension] = []
	) -> MLS.RFC9420.KeyPackage {
		.init(
			version: .mls10, cipherSuite: .curve25519Aes128,
			initKey: .init(Data(repeating: 3, count: 32)),
			leafNode: leafNode(extensions: leafExtensions), extensions: extensions,
			signature: Data([8]))
	}

	private static func groupContext(
		extensions: [MLS.RFC9420.Extension]
	) -> MLS.RFC9420.GroupContext {
		.init(
			version: .mls10, cipherSuite: .curve25519Aes128, groupID: Data([1]),
			epoch: 0,
			treeHash: Data([2]), confirmedTranscriptHash: Data([3]),
			extensions: extensions)
	}

	private static func groupInfo(
		extensions: [MLS.RFC9420.Extension]
	) -> MLS.RFC9420.GroupInfo {
		.init(
			groupContext: groupContext(extensions: []), extensions: extensions,
			confirmationTag: .init(Data(repeating: 4, count: 32)),
			signer: .init(value: 0), signature: Data([7]))
	}

	private static func reInit(
		extensions: [MLS.RFC9420.Extension]
	) -> MLS.RFC9420.ReInitProposal {
		.init(
			groupID: Data([1]), version: .mls10, cipherSuite: .curve25519Aes128,
			extensions: extensions)
	}

	private static func expectDuplicate<T: MLSDecodable>(
		_ type: T.Type, _ bytes: Data, sourceLocation: SourceLocation = #_sourceLocation
	) {
		#expect(
			throws: MLS.RFC9420.WireError.duplicateExtensionType(marker.type),
			sourceLocation: sourceLocation
		) {
			var reader = MLS.Reader(bytes)
			_ = try T(from: &reader)
		}
	}

	@Test("a KeyPackage with a repeated extension type fails to decode")
	func keyPackageWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(Self.keyPackage(extensions: [Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.KeyPackage.self, bytes)
	}

	@Test("a LeafNode with a repeated extension type fails to decode")
	func leafNodeWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(Self.leafNode(extensions: [Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.LeafNode.self, bytes)
	}

	@Test("a GroupContext with a repeated extension type fails to decode")
	func groupContextWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(Self.groupContext(extensions: [Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.GroupContext.self, bytes)
	}

	@Test("a GroupInfo with a repeated extension type fails to decode")
	func groupInfoWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(Self.groupInfo(extensions: [Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.GroupInfo.self, bytes)
	}

	@Test("a ReInit proposal with a repeated extension type fails to decode")
	func reInitWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(Self.reInit(extensions: [Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.ReInitProposal.self, bytes)
	}

	@Test("a GroupContextExtensions proposal with a repeated extension type fails to decode")
	func groupContextExtensionsProposalWithDuplicateExtensionTypeFailsToDecode() throws {
		let bytes = try Self.doubled(
			MLS.RFC9420.Proposal.groupContextExtensions([Self.marker]))
		Self.expectDuplicate(MLS.RFC9420.Proposal.self, bytes)
	}

	@Test("extension lists with distinct types still decode")
	func distinctExtensionTypesStillDecode() throws {
		let other = MLS.RFC9420.Extension(type: .unknown(0x7777), data: Data([1]))
		let value = Self.groupContext(extensions: [Self.marker, other])
		var reader = MLS.Reader(try Self.encoded(value))
		#expect(try MLS.RFC9420.GroupContext(from: &reader) == value)
	}

	@Test("two unknown extensions with the same wire type are rejected")
	func unknownExtensionTypeDuplicatesAreRejected() throws {
		var entries = MLS.Writer()
		let unknown = { (data: UInt8) in
			MLS.RFC9420.Extension(type: .unknown(0x4242), data: Data([data]))
		}
		for entry in [unknown(1), Self.marker, unknown(2)] {
			try entries.encode(entry)
		}
		var writer = MLS.Writer()
		try writer.writeOpaque(entries.bytes)
		var reader = MLS.Reader(writer.bytes)
		#expect(throws: MLS.RFC9420.WireError.duplicateExtensionType(.unknown(0x4242))) {
			_ = try reader.decodeExtensionList()
		}
	}

	@Test(
		"encoding any structure whose extension list repeats a type throws",
		.disabled("not yet implemented"))
	func encodingExtensionListWithRepeatedTypeThrows() throws {}

	@Test(
		"creating a group with a known and an unknown extension of the same wire type throws",
		.disabled("not yet implemented"))
	func createRejectsKnownAndUnknownExtensionWithSameWireType() throws {}

	@Test(
		"creating a group with repeated GroupContext extension types throws",
		.disabled("not yet implemented"))
	func createRejectsDuplicateGroupContextExtensionTypes() throws {}

	@Test(
		"committing a GroupContextExtensions proposal with repeated types throws",
		.disabled("not yet implemented"))
	func committingRejectsGroupContextExtensionsProposalWithDuplicateTypes() throws {}

	@Test(
		"committing an Add of a KeyPackage with repeated extension types throws",
		.disabled("not yet implemented"))
	func committingRejectsAddOfKeyPackageWithDuplicateTypes() throws {}
}
