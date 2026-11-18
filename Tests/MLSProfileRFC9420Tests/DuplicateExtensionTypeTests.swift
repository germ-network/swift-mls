import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// RFC 9420 §13.4: "Any field containing a list of extensions MUST NOT have more
/// than one extension of any given type." Such a list fails to decode, and the
/// library refuses to build one, so everything it sends decodes.
@Suite("Duplicate extension types are rejected (RFC 9420 §13.4)")
struct DuplicateExtensionTypeTests {
	static let marker = MLS.RFC9420.Extension(
		type: .known(.applicationID), data: Data([0xDE, 0xAD, 0xBE]))

	static func encoded(_ value: some MLSEncodable) throws -> Data {
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

	static func leafNode(extensions: [MLS.RFC9420.Extension]) -> MLS.RFC9420.LeafNode {
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

	static func keyPackage(
		extensions: [MLS.RFC9420.Extension], leafExtensions: [MLS.RFC9420.Extension] = []
	) -> MLS.RFC9420.KeyPackage {
		.init(
			version: .mls10, cipherSuite: .curve25519Aes128,
			initKey: .init(Data(repeating: 3, count: 32)),
			leafNode: leafNode(extensions: leafExtensions), extensions: extensions,
			signature: Data([8]))
	}

	static func groupContext(
		extensions: [MLS.RFC9420.Extension]
	) -> MLS.RFC9420.GroupContext {
		.init(
			version: .mls10, cipherSuite: .curve25519Aes128, groupID: Data([1]),
			epoch: 0,
			treeHash: Data([2]), confirmedTranscriptHash: Data([3]),
			extensions: extensions)
	}

	static func groupInfo(
		extensions: [MLS.RFC9420.Extension]
	) -> MLS.RFC9420.GroupInfo {
		.init(
			groupContext: groupContext(extensions: []), extensions: extensions,
			confirmationTag: .init(Data(repeating: 4, count: 32)),
			signer: .init(value: 0), signature: Data([7]))
	}

	static func reInit(
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

	private static func expectDuplicateError(
		_ body: () throws -> Void, sourceLocation: SourceLocation = #_sourceLocation
	) {
		#expect(
			sourceLocation: sourceLocation, performing: body,
			throws: { error in
				guard case MLS.RFC9420.WireError.duplicateExtensionType = error
				else {
					return false
				}
				return true
			})
	}

	typealias T = DuplicateExtensionTypeTests

	enum Structure: String, CaseIterable, CustomTestStringConvertible {
		case keyPackage, keyPackageToBeSigned, leafNode, leafNodeToBeSigned
		case groupContext, groupInfo, groupInfoToBeSigned, reInit, groupContextExtensions

		var testDescription: String { rawValue }

		func encode(_ duplicated: [MLS.RFC9420.Extension]) throws {
			switch self {
			case .keyPackage:
				_ = try T.encoded(T.keyPackage(extensions: duplicated))
			case .keyPackageToBeSigned:
				_ = try T.keyPackage(extensions: duplicated).toBeSigned()
			case .leafNode:
				_ = try T.encoded(T.leafNode(extensions: duplicated))
			case .leafNodeToBeSigned:
				_ = try T.leafNode(extensions: duplicated).toBeSigned(
					placement: .keyPackage)
			case .groupContext:
				_ = try T.encoded(T.groupContext(extensions: duplicated))
			case .groupInfo:
				_ = try T.encoded(T.groupInfo(extensions: duplicated))
			case .groupInfoToBeSigned:
				_ = try T.groupInfo(extensions: duplicated).toBeSigned()
			case .reInit:
				_ = try T.encoded(T.reInit(extensions: duplicated))
			case .groupContextExtensions:
				_ = try T.encoded(
					MLS.RFC9420.Proposal.groupContextExtensions(duplicated))
			}
		}
	}

	@Test(
		"encoding any structure whose extension list repeats a type throws",
		arguments: Structure.allCases)
	func encodingExtensionListWithRepeatedTypeThrows(_ structure: Structure) throws {
		Self.expectDuplicateError { try structure.encode([Self.marker, Self.marker]) }
	}

	private static func createGroup(
		extensions: [MLS.RFC9420.Extension], leafExtensions: [MLS.RFC9420.Extension] = []
	) throws -> MLS.RFC9420.Group {
		let alice = try SelfInteropTests.member("alice")
		var leaf = alice.keyPackage.leafNode
		leaf.extensions = leafExtensions
		return try MLS.RFC9420.Group.create(
			SelfInteropTests.provider, groupID: Data([1]), leafNode: leaf,
			leafSecretKey: alice.leafSecretKey, extensions: extensions,
			epochSecret: SecretBytes(randomByteCount: 32), lifetimeCheck: .unchecked)
	}

	@Test("creating a group with repeated GroupContext extension types throws")
	func createRejectsDuplicateGroupContextExtensionTypes() throws {
		Self.expectDuplicateError {
			_ = try Self.createGroup(extensions: [Self.marker, Self.marker])
		}
		Self.expectDuplicateError {
			_ = try Self.createGroup(
				extensions: [], leafExtensions: [Self.marker, Self.marker])
		}
	}

	@Test(
		"creating a group with a known and an unknown extension of the same wire type throws"
	)
	func createRejectsKnownAndUnknownExtensionWithSameWireType() throws {
		let known = MLS.RFC9420.Extension(type: .known(.applicationID), data: Data([1]))
		let unknown = MLS.RFC9420.Extension(type: .unknown(1), data: Data([2]))
		Self.expectDuplicateError {
			_ = try Self.createGroup(extensions: [known, unknown])
		}
	}

	@Test("committing a GroupContextExtensions proposal with repeated types throws")
	func committingRejectsGroupContextExtensionsProposalWithDuplicateTypes() throws {
		let provider = SelfInteropTests.provider
		let alice = try SelfInteropTests.member("alice")
		var group = try SelfInteropTests.createGroup(alice)
		Self.expectDuplicateError {
			_ = try group.commit(
				provider,
				proposals: [
					.proposal(
						.groupContextExtensions([Self.marker, Self.marker]))
				], signingKey: alice.signingKey, randomness: .generate(provider))
		}
	}

	@Test("committing an Add of a KeyPackage with repeated extension types throws")
	func committingRejectsAddOfKeyPackageWithDuplicateTypes() throws {
		let provider = SelfInteropTests.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var group = try SelfInteropTests.createGroup(alice)
		var keyPackage = bob.keyPackage
		keyPackage.extensions = [Self.marker, Self.marker]
		Self.expectDuplicateError {
			_ = try group.commit(
				provider, proposals: [.proposal(.add(keyPackage))],
				signingKey: alice.signingKey, randomness: .generate(provider))
		}
	}
}
