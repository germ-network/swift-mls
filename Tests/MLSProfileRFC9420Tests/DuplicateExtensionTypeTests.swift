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
	@Test(
		"a KeyPackage with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func keyPackageWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test(
		"a LeafNode with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func leafNodeWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test(
		"a GroupContext with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func groupContextWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test(
		"a GroupInfo with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func groupInfoWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test(
		"a ReInit proposal with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func reInitWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test(
		"a GroupContextExtensions proposal with a repeated extension type fails to decode",
		.disabled("not yet implemented"))
	func groupContextExtensionsProposalWithDuplicateExtensionTypeFailsToDecode() throws {}

	@Test("extension lists with distinct types still decode", .disabled("not yet implemented"))
	func distinctExtensionTypesStillDecode() throws {}

	@Test(
		"two unknown extensions with the same wire type are rejected",
		.disabled("not yet implemented"))
	func unknownExtensionTypeDuplicatesAreRejected() throws {}

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
