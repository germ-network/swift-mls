import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420
@testable import MLSTreeKEM

/// `validateParentHashChain` must give the same verdict, and the same error,
/// as `validateUnmergedLeaves()` followed by the straightforward
/// implementation of RFC 9420 §7.9.2's bottom-up procedure. The reference is
/// self-contained: its own filtered tree hash (the §7.9 original sibling tree
/// hash), parent-hash input encoding and recursive descendant walk, over
/// public tree accessors and the provider only. It is slow by design and runs
/// only on small trees.
@Suite("Parent-hash validation agrees with the reference implementation")
struct ParentHashReferenceTests {
	@Test("every tree-validation vector tree gets the same result from both")
	func vectorTreesAgree() throws {
		Issue.record("pending")
	}

	@Test("every single-node mutation of a vector tree gets the same result from both")
	func mutatedVectorTreesAgree() throws {
		Issue.record("pending")
	}
}
