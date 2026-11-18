import Foundation
import Testing

@testable import MLSCodec

/// A bounded vector decode stops at the first element past its limit and
/// materialises at most `maxCount` elements.
@Suite("Bounded vector decode")
struct VectorLimitTests {
	@Test("a vector of exactly maxCount elements decodes")
	func vectorAtLimitDecodes() throws {
		Issue.record("pending")
	}

	@Test("a vector longer than maxCount throws vectorElementLimitExceeded")
	func vectorOverLimitThrows() throws {
		Issue.record("pending")
	}

	@Test("decoding stops before element maxCount + 1 is decoded")
	func decodingStopsAtLimit() throws {
		Issue.record("pending")
	}
}
