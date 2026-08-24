import Foundation
import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSFraming

@Suite("reuse_guard.json (mls-rs, self-contained)")
struct ReuseGuardTests {
	static let records = try! VectorFile.load("reuse_guard", as: [ReuseGuardVector].self)

	@Test("XORs into the leading 4 bytes of the nonce, symmetrically", arguments: records)
	func matchesVector(_ record: ReuseGuardVector) {
		let guardValue = MLS.Framing.ReuseGuard(Data(record.guardBytes))
		let applied = guardValue.applied(to: Data(record.nonce))
		#expect(applied == Data(record.result))
		// Applying it again removes it — XOR is its own inverse.
		#expect(guardValue.applied(to: applied) == Data(record.nonce))
	}
}
