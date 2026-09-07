import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import Testing

@testable import MLSCombiner

@Suite struct APQInfoTests {
	@Test func apqInfoRoundTrips() throws {
		let info = MLS.Combiner.APQInfo(
			tSessionGroupID: Data([1, 2, 3]),
			pqSessionGroupID: Data([4, 5, 6, 7]),
			mode: 0,
			tCipherSuite: MLS.CipherSuite(id: 1),
			pqCipherSuite: MLS.CipherSuite(id: 0xFDEA),
			tEpoch: 1,
			pqEpoch: 1)
		let bytes = try info.mlsEncoded()
		var reader = MLS.Reader(bytes)
		let decoded = try MLS.Combiner.APQInfo(from: &reader)
		try reader.finish()
		#expect(decoded == info)
	}
}
