import Foundation
import MLSVectorSupport
import Testing

@testable import MLSCodec

/// `deserialization.json` (mlswg/mls-implementations). Vendored since phase 0
/// and, until now, asserted against by nothing — `Vectors/README.md` claimed
/// it was "consumed by `MLSCodecTests`" and no test referenced it. A vendored
/// vector nothing reads is a coverage claim the repo makes and does not
/// honour, which is worse than not vendoring it.
///
/// `MLSVectorSupport` declares no dependencies of its own, so linking it here
/// preserves this target's isolation property (it still reaches only
/// `MLSCodec`) — that isolation is why the file sat unwired, not an oversight
/// about what it contained.
///
/// This overlaps `VarintTests`' hand-written boundary cases deliberately. Those
/// were derived from RFC 9420 §2.1.2 by reading; these are the working group's
/// own numbers, and agreeing with both is the point.
///
/// What this file does **not** cover, stated so the coverage claim stays
/// honest: all 14 entries are well-formed minimum-length encodings, so it
/// exercises the accept path only. The reserved `0b11` prefix, non-minimal
/// encodings, and truncated headers are rejected by tests in `VarintTests`
/// and `CodecTests`, which the working group publishes no vectors for.
@Suite("deserialization.json (mlswg/mls-implementations, official)")
struct DeserializationVectorTests {
	static let records = try! VectorFile.load(
		"deserialization", as: [DeserializationVector].self)

	@Test("each header decodes to its stated length, consuming exactly its own bytes")
	func headersDecode() throws {
		for record in Self.records {
			var reader = MLS.Reader(record.vlbytesHeader.bytes)
			#expect(try reader.readVarint() == record.length)
			// The width is fully determined by the first byte's top two
			// bits, so a short read throws rather than returning a wrong
			// value. `finish()` pins the other direction: the decoder must
			// not run *past* the header either, which is what makes each
			// entry a complete header rather than the prefix of one.
			try reader.finish()
		}
	}

	/// The other direction, which the vector file does not itself demand but
	/// which is the property that actually matters for interop: RFC 9420
	/// §2.1.2 requires minimum-length encoding, so for each of these lengths
	/// there is exactly one legal header — the one the file gives.
	@Test("each length re-encodes to exactly the header the vector gives")
	func lengthsReEncode() throws {
		for record in Self.records {
			var writer = MLS.Writer()
			try writer.writeVarint(record.length)
			#expect(Data(writer.bytes) == record.vlbytesHeader.bytes)
		}
	}
}
