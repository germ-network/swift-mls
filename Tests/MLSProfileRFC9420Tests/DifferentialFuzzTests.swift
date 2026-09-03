import Foundation
import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// Splitmix64 — same constants as `MLSCodecTests`' generator, redeclared
/// here because test targets deliberately do not link each other.
private struct SeededGenerator: RandomNumberGenerator {
	private var state: UInt64
	init(seed: UInt64) { state = seed }
	mutating func next() -> UInt64 {
		state &+= 0x9E37_79B9_7F4A_7C15
		var z = state
		z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
		z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
		return z ^ (z >> 31)
	}
}

/// The codec target proves decode-or-round-trip-exactly on a synthetic
/// struct; this proves it on the *real* RFC 9420 message grammar, over the
/// official vector corpus. The property is what protects every signature
/// and hash: a decoder that canonicalizes malformed input — or accepts two
/// byte strings as the same value — breaks any signature computed over the
/// original bytes. Deterministic seed; each corpus message takes 2,000
/// single-byte mutations plus 200 random truncations.
@Suite("Differential fuzz over the vector corpus (mlswg/mls-implementations)")
struct DifferentialFuzzTests {
	static func corpus() throws -> [Data] {
		var corpus: [Data] = []
		let welcome = try VectorFile.load(
			"passive-client-welcome", as: [PassiveClientVector].self)
		let commits = try VectorFile.load(
			"passive-client-handling-commit", as: [PassiveClientVector].self)
		// One record per cipher suite from each file keeps the corpus
		// representative without an hour of runtime.
		var seenSuites: Set<UInt16> = []
		for record in welcome where seenSuites.insert(record.cipherSuite).inserted {
			corpus.append(record.keyPackage.bytes)
			corpus.append(record.welcome.bytes)
		}
		seenSuites = []
		for record in commits where seenSuites.insert(record.cipherSuite).inserted {
			if let epoch = record.epochs.first {
				corpus.append(epoch.commit.bytes)
				corpus.append(contentsOf: epoch.proposals.prefix(2).map(\.bytes))
			}
		}
		return corpus
	}

	@Test("mutated vector messages either fail to decode or re-encode byte-identically")
	func decodeOrRoundTrip() throws {
		var generator = SeededGenerator(seed: 0x9420_9420_0000_0001)
		var decoded = 0
		var rejected = 0
		for original in try Self.corpus() {
			var bytes = Array(original)
			for round in 0..<2_200 {
				if round < 2_000 {
					let index = Int.random(
						in: 0..<bytes.count, using: &generator)
					bytes[index] = UInt8.random(
						in: .min ... .max, using: &generator)
				} else {
					// Truncations probe the length-header paths.
					let cut = Int.random(in: 0..<bytes.count, using: &generator)
					bytes = Array(bytes.prefix(cut))
					if bytes.isEmpty { bytes = Array(original) }
				}
				var reader = MLS.Reader(Data(bytes))
				guard let message = try? MLS.RFC9420.Message(from: &reader),
					(try? reader.finish()) != nil
				else {
					rejected += 1
					bytes = Array(original)
					continue
				}
				decoded += 1
				var writer = MLS.Writer()
				try message.encode(to: &writer)
				#expect(
					Array(writer.bytes) == bytes,
					"a decoded mutation must re-encode to exactly its own bytes"
				)
				bytes = Array(original)
			}
			// The unmutated original must round-trip too.
			var reader = MLS.Reader(original)
			let message = try MLS.RFC9420.Message(from: &reader)
			try reader.finish()
			var writer = MLS.Writer()
			try message.encode(to: &writer)
			#expect(Data(writer.bytes) == original)
		}
		// The run must have exercised both arms, or the property is
		// vacuous.
		#expect(decoded > 0, "no mutation ever decoded — the accept arm never ran")
		#expect(rejected > 0, "no mutation was ever rejected — the reject arm never ran")
	}
}
