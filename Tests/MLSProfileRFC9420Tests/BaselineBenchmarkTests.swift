import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSProfileRFC9420

/// The RFC 9420 baseline row — the numbers phases 8–10 measure against
/// (`spec/benchmarks.md` is the durable copy; this suite is what keeps it
/// honest). The scenario is fixed so the numbers are *exact*, not
/// ceilings: suite 1 (Ed25519, X25519, fixed-length primitives), 5-byte
/// identities, a 2-member group, an empty full-path commit as "one
/// rotation". Every length in that shape is determined, so drift in any
/// direction — a field added, an encoding changed, a signature grown — is
/// a failure here first and a conscious edit to both files second.
@Suite("Wire-size and signature-count baseline (suite 1)")
struct BaselineBenchmarkTests {
	struct Measured {
		var rotationCommit: Int
		var addCommit: Int
		var welcome: Int
		var keyPackage: Int
		var rotationFramingSignatures: Int
		var rotationLeafSignatures: Int
	}

	static func measure() throws -> Measured {
		let provider = SelfInteropTests.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		var groupA = try SelfInteropTests.createGroup(alice)
		let add = try groupA.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		groupA = add.group
		let rotation = try groupA.committing(
			provider, proposals: [], signingKey: alice.signingKey,
			randomness: .generate(provider))

		func size(_ message: MLS.RFC9420.Message) throws -> Int {
			var writer = MLS.Writer()
			try message.encode(to: &writer)
			return writer.bytes.count
		}
		guard case .commit(let commit) = rotation.commit.content.content else {
			throw CommitRejectionTests.Failure.shape
		}
		return Measured(
			rotationCommit: try size(.publicMessage(rotation.commit)),
			addCommit: try size(.publicMessage(add.commit)),
			welcome: try size(.welcome(try #require(add.welcome))),
			keyPackage: try size(.keyPackage(bob.keyPackage)),
			rotationFramingSignatures: rotation.commit.auth.signature == nil ? 0 : 1,
			rotationLeafSignatures: commit.path == nil ? 0 : 1)
	}

	@Test("one rotation costs exactly 2 signatures and 491 wire bytes")
	func rotationBaseline() throws {
		let m = try Self.measure()
		#expect(m.rotationFramingSignatures == 1)
		#expect(m.rotationLeafSignatures == 1)
		#expect(m.rotationCommit == 491)
	}

	@Test("add-commit, Welcome, and KeyPackage sizes match spec/benchmarks.md")
	func messageSizes() throws {
		let m = try Self.measure()
		#expect(m.addCommit == 682)
		#expect(m.welcome == 795)
		#expect(m.keyPackage == 275)
	}

	/// The row the whole modularization exists to shrink: TwoMLS runs four
	/// parallel groups, so one identity rotation today costs 4 leaf
	/// signatures + 4 framing signatures = 8, and 4x the rotation bytes.
	/// Phase 8's single-signature construction targets 4; phase 9's shared
	/// leaf targets 1.
	@Test("the four-group TwoMLS shape: 8 signatures per rotation")
	func fourGroupBaseline() throws {
		let m = try Self.measure()
		let signatures = 4 * (m.rotationFramingSignatures + m.rotationLeafSignatures)
		#expect(signatures == 8)
		#expect(4 * m.rotationCommit == 1964)
	}
}
