import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// `Group.exportSecret` (RFC 9420 §8.5) is reachable per-half off a
/// `CombinerGroup` via its public `.classical` / `.pq` `Group`s, with no
/// combiner-level change: each half derives independently from its own
/// `exporter_secret`.
@Suite("Group.exportSecret reachability through CombinerGroup")
struct ExportSecretReachabilityTests {
	typealias Support = CombinerTestSupport

	@Test("both halves export, independently, and agree across parties")
	func bothHalvesExportIndependentlyAndConverge() throws {
		let provider = Support.provider
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, peer) = try Support.establishedPair(founder: alice, peer: bob)

		let classicalExport = try founder.classical.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		let pqExport = try founder.pq.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		#expect(classicalExport.byteCount == 32)
		#expect(pqExport.byteCount == 32)

		// Independent halves: identical inputs on each half's own exporter secret
		// do not coincide.
		#expect(classicalExport != pqExport)

		// Both parties converge on each half's real epoch exporter.
		let peerClassicalExport = try peer.classical.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		let peerPqExport = try peer.pq.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		#expect(classicalExport == peerClassicalExport)
		#expect(pqExport == peerPqExport)
	}

	@Test("repeatable on a single half")
	func repeatableOnOneHalf() throws {
		let provider = Support.provider
		let alice = try Support.member("alice")
		let bob = try Support.member("bob")
		let (founder, _) = try Support.establishedPair(founder: alice, peer: bob)

		let first = try founder.classical.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		let second = try founder.classical.exportSecret(
			provider, label: "rendezvous", context: Data("ctx".utf8), length: 32)
		#expect(first == second)
	}
}
