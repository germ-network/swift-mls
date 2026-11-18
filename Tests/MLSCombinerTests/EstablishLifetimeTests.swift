import Foundation
import MLSCodec
import Testing

@testable import MLSCombiner
@testable import MLSProfileRFC9420

/// `establish` passes its `lifetimeCheck` to both halves' group creation and Add.
@Suite("Combiner establish checks KeyPackage lifetimes (RFC 9420 §7.3)")
struct EstablishLifetimeTests {
	typealias Support = CombinerTestSupport
	static let window = MLS.RFC9420.Lifetime(notBefore: 100, notAfter: 200)

	private static func establish(
		founder: Support.Member, peer: Support.Member, at check: MLS.RFC9420.LifetimeCheck
	) throws {
		_ = try MLS.Combiner.CombinerGroup.establish(
			classical: try Support.halfCreation(founder: founder, peer: peer),
			pq: try Support.halfCreation(founder: founder, peer: peer, half: .pq),
			mode: 0, classicalProvider: Support.provider,
			pqProvider: Support.pqProvider,
			lifetimeCheck: check)
	}

	@Test("an expired peer KeyPackage is refused when a time is given")
	func establishRejectsExpiredPeerKeyPackage() throws {
		let founder = try Support.member("founder")
		let peer = try Support.member("peer", lifetime: Self.window)
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try Self.establish(founder: founder, peer: peer, at: .at(unixSeconds: 201))
		}
		try Self.establish(founder: founder, peer: peer, at: .at(unixSeconds: 150))
		try Self.establish(founder: founder, peer: peer, at: .unchecked)
	}

	@Test("an expired founder leaf is refused when a time is given")
	func establishRejectsExpiredFounderLeaf() throws {
		let founder = try Support.member("founder", lifetime: Self.window)
		let peer = try Support.member("peer")
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try Self.establish(founder: founder, peer: peer, at: .at(unixSeconds: 201))
		}
	}
}
