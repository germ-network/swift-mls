import Foundation
import MLSCodec
import MLSCrypto
import MLSVectorSupport
import Testing

@testable import MLSProfileRFC9420

/// The passive-client scenario, end to end: join the group a different
/// implementation created, then apply its commits epoch by epoch and match
/// its `epoch_authenticator` every time. This is the strongest signal the
/// project has short of live interop — every structure, every hash chain
/// and every key-schedule step has to agree with an implementation this
/// code has never seen.
///
/// Shared by both commit-bearing vectors. `passive-client-handling-commit`
/// is broad (many records, two epochs each, every proposal type);
/// `passive-client-random` is deep (one record, 200 consecutive epochs) and
/// is the only thing that exercises held-key staleness across a long chain,
/// so it runs as its own suite to keep its runtime legible.
enum PassiveClientRunner {
	static func run(_ record: PassiveClientVector, provider: any MLS.CipherSuiteProvider) throws
	{
		var keyPackageReader = MLS.Reader(record.keyPackage.bytes)
		guard
			case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(
				from: &keyPackageReader)
		else {
			Issue.record("expected wire_format == mls_key_package")
			return
		}
		try keyPackageReader.finish()

		var welcomeReader = MLS.Reader(record.welcome.bytes)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(from: &welcomeReader)
		else {
			Issue.record("expected wire_format == mls_welcome")
			return
		}
		try welcomeReader.finish()

		let externalPsks = Dictionary(
			uniqueKeysWithValues: record.externalPsks.map {
				($0.pskID.bytes, $0.psk.bytes)
			})
		let resolveExternal: (MLS.RFC9420.PreSharedKeyIdentifier) throws -> Data? = { id in
			guard case .external(let pskID, _) = id else { return nil }
			return externalPsks[pskID]
		}

		var externalTree: [MLS.RFC9420.Node?]?
		if let ratchetTree = record.ratchetTree {
			var treeReader = MLS.Reader(ratchetTree.bytes)
			externalTree = try treeReader.decodeVector()
			try treeReader.finish()
		}

		var group = try MLS.RFC9420.Group.join(
			provider, welcome: welcome,
			credentials: .init(
				keyPackage: keyPackage,
				initKey: MLS.HpkeSecretKey(record.initPriv.bytes),
				encryptionKey: MLS.HpkeSecretKey(record.encryptionPriv.bytes)),
			externalTree: externalTree, psk: resolveExternal)

		#expect(group.epoch.epochAuthenticator == record.initialEpochAuthenticator.bytes)

		for (index, epoch) in record.epochs.enumerated() {
			// Every loose proposal this epoch goes into the store keyed by
			// its own ProposalRef, which is what the commit references. A
			// proposal the commit doesn't reference is simply never looked
			// up -- RFC 9420 §12.4 explicitly does not make receivers
			// enforce that they saw every referenced proposal and no more.
			var store = MLS.RFC9420.ProposalStore()
			for proposalBytes in epoch.proposals {
				var reader = MLS.Reader(proposalBytes.bytes)
				guard
					case .publicMessage(let message) = try MLS.RFC9420.Message(
						from: &reader)
				else {
					Issue.record(
						"epoch \(index): expected a PublicMessage proposal")
					return
				}
				try reader.finish()
				guard case .proposal = message.content.content else {
					Issue.record("epoch \(index): expected proposal content")
					return
				}
				// Real vector proposals — authenticate the framing through
				// `verify`, as a live receiver does, before the store accepts
				// them.
				try store.insert(
					try group.verify(proposal: message, provider), provider)
			}

			var commitReader = MLS.Reader(epoch.commit.bytes)
			guard
				case .publicMessage(let commit) = try MLS.RFC9420.Message(
					from: &commitReader)
			else {
				Issue.record("epoch \(index): expected a PublicMessage commit")
				return
			}
			try commitReader.finish()

			try group.process(
				provider, commit: commit, proposals: store, psk: resolveExternal)

			#expect(
				group.epoch.epochAuthenticator == epoch.epochAuthenticator.bytes,
				"epoch \(index) authenticator")
		}
	}
}

@Suite("passive-client-handling-commit.json (mlswg/mls-implementations, official)")
struct PassiveClientCommitTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"passive-client-handling-commit", as: [PassiveClientVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test(
		"join, then apply every commit and match each epoch_authenticator",
		arguments: records)
	func handlesCommits(_ record: PassiveClientVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		try PassiveClientRunner.run(record, provider: provider)
	}
}

/// One record, 200 consecutive epochs — kept separate because it is the
/// only test that exercises held-key staleness over a long chain (a key
/// pruned one epoch too early or too late surfaces dozens of epochs later,
/// not immediately), and because its runtime would otherwise dominate the
/// suite it sat in.
@Suite("passive-client-random.json (mlswg/mls-implementations, official)")
struct PassiveClientRandomTests {
	static let provider = SwiftCryptoProvider()

	static let records = try! VectorFile.load(
		"passive-client-random", as: [PassiveClientVector].self
	)
	.filter { provider.supportedCipherSuites.map(\.id).contains($0.cipherSuite) }

	@Test("200 consecutive epochs, each authenticator matching", arguments: records)
	func handlesLongChain(_ record: PassiveClientVector) throws {
		let provider = try #require(
			Self.provider.cipherSuiteProvider(for: .init(id: record.cipherSuite)))
		try PassiveClientRunner.run(record, provider: provider)
	}
}
