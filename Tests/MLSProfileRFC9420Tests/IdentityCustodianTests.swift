import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import SecretBytes
import Testing

@testable import MLSProfileRFC9420

/// Documentation-as-executable-code for an architecture pattern: `Group`/
/// `Membership` are values the app owns; an app-side **Identity custodian**
/// is the sole holder of the signing key, standing in for a stateful
/// (hash-based, one-time-ticket) signer. The library never sees or persists
/// a key -- every signature it produces comes back out through
/// `provider.sign(privateKey:content:)`, so a test-side provider wrapping
/// the real one is the one place to observe *actual* per-signature
/// consumption, not a proxy for it (a counter bumped once per `committing`
/// call would not prove the same thing).
///
/// No `Sources/` change backs any of this: `CustodialProvider` forwards
/// `MLS.CipherSuiteProvider` to `SwiftCryptoProvider`'s per-suite provider,
/// `Identity` is a plain actor built on the public `committing` /
/// `proposeUpdate` / `protect` / `archive` / `restore` / `joining` surface.
@Suite("Identity custodian: an isolated signer, observed at the one choke point")
struct IdentityCustodianTests {
	static let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	// MARK: - Ledger

	/// The custodian's own bookkeeping. `next` is the in-memory high-water
	/// ticket mark; `durable` is the simulated persisted store (a prefix of
	/// `next`); `log` is the full ordered history `#expect` reads back.
	struct Ledger: Sendable, Equatable {
		enum Event: Sendable, Equatable {
			case consumed(Int, String)
			case persistedIdentity(through: Int)
			case persistedGroup(Int)
			case transmitted
		}

		var next = 0
		var durable: [Int] = []
		var log: [Event] = []
		private var groupVersion = 0

		mutating func consume(role: String) -> Int {
			let ticket = next
			next += 1
			log.append(.consumed(ticket, role))
			return ticket
		}

		mutating func persistIdentity() {
			if next > durable.count {
				durable.append(contentsOf: durable.count..<next)
			}
			log.append(.persistedIdentity(through: next - 1))
		}

		mutating func persistGroup() -> Int {
			groupVersion += 1
			log.append(.persistedGroup(groupVersion))
			return groupVersion
		}

		mutating func transmit() {
			log.append(.transmitted)
		}

		/// A process restart: only `durable` survives. Anything minted after
		/// the last `persistIdentity()` is lost, and the next ticket handed
		/// out resumes from there -- correctly if that was also the last
		/// thing persisted, unsafely (a reissued ticket) if it was not.
		mutating func crashAndReload() {
			next = durable.count
		}
	}

	/// `sign()` is a synchronous, non-`async` protocol requirement, so
	/// `CustodialProvider` cannot hop back into `Identity`'s isolation to
	/// record a consumption -- there is no `await` to spend. This box gives
	/// the ledger its own lock instead. In practice it never contends:
	/// `Identity` is the sole owner, and every call into it happens
	/// synchronously, nested inside one already-serialized actor call.
	final class LedgerBox: @unchecked Sendable {
		private var state = Ledger()
		private let lock = NSLock()

		@discardableResult
		func consume(role: String) -> Int {
			lock.lock()
			defer { lock.unlock() }
			return state.consume(role: role)
		}
		func persistIdentity() {
			lock.lock()
			defer { lock.unlock() }
			state.persistIdentity()
		}
		@discardableResult
		func persistGroup() -> Int {
			lock.lock()
			defer { lock.unlock() }
			return state.persistGroup()
		}
		func transmit() {
			lock.lock()
			defer { lock.unlock() }
			state.transmit()
		}
		func crashAndReload() {
			lock.lock()
			defer { lock.unlock() }
			state.crashAndReload()
		}
		var snapshot: Ledger {
			lock.lock()
			defer { lock.unlock() }
			return state
		}
	}

	// MARK: - The observation hook

	/// Wraps the real provider, forwarding every `CipherSuiteProvider`
	/// requirement except `sign`, which records a consumption first. Every
	/// library signature is `SignWithLabel`'s `Encode(SignContent)` --
	/// `opaque label<V>` then `opaque content<V>`, `label` = `"MLS 1.0 " +
	/// Label` (`Sources/MLSCrypto/Labels.swift`) -- so the label, and hence
	/// the signature's role, is read straight off the bytes handed to
	/// `sign`, not guessed from the call site.
	struct CustodialProvider: MLS.CipherSuiteProvider {
		let inner: any MLS.CipherSuiteProvider
		let ledger: LedgerBox

		var cipherSuite: MLS.CipherSuite { inner.cipherSuite }
		var hashSize: Int { inner.hashSize }
		var aeadKeySize: Int { inner.aeadKeySize }
		var aeadNonceSize: Int { inner.aeadNonceSize }
		var hpkeSecretKeySize: Int? { inner.hpkeSecretKeySize }

		func randomBytes(_ count: Int) -> Data { inner.randomBytes(count) }
		func hash(_ data: Data) throws -> Data { try inner.hash(data) }

		func kdfExtract(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws
			-> Data
		{
			try inner.kdfExtract(salt: salt, ikm: ikm)
		}
		func kdfExpand(prk: some ContiguousBytes, info: Data, length: Int) throws -> Data {
			try inner.kdfExpand(prk: prk, info: info, length: length)
		}
		func kdfExtractSecret(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws
			-> SecretBytes
		{
			try inner.kdfExtractSecret(salt: salt, ikm: ikm)
		}
		func kdfExpandSecret(prk: some ContiguousBytes, info: Data, length: Int) throws
			-> SecretBytes
		{
			try inner.kdfExpandSecret(prk: prk, info: info, length: length)
		}

		func sign(privateKey: MLS.SignatureSecretKey, content: Data) throws -> Data {
			ledger.consume(role: Self.role(fromSignedContent: content))
			return try inner.sign(privateKey: privateKey, content: content)
		}
		func verify(publicKey: MLS.SignaturePublicKey, content: Data, signature: Data)
			throws
			-> Bool
		{
			try inner.verify(
				publicKey: publicKey, content: content, signature: signature)
		}

		func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data {
			try inner.aeadSeal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		}
		func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data {
			try inner.aeadOpen(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		}

		func hpkeGenerateKeyPair() throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
			try inner.hpkeGenerateKeyPair()
		}
		func hpkeSeal(publicKey: MLS.HpkePublicKey, info: Data, aad: Data?, plaintext: Data)
			throws -> (enc: Data, ciphertext: Data)
		{
			try inner.hpkeSeal(
				publicKey: publicKey, info: info, aad: aad, plaintext: plaintext)
		}
		func hpkeOpen(
			enc: Data, secretKey: MLS.HpkeSecretKey, info: Data, aad: Data?,
			ciphertext: Data
		) throws -> Data {
			try inner.hpkeOpen(
				enc: enc, secretKey: secretKey, info: info, aad: aad,
				ciphertext: ciphertext)
		}
		func hpkeDeriveKeyPair(ikm: some ContiguousBytes) throws -> (
			MLS.HpkeSecretKey, MLS.HpkePublicKey
		) {
			try inner.hpkeDeriveKeyPair(ikm: ikm)
		}

		static func role(fromSignedContent content: Data) -> String {
			var reader = MLS.Reader(content)
			guard let labelBytes = try? reader.readOpaque() else { return "unknown" }
			let label = String(decoding: labelBytes, as: UTF8.self)
			let prefix = "MLS 1.0 "
			return label.hasPrefix(prefix)
				? String(label.dropFirst(prefix.count)) : label
		}
	}

	// MARK: - The custodian

	/// The isolated custodian: the only thing in this file that ever holds
	/// `signingKey`. `Group`/`Membership` stay values passed in and handed
	/// back by every method; nothing here retains one across calls. Each op
	/// wraps the caller's provider, calls straight into the public
	/// `committing` / `proposeUpdate` / `protect` from inside the actor's own
	/// isolation with no `await` in between the library call and reading the
	/// ledger back out, then returns a plain `Sendable` bundle -- `Transition`
	/// / `SentCommit` / `PendingCommit` are `~Copyable` and stay inside the
	/// call that produced them, exactly as `MLSInteropService` keeps a
	/// `PendingCommit` in a reference slot rather than a struct field.
	actor Identity {
		private let signingKey: MLS.SignatureSecretKey
		private let ledger = LedgerBox()

		init(signingKey: MLS.SignatureSecretKey) {
			self.signingKey = signingKey
		}

		struct CommitArtifact: Sendable {
			/// `Transition.group`: the OLD epoch with this commit's own
			/// handshake generation already consumed -- persist this before
			/// transmitting `message`.
			let sealedGroup: MLS.RFC9420.Group
			/// `pending.apply(onto: sealedGroup)`'s result -- the new epoch,
			/// for continuing operations.
			let advancedGroup: MLS.RFC9420.Group
			let message: MLS.RFC9420.Message
			let welcome: MLS.RFC9420.Welcome?
			let effects: MLS.RFC9420.CommitEffects
			let consumedTickets: [Int]
		}
		struct UpdateArtifact: Sendable {
			let group: MLS.RFC9420.Group
			let message: MLS.RFC9420.Message
			let ref: MLS.HashReference
			let consumedTickets: [Int]
		}
		struct ProtectArtifact: Sendable {
			let group: MLS.RFC9420.Group
			let message: MLS.RFC9420.PrivateMessage
			let consumedTickets: [Int]
		}

		@discardableResult
		func commit(
			_ provider: any MLS.CipherSuiteProvider,
			group: MLS.RFC9420.Group,
			proposals: [MLS.RFC9420.ProposalOrRef],
			includePath: Bool = true,
			psk: @Sendable (MLS.RFC9420.PreSharedKeyIdentifier) throws -> SecretBytes? =
				{
					_ in nil
				}
		) throws -> CommitArtifact {
			let custodial = CustodialProvider(inner: provider, ledger: ledger)
			let before = ledger.snapshot.next
			let transition = try group.committing(
				custodial, proposals: proposals, signingKey: signingKey,
				randomness: try .generate(custodial), includePath: includePath,
				psk: psk)
			let sealedGroup = transition.group
			let sent = transition.takeOutput()
			let message = sent.message
			let welcome = sent.welcome
			let pending = sent.takePending()
			let advanced = try pending.apply(onto: sealedGroup)
			let after = ledger.snapshot.next
			return CommitArtifact(
				sealedGroup: sealedGroup, advancedGroup: advanced.group,
				message: message,
				welcome: welcome, effects: advanced.output,
				consumedTickets: Array(before..<after))
		}

		@discardableResult
		func proposeUpdate(
			_ provider: any MLS.CipherSuiteProvider,
			group: MLS.RFC9420.Group,
			framing: MLS.RFC9420.Group.HandshakeFraming = .privateMessage
		) throws -> UpdateArtifact {
			let custodial = CustodialProvider(inner: provider, ledger: ledger)
			let before = ledger.snapshot.next
			var updated = group
			let (message, ref) = try updated.proposeUpdate(
				custodial, signingKey: signingKey, framing: framing)
			let after = ledger.snapshot.next
			return UpdateArtifact(
				group: updated, message: message, ref: ref,
				consumedTickets: Array(before..<after))
		}

		@discardableResult
		func protect(
			_ provider: any MLS.CipherSuiteProvider,
			group: MLS.RFC9420.Group,
			applicationData: Data,
			authenticatedData: Data = Data()
		) throws -> ProtectArtifact {
			let custodial = CustodialProvider(inner: provider, ledger: ledger)
			let before = ledger.snapshot.next
			var sent = group
			let message = try sent.protect(
				custodial, applicationData: applicationData,
				authenticatedData: authenticatedData, signingKey: signingKey)
			let after = ledger.snapshot.next
			return ProtectArtifact(
				group: sent, message: message,
				consumedTickets: Array(before..<after))
		}

		func persistIdentity() { ledger.persistIdentity() }
		@discardableResult
		func notePersistedGroup() -> Int { ledger.persistGroup() }
		func noteTransmitted() { ledger.transmit() }
		func simulateCrash() { ledger.crashAndReload() }

		var log: [Ledger.Event] { ledger.snapshot.log }
		var durable: [Int] { ledger.snapshot.durable }
		var nextTicket: Int { ledger.snapshot.next }
	}

	// MARK: - Reflection helper (test 5)

	/// Every value reachable from `root` by walking stored properties --
	/// `SecretArchive` has no plaintext byte accessor other than `seal`
	/// (which encrypts), so "the group holds no key" is checked on the value
	/// that *feeds* `archive()`, not on its output.
	static func reachableValues(from root: Any) -> [Any] {
		var found: [Any] = []
		var stack: [(Any, Int)] = [(root, 0)]
		while let (value, depth) = stack.popLast() {
			found.append(value)
			guard depth < 40 else { continue }
			for child in Mirror(reflecting: value).children {
				stack.append((child.value, depth + 1))
			}
		}
		return found
	}

	// MARK: - Tests

	@Test("committing/proposeUpdate/protect each consume exactly the real per-signature chain")
	func perSignatureConsumption() async throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let identity = Identity(signingKey: alice.signingKey)
		let group = try SelfInteropTests.createGroup(alice)

		let commitResult = try await identity.commit(
			provider, group: group, proposals: [.proposal(.add(bob.keyPackage))])
		#expect(commitResult.consumedTickets == [0, 1, 2])
		var log = await identity.log
		#expect(
			log == [
				.consumed(0, "LeafNodeTBS"), .consumed(1, "FramedContentTBS"),
				.consumed(2, "GroupInfoTBS"),
			])

		let updateResult = try await identity.proposeUpdate(
			provider, group: commitResult.advancedGroup)
		#expect(updateResult.consumedTickets == [3, 4])
		log = await identity.log
		#expect(
			log.suffix(2) == [
				.consumed(3, "LeafNodeTBS"), .consumed(4, "FramedContentTBS"),
			])

		let protectResult = try await identity.protect(
			provider, group: updateResult.group, applicationData: Data("hi".utf8))
		#expect(protectResult.consumedTickets == [5])
		log = await identity.log
		#expect(log.last == .consumed(5, "FramedContentTBS"))
		#expect(log.count == 6)
	}

	@Test(
		"identity state is durable before the group artifact, which is durable before transmit"
	)
	func consumeBeforeTransmitAcrossTwoStores() async throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let identity = Identity(signingKey: alice.signingKey)
		let group = try SelfInteropTests.createGroup(alice)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [.proposal(.add(bob.keyPackage))]

		// Positive arm: identity durable, then the group artifact, then transmit.
		let t = try await identity.commit(provider, group: group, proposals: proposals)
		#expect(t.consumedTickets == [0, 1, 2])
		await identity.persistIdentity()
		_ = await identity.notePersistedGroup()  // "the app persists t.group"
		await identity.noteTransmitted()

		let log = await identity.log
		#expect(
			log == [
				.consumed(0, "LeafNodeTBS"), .consumed(1, "FramedContentTBS"),
				.consumed(2, "GroupInfoTBS"),
				.persistedIdentity(through: 2),
				.persistedGroup(1),
				.transmitted,
			])

		// Negative arm: the same commit rebuilt, but this time the group is
		// persisted BEFORE the identity. A crash between the two loses tickets
		// that were minted but never made durable, and the rebuild reissues them.
		let t2 = try await identity.commit(provider, group: group, proposals: proposals)
		#expect(t2.consumedTickets == [3, 4, 5])
		// WRONG order: the group is persisted before the identity.
		_ = await identity.notePersistedGroup()
		// The crash loses the high-water mark: `identity.persistIdentity()`
		// never ran, so the durable mark is still "through 2" and the rebuild
		// below resumes at ticket 3, not 6.
		await identity.simulateCrash()

		let rebuilt = try await identity.commit(
			provider, group: group, proposals: proposals)
		// Collides with `t2`, ticket-for-ticket -- the unsafe reuse.
		#expect(rebuilt.consumedTickets == [3, 4, 5])

		let fullLog = await identity.log
		let ticketCounts = Dictionary(
			grouping: fullLog.compactMap { event -> Int? in
				if case .consumed(let id, _) = event { return id }
				return nil
			}, by: { $0 })
		#expect(ticketCounts[3]?.count == 2)
		#expect(ticketCounts[4]?.count == 2)
		#expect(ticketCounts[5]?.count == 2)
	}

	@Test("a crash before adopting the transition never lets a rebuild reissue a spent ticket")
	func crashRebuildNeverReusesTickets() async throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let identity = Identity(signingKey: alice.signingKey)
		let group = try SelfInteropTests.createGroup(alice)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [.proposal(.add(bob.keyPackage))]

		let dropped = try await identity.commit(
			provider, group: group, proposals: proposals)
		#expect(dropped.consumedTickets == [0, 1, 2])
		await identity.persistIdentity()
		// `dropped` (message, welcome, advancedGroup) is discarded right here,
		// unadopted and untransmitted -- the crash the test name refers to.
		await identity.simulateCrash()

		let rebuilt = try await identity.commit(
			provider, group: group, proposals: proposals)
		#expect(rebuilt.consumedTickets == [3, 4, 5])  // fresh tickets, never 0...2 again.

		let durable = await identity.durable
		#expect(!durable.contains { $0 > 2 })  // 3...5 were never made durable.
		let log = await identity.log
		#expect(!log.contains(.transmitted))  // the dropped commit reached no wire.
	}

	@Test(
		"one identity serializes ticket allocation across two independent, concurrently-driven groups"
	)
	func oneIdentityTwoGroupsMonotone() async throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let identity = Identity(signingKey: alice.signingKey)
		let g1 = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.leafNode, leafSecretKey: alice.leafSecretKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		let g2 = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.leafNode, leafSecretKey: alice.leafSecretKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))

		let operationCount = 8
		let tickets = try await withThrowingTaskGroup(of: [Int].self) { taskGroup in
			for i in 0..<operationCount {
				let target = i.isMultiple(of: 2) ? g1 : g2
				taskGroup.addTask {
					let result = try await identity.protect(
						provider, group: target,
						applicationData: Data("msg-\(i)".utf8))
					return result.consumedTickets
				}
			}
			var all: [Int] = []
			for try await batch in taskGroup { all.append(contentsOf: batch) }
			return all
		}

		#expect(tickets.count == operationCount)
		#expect(Set(tickets) == Set(0..<operationCount))  // no duplicates, none skipped.

		await identity.persistIdentity()
		let durable = await identity.durable
		#expect(durable == Array(0..<operationCount))  // contiguous: monotone, no gaps.
	}

	@Test("archive/restore round-trips the real API; the value it persists never held the key")
	func valueRoundTripHoldsNoKey() async throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let bob = try SelfInteropTests.member("bob")
		let rawSigningKeyBytes = alice.signingKey.data.withUnsafeBytes { Data($0) }
		let identity = Identity(signingKey: alice.signingKey)
		let group = try SelfInteropTests.createGroup(alice)

		let commitResult = try await identity.commit(
			provider, group: group, proposals: [.proposal(.add(bob.keyPackage))])
		let welcome = try #require(commitResult.welcome)
		var bobGroup = try MLS.RFC9420.Group.join(
			provider, welcome: welcome, credentials: bob.joinCredentials,
			psk: { _ in nil })

		let archived = try commitResult.advancedGroup.archive()
		let restored = try MLS.RFC9420.Group.restore(from: archived, provider)
		#expect(restored.context == commitResult.advancedGroup.context)

		// `SecretArchive` deliberately exposes no plaintext byte accessor besides
		// `seal` (which encrypts, so a ciphertext scan would pass whether or not
		// the key were ever present -- not load-bearing). The honest, assertable
		// form of "the group holds no key" is structural: walk the value that
		// feeds `archive()` and confirm the key -- neither its type nor its raw
		// bytes -- appears anywhere in it.
		let found = Self.reachableValues(from: restored)
		#expect(!found.contains { $0 is MLS.SignatureSecretKey })
		let dataLeaves = found.compactMap { $0 as? Data }
		#expect(!dataLeaves.contains(rawSigningKeyBytes))

		let protectResult = try await identity.protect(
			provider, group: restored, applicationData: Data("hi bob".utf8))
		let opened = try bobGroup.unprotect(provider, message: protectResult.message)
		guard case .application(let data) = opened.content else {
			Issue.record("expected application content")
			return
		}
		#expect(data == Data("hi bob".utf8))
	}

	@Test(
		"consumedKeyPackage is context-independent; a replay is only caught by (groupID, epoch)"
	)
	func lastResortReplayKeyedByContextNotKeyPackageRef() throws {
		let provider = Self.provider
		let alice = try SelfInteropTests.member("alice")
		let carol = try SelfInteropTests.member("carol")
		let bob = try SelfInteropTests.member("bob")

		// The SAME KeyPackage, added into two unrelated groups: nothing in
		// `joining` dedups against a global registry (`Group.swift`'s `joining`
		// computes `keyPackageRef` as a pure hash of the KeyPackage, with no
		// cross-group state), so this is the real API, not a faithful variant.
		var groupAlice = try SelfInteropTests.createGroup(alice)
		let addToAlice = try groupAlice.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider))
		var groupCarol = try SelfInteropTests.createGroup(carol)
		let addToCarol = try groupCarol.commit(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: carol.signingKey, randomness: .generate(provider))

		let welcomeAlice = try #require(addToAlice.welcome)
		let welcomeCarol = try #require(addToCarol.welcome)
		let pendingAlice = try MLS.RFC9420.Group.joining(
			provider, welcome: welcomeAlice, credentials: bob.joinCredentials,
			psk: { _ in nil })
		let pendingCarol = try MLS.RFC9420.Group.joining(
			provider, welcome: welcomeCarol, credentials: bob.joinCredentials,
			psk: { _ in nil })
		// A replay of the identical Welcome: the library itself does not refuse it.
		let pendingReplay = try MLS.RFC9420.Group.joining(
			provider, welcome: welcomeAlice, credentials: bob.joinCredentials,
			psk: { _ in nil })

		// The one-time reference is IDENTICAL across all three -- proving it
		// cannot be the replay key, which is this test's point.
		let expectedRef = try bob.keyPackage.reference(provider)
		#expect(pendingAlice.consumedKeyPackage == expectedRef)
		#expect(pendingCarol.consumedKeyPackage == expectedRef)
		#expect(pendingReplay.consumedKeyPackage == expectedRef)

		// A test-side replay map keyed on (groupID, epoch) is what actually
		// distinguishes them: two different groups are both accepted, but the
		// replayed identical Welcome collides with the first.
		struct ReplayKey: Hashable {
			let groupID: Data
			let epoch: UInt64
		}
		func key(_ context: MLS.RFC9420.GroupContext) -> ReplayKey {
			ReplayKey(groupID: context.groupID, epoch: context.epoch)
		}

		var seen: Set<ReplayKey> = []
		#expect(seen.insert(key(pendingAlice.context)).inserted)
		#expect(seen.insert(key(pendingCarol.context)).inserted)
		#expect(key(pendingAlice.context) != key(pendingCarol.context))
		#expect(!seen.insert(key(pendingReplay.context)).inserted)
	}
}
