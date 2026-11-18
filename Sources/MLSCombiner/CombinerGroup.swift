import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSFraming
import MLSProfileRFC9420
import MLSTreeMath
import SecretBytes

extension MLS.Combiner {
	/// One half's creation material for [`CombinerGroup/establish`]: the founder's
	/// own already-signed leaf and its private keys, a pre-generated group id (a
	/// group's id must appear inside its own creation-time `APQInfo`, so it exists
	/// before `create`), the `epochSecret` (RFC 9420 §11's fresh KDF.Nh value) and the
	/// `CommitRandomness` for the founding add-commit, and the peer's `KeyPackage` to
	/// add. The caller supplies this material; the rest of the randomness `establish`
	/// consumes flows through the two providers — the classical `psk_nonce` and each
	/// founding commit's private-framing reuse guard via `randomBytes`, and the
	/// Welcome/UpdatePath encapsulations via `hpkeSeal`, both `CipherSuiteProvider`
	/// requirements — so providers that make those deterministic reproduce
	/// establishment byte-for-byte.
	public struct HalfCreation: Sendable {
		public var groupID: Data
		public var leafNode: MLS.RFC9420.LeafNode
		public var leafSecretKey: MLS.HpkeSecretKey
		public var signingKey: MLS.SignatureSecretKey
		public var epochSecret: SecretBytes
		public var randomness: MLS.RFC9420.Group.CommitRandomness
		public var peerKeyPackage: MLS.RFC9420.KeyPackage

		public init(
			groupID: Data,
			leafNode: MLS.RFC9420.LeafNode,
			leafSecretKey: MLS.HpkeSecretKey,
			signingKey: MLS.SignatureSecretKey,
			epochSecret: SecretBytes,
			randomness: MLS.RFC9420.Group.CommitRandomness,
			peerKeyPackage: MLS.RFC9420.KeyPackage
		) {
			self.groupID = groupID
			self.leafNode = leafNode
			self.leafSecretKey = leafSecretKey
			self.signingKey = signingKey
			self.epochSecret = epochSecret
			self.randomness = randomness
			self.peerKeyPackage = peerKeyPackage
		}
	}

	/// One combiner group's exported per-half state, for persistence. Each half is a
	/// `SecretArchive` (zeroizing; the caller seals it at its own boundary before
	/// storing). The PSK store is deliberately NOT here: it is ephemeral plumbing —
	/// a live `apq_psk` is already folded into the epoch secrets by the commit that
	/// referenced it, so it holds nothing the archived group state does not.
	public struct CombinerGroupState: Sendable {
		public var classical: SecretArchive
		public var pq: SecretArchive

		public init(classical: SecretArchive, pq: SecretArchive) {
			self.classical = classical
			self.pq = pq
		}
	}

	/// What one half of a validated combiner join presents for the application to
	/// adjudicate before adopting the pair — the facts of that half's
	/// `MLS.RFC9420.Group.PendingJoin`, which `CombinerGroup.joining` consumes.
	public struct HalfJoin: Sendable {
		/// The half's members as the Welcome presents them.
		public let roster: [MLS.RFC9420.RosterEntry]
		/// The leaf that signed the half's Welcome (the committer).
		public let signer: MLS.LeafIndex
		/// The one-time KeyPackage this half's join used. Reported whether or not
		/// the application adopts the pair, so a declined join still deletes it.
		public let consumedKeyPackage: MLS.HashReference
		/// The joined half's context — `groupID`, `epoch`, `cipherSuite` — for the
		/// RFC 9420 §12.4.3.1 checks this library leaves to its caller, such as
		/// `group_id` uniqueness among the client's other groups.
		public let context: MLS.RFC9420.GroupContext
		/// The joiner's own leaf in this half.
		public let myLeafIndex: MLS.LeafIndex
	}

	/// A combiner join that passed each half's RFC 9420 join validation and this
	/// module's pair checks but is not yet adopted: the application reads `classical` and `pq`
	/// — the rosters and signers it is about to trust — and adopts with `apply()`
	/// or drops the value to decline. Single-use, like the `PendingJoin`s it
	/// consumes.
	public struct PendingJoinPair: ~Copyable, Sendable {
		public let classical: HalfJoin
		public let pq: HalfJoin
		let group: CombinerGroup

		/// Adopt the pair. Non-throwing: all validation happened in `joining`.
		public consuming func apply() -> CombinerGroup {
			group
		}
	}

	/// The `{classical, PQ}` group pair of draft-ietf-mls-combiner-02 (§4/§6): two
	/// RFC 9420 groups whose classical (message) half is bound to the PQ half's
	/// secrecy by an exported `apq_psk`. Application messages ride the classical half;
	/// the PQ half is the side channel that injects post-quantum secrecy.
	///
	/// This is the draft-generic pair: PQ-first establishment and join, `APQInfo`
	/// pair verification, and membership consistency (§4.2.1). The Germ deviations
	/// (the deferred-half A.3 bootstrap, the PQ ratchets, the 2-party operation rules,
	/// the directional send groups, and the session persistence model) are downstream.
	public struct CombinerGroup: Sendable {
		public internal(set) var classical: MLS.RFC9420.Group
		public internal(set) var pq: MLS.RFC9420.Group
		/// The store `establish`/`joining` resolve the founding `apq_psk` from while
		/// building the pair. Empty on every `CombinerGroup` this module returns:
		/// `establish` and `joining` each forget the `apq_psk` once its commit or
		/// Welcome has folded it, and `restore` never populates one either — there
		/// is nothing left here for a caller to read, and the setter is `internal`
		/// besides.
		public internal(set) var pskStore: PSKStore
		public let codepoints: Codepoints
		// The memberwise initializer is intentionally internal (synthesized): a
		// `CombinerGroup` is produced only by `establish` / `joining` / `join` / `restore`.
	}
}

extension MLS.Combiner.CombinerGroup {
	/// Establish a new combiner group and add one peer to each half (PQ-first,
	/// draft §4 / §6.2). The pair's two group ids are named in each half's
	/// creation-time `APQInfo`, so both halves land at epoch 1 as a structurally-FULL
	/// creation carrying the `{1, 1}` `AppDataUpdate` attestation:
	///
	/// 1. build `APQInfo{ids, mode, suites, 1, 1}` and create the **PQ** half with it,
	///    committing the PQ peer + the attestation → PQ epoch 1;
	/// 2. export the `apq_psk` off the PQ half's epoch-1 exporter and register it;
	/// 3. create the **classical** half with the same `APQInfo`, committing the
	///    classical peer + a `PreSharedKey` referencing the `apq_psk` + the attestation
	///    → classical epoch 1.
	///
	/// Both founding commits carry no `UpdatePath`: `createAndAdd` adds the peer in
	/// the commit immediately following the group's creation, so there is no gap for a
	/// path to cover.
	///
	/// Returns the pair and the logical `APQWelcome{t, pq}`; the caller frames it (the
	/// draft §7 codec, or twomlspq-swift's own framing). Runs under the codepoints'
	/// component-id wire width so the `apq_psk` `PreSharedKeyID` and the `AppDataUpdate`
	/// proposal encode at the deployed width.
	///
	/// `classicalExtraExtensions` are caller-supplied creation-time GroupContext
	/// extensions (RFC 9420 §11.1) appended after the combiner's own `APQInfo` on the
	/// classical half only — the classical half is the message half, so that is where
	/// application-defined creation-time extensions belong. They are not threaded onto
	/// the PQ half. Defaults to empty, so existing callers are unaffected. A type
	/// repeated among them, or equal to the `APQInfo` extension type, throws
	/// `duplicateExtensionType` (RFC 9420 §13.4).
	///
	/// The halves must be distinct sessions (`halvesNotDistinct`: equal cipher suites
	/// or group ids) and carry the same members (`membershipInconsistent`: the
	/// founder and peer identities differ across halves, or any of those credentials
	/// is not Basic); both are checked before either half is built.
	public static func establish(
		classical: MLS.Combiner.HalfCreation,
		pq: MLS.Combiner.HalfCreation,
		mode: UInt8,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		classicalExtraExtensions: [MLS.RFC9420.Extension] = [],
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (group: MLS.Combiner.CombinerGroup, welcome: MLS.Combiner.APQWelcome) {
		try codepoints.withWireWidth {
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: classical.groupID,
				pqSessionGroupID: pq.groupID,
				mode: mode,
				tCipherSuite: classicalProvider.cipherSuite,
				pqCipherSuite: pqProvider.cipherSuite,
				tEpoch: 1,
				pqEpoch: 1)
			guard info.namesDistinctHalves else {
				throw MLS.Combiner.Error.halvesNotDistinct
			}
			try checkMembershipConsistent(
				[classical.leafNode.credential, classical.peerKeyPackage.leafNode.credential],
				[pq.leafNode.credential, pq.peerKeyPackage.leafNode.credential])
			let infoExtension = try info.asExtension(
				type: codepoints.apqInfoExtensionType)
			// Compare by rawValue, not by ExtensionType itself: ExtensionType's
			// synthesized Equatable/Hashable treats `.known` and `.unknown` at the
			// same code point as distinct, so a Set<ExtensionType> would miss a
			// hand-built `.unknown` duplicating a `.known` type's wire value.
			let classicalExtensions = [infoExtension] + classicalExtraExtensions
			var seenExtensionTypes: Set<UInt16> = []
			for classicalExtension in classicalExtensions {
				guard
					seenExtensionTypes.insert(classicalExtension.type.rawValue)
						.inserted
				else {
					throw MLS.Combiner.Error.duplicateExtensionType(
						MLS.RFC9420.ExtensionType(
							rawValue: classicalExtension.type.rawValue))
				}
			}

			let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 1)
			let attestationProposal = MLS.RFC9420.ProposalOrRef.proposal(
				try attestation.proposal(componentID: codepoints.apqComponentID))

			// PQ half first, unbound.
			let (pqGroup, pqWelcome) = try createAndAdd(
				pqProvider, creation: pq, extensions: [infoExtension],
				extraProposals: [attestationProposal],
				pskStore: MLS.Combiner.PSKStore())

			// apq_psk: export from the PQ half, inject into the classical half.
			var pqGroupForExport = pqGroup
			let apqPsk = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroupForExport, pqProvider,
				componentID: codepoints.apqComponentID)
			var store = MLS.Combiner.PSKStore()
			store.register(apqPsk)

			let nonce = classicalProvider.randomBytes(classicalProvider.hashSize)
			let (classicalGroup, classicalWelcome) = try createAndAdd(
				classicalProvider, creation: classical,
				extensions: classicalExtensions,
				extraProposals: [
					.proposal(apqPsk.proposal(nonce: nonce)),
					attestationProposal,
				],
				pskStore: store)

			guard let pqWelcome, let classicalWelcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			store.forget(storageID: apqPsk.storageID)
			let group = MLS.Combiner.CombinerGroup(
				classical: classicalGroup, pq: pqGroupForExport, pskStore: store,
				codepoints: codepoints)
			return (
				group,
				MLS.Combiner.APQWelcome(
					tWelcome: classicalWelcome, pqWelcome: pqWelcome)
			)
		}
	}

	/// Create a one-member group carrying `extensions` and commit the peer add plus
	/// `extraProposals` (the `apq_psk` reference and/or the `AppDataUpdate`
	/// attestation) as the founding commit; returns the group at epoch 1 and the
	/// added member's Welcome. The two-step handshake: adopt the `committing`
	/// transition's group, then apply the pending advance onto it.
	///
	/// The read-`group`-then-`takeOutput()` handoff on `Transition` (a
	/// non-frozen `~Copyable` struct) trips a Swift 6.4.0 optimizer bug under
	/// `-O` — SIL verification fails with "read-only scope invalidated by a
	/// local write" once a public caller makes this function a specialization
	/// target (the swiftlang/swift#86147 family; #86178's verifier relaxation
	/// covered only the `destroy_addr` form, and the crash reproduces only
	/// cross-compiling for Android). These are one-shot handshake
	/// orchestration paths, so opt them out of optimization.
	@_optimize(none)
	private static func createAndAdd(
		_ provider: any MLS.CipherSuiteProvider,
		creation: MLS.Combiner.HalfCreation,
		extensions: [MLS.RFC9420.Extension],
		extraProposals: [MLS.RFC9420.ProposalOrRef],
		pskStore: MLS.Combiner.PSKStore
	) throws -> (group: MLS.RFC9420.Group, welcome: MLS.RFC9420.Welcome?) {
		let epoch0 = try MLS.RFC9420.Group.create(
			provider, groupID: creation.groupID, leafNode: creation.leafNode,
			leafSecretKey: creation.leafSecretKey, extensions: extensions,
			epochSecret: creation.epochSecret)
		let transition = try epoch0.committing(
			provider,
			proposals: [.proposal(.add(creation.peerKeyPackage))] + extraProposals,
			signingKey: creation.signingKey, randomness: creation.randomness,
			includePath: false,
			psk: pskStore.resolver())
		let adopted = transition.group
		let sent = transition.takeOutput()
		let welcome = sent.welcome
		let advanced = try sent.takePending().apply(onto: adopted)
		return (advanced.group, welcome)
	}

	/// Validate a combiner join from an `APQWelcome` without adopting it (PQ-first,
	/// draft §4 / §4.2.1): join the PQ half, re-derive and register the same
	/// `apq_psk` off it, join the classical half bound by that PSK, then verify the
	/// `APQInfo` pair and that both halves' rosters carry the same members. The
	/// result is a `PendingJoinPair`, so the application can adjudicate both halves'
	/// rosters and signers before `apply()`. `JoinerCredentials` are the joiner's own
	/// key material per half (never on the wire).
	///
	/// A throw reports neither consumed KeyPackage, yet either half's Welcome may
	/// already have been opened with its KeyPackage — the PQ half's is opened before
	/// the classical half or any pair check can fail. The caller supplied both and
	/// decides whether to burn them.
	public static func joining(
		welcome: MLS.Combiner.APQWelcome,
		classicalCredentials: MLS.RFC9420.Group.JoinerCredentials,
		pqCredentials: MLS.RFC9420.Group.JoinerCredentials,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.Combiner.PendingJoinPair {
		let (classical, pq, group) = try codepoints.withWireWidth {
			// PQ half first, resolving no PSK (its creation commit bound none).
			let pqPending = try MLS.RFC9420.Group.joining(
				pqProvider, welcome: welcome.pqWelcome, credentials: pqCredentials,
				psk: { _ in nil })
			let pqJoin = MLS.Combiner.HalfJoin(
				roster: pqPending.roster, signer: pqPending.signer,
				consumedKeyPackage: pqPending.consumedKeyPackage,
				context: pqPending.context, myLeafIndex: pqPending.myLeafIndex)
			// Applied here, not at `PendingJoinPair.apply()`: the `apq_psk` below is
			// exported from this group. Nothing is adopted until the pair is applied.
			var pqGroup = pqPending.apply().group

			// Re-derive the same apq_psk the creator bound the classical half with.
			let apqPsk = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider, componentID: codepoints.apqComponentID)
			var store = MLS.Combiner.PSKStore()
			store.register(apqPsk)

			// Recording, not the plain resolver: a non-conforming classical Welcome
			// can carry `APQInfo` + the epoch attestation without ever referencing the
			// `apq_psk` in a PreSharedKey proposal, in which case `joining` below
			// succeeds having resolved nothing — the guard after it is what catches
			// that (draft-ietf-mls-combiner-02 §6.2: the T commit MUST include the PSK
			// proposal; §4.1 describes it).
			let (resolver, record) = store.recordingResolver()
			let classicalPending = try MLS.RFC9420.Group.joining(
				classicalProvider, welcome: welcome.tWelcome,
				credentials: classicalCredentials, psk: resolver)
			// Resolution happens inside `joining` itself, so the record is already
			// complete here — fail fast, before the (pure value) `apply()` below.
			guard record.resolved(apqPsk.storageID) else {
				throw MLS.Combiner.Error.apqPskNotBound
			}
			let classicalJoin = MLS.Combiner.HalfJoin(
				roster: classicalPending.roster, signer: classicalPending.signer,
				consumedKeyPackage: classicalPending.consumedKeyPackage,
				context: classicalPending.context,
				myLeafIndex: classicalPending.myLeafIndex)
			let classicalGroup = classicalPending.apply().group

			store.forget(storageID: apqPsk.storageID)
			let group = MLS.Combiner.CombinerGroup(
				classical: classicalGroup, pq: pqGroup, pskStore: store,
				codepoints: codepoints)
			try group.verifyPair()
			try MLS.Combiner.CombinerGroup.checkMembershipConsistent(
				classicalJoin.roster.map(\.presentation.credential),
				pqJoin.roster.map(\.presentation.credential))
			return (classicalJoin, pqJoin, group)
		}
		return MLS.Combiner.PendingJoinPair(classical: classical, pq: pq, group: group)
	}

	/// Join both halves of a combiner group and adopt them at once:
	/// `joining(...)` followed by `apply()`, for callers that do no adjudication of
	/// their own.
	public static func join(
		welcome: MLS.Combiner.APQWelcome,
		classicalCredentials: MLS.RFC9420.Group.JoinerCredentials,
		pqCredentials: MLS.RFC9420.Group.JoinerCredentials,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.Combiner.CombinerGroup {
		try joining(
			welcome: welcome, classicalCredentials: classicalCredentials,
			pqCredentials: pqCredentials, classicalProvider: classicalProvider,
			pqProvider: pqProvider, codepoints: codepoints
		).apply()
	}
}

extension MLS.Combiner.CombinerGroup {
	/// draft §6 joiner verification for a full pair (both halves at their join epoch):
	/// each half carries an `APQInfo`; the identity fields (group ids, mode, suites)
	/// agree across halves; the halves are distinct sessions; each names the group
	/// and cipher suite it actually rides in; and each epoch field matches the
	/// observed epoch. Suite *validity* is not judged (a downstream, Germ-suite
	/// concern) — only that the stated suites are the real, distinct ones.
	public func verifyPair() throws {
		guard
			let classicalInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: classical.context,
				type: codepoints.apqInfoExtensionType),
			let pqInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pq.context, type: codepoints.apqInfoExtensionType)
		else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		try MLS.Combiner.CombinerGroup.checkAPQInfoConsistent(
			classicalInfo: classicalInfo, pqInfo: pqInfo,
			classicalObserved: (
				groupID: classical.context.groupID, epoch: classical.context.epoch,
				cipherSuite: classical.context.cipherSuite
			),
			pqObserved: (
				groupID: pq.context.groupID, epoch: pq.context.epoch,
				cipherSuite: pq.context.cipherSuite
			))
	}

	/// The pure half of `verifyPair`: identity-fields agreement across the two decoded
	/// `APQInfo` copies, the halves being distinct sessions, each copy naming the
	/// group and cipher suite it actually rides in, and each epoch field matching the
	/// half's observed epoch — split one clause per guard so a single-field mismatch
	/// (e.g. a stale `pqEpoch`) is independently testable.
	///
	/// The suite-truthfulness clauses are this module's enforcement of
	/// draft-ietf-mls-combiner-02, not of a quoted MUST: §8.1 says the choice of
	/// primitives "must be explicitly stated by the CipherSuite objects within
	/// APQInfo", and §4.2.1 requires the `APQInfo` indicating "the GroupID and
	/// ciphersuites of the two sessions" in the Welcome "in order to validate joining
	/// the combined sessions". An `APQInfo` stating suites the groups do not run
	/// states nothing true.
	///
	/// `observed` is `(groupID, epoch, cipherSuite)` read off each half's live
	/// `GroupContext`, so the check itself takes no `Group` and is exercisable
	/// against hand-built values.
	static func checkAPQInfoConsistent(
		classicalInfo: MLS.Combiner.APQInfo,
		pqInfo: MLS.Combiner.APQInfo,
		classicalObserved: (groupID: Data, epoch: UInt64, cipherSuite: MLS.CipherSuite),
		pqObserved: (groupID: Data, epoch: UInt64, cipherSuite: MLS.CipherSuite)
	) throws {
		guard classicalInfo.identityFieldsMatch(pqInfo) else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.namesDistinctHalves else {
			throw MLS.Combiner.Error.halvesNotDistinct
		}
		guard classicalInfo.tSessionGroupID == classicalObserved.groupID,
			classicalInfo.pqSessionGroupID == pqObserved.groupID
		else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.tCipherSuite == classicalObserved.cipherSuite else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.pqCipherSuite == pqObserved.cipherSuite else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.tEpoch == classicalObserved.epoch else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard pqInfo.pqEpoch == pqObserved.epoch else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.pqEpoch == pqObserved.epoch else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
	}

	/// draft §4.2.1: both halves' member sets — each member's Basic-credential
	/// identifier — must be equal. Deliberately no roster-*size* constraint: the
	/// `== 2` two-party restriction is downstream policy, not the draft's consistency
	/// requirement, which is about equality of the two sessions' membership. Takes
	/// credentials rather than roster entries so `establish` can check the members
	/// it is about to create (from its `HalfCreation`s) and `join` the members its
	/// Welcomes present.
	static func checkMembershipConsistent(
		_ a: [MLS.RFC9420.Credential], _ b: [MLS.RFC9420.Credential]
	) throws {
		func basicIdentifiers(_ credentials: [MLS.RFC9420.Credential]) throws -> [Data] {
			try credentials.map { credential in
				guard case .basic(let identity) = credential
				else {
					throw MLS.Combiner.Error.membershipInconsistent
				}
				return identity
			}
			.sorted { $0.lexicographicallyPrecedes($1) }
		}
		guard try basicIdentifiers(a) == basicIdentifiers(b) else {
			throw MLS.Combiner.Error.membershipInconsistent
		}
	}
}

extension MLS.Combiner.CombinerGroup {
	/// Export both halves' state for persistence (each a zeroizing `SecretArchive`
	/// the caller seals). The PSK store is not exported (ephemeral).
	public func exportState() throws -> MLS.Combiner.CombinerGroupState {
		MLS.Combiner.CombinerGroupState(
			classical: try classical.archive(), pq: try pq.archive())
	}

	/// Rebuild a combiner group from exported state, with a fresh (empty) PSK store —
	/// a live `apq_psk` is already folded into the archived epoch secrets.
	public static func restore(
		from state: MLS.Combiner.CombinerGroupState,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.Combiner.CombinerGroup {
		MLS.Combiner.CombinerGroup(
			classical: try MLS.RFC9420.Group.restore(
				from: state.classical, classicalProvider),
			pq: try MLS.RFC9420.Group.restore(from: state.pq, pqProvider),
			pskStore: MLS.Combiner.PSKStore(),
			codepoints: codepoints)
	}
}
