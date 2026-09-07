import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

extension MLS.Combiner {
	/// One half's creation material for [`CombinerGroup/establish`]: the founder's
	/// own already-signed leaf and its private keys, a pre-generated group id (a
	/// group's id must appear inside its own creation-time `APQInfo`, so it exists
	/// before `create`), the `epochSecret` (RFC 9420 §11's fresh KDF.Nh value) and the
	/// `CommitRandomness` for the founding add-commit, and the peer's `KeyPackage` to
	/// add. The caller owns all randomness — nothing is generated inside the combiner,
	/// so establishment is byte-for-byte reproducible.
	public struct HalfCreation: Sendable {
		public var groupID: Data
		public var leafNode: MLS.RFC9420.LeafNode
		public var leafSecretKey: MLS.HpkeSecretKey
		public var signingKey: MLS.SignatureSecretKey
		public var epochSecret: Data
		public var randomness: MLS.RFC9420.Group.CommitRandomness
		public var peerKeyPackage: MLS.RFC9420.KeyPackage

		public init(
			groupID: Data,
			leafNode: MLS.RFC9420.LeafNode,
			leafSecretKey: MLS.HpkeSecretKey,
			signingKey: MLS.SignatureSecretKey,
			epochSecret: Data,
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
		/// The values `application` PSK references in the two halves' commits/joins
		/// resolve from. Held here, not on either half — the profile resolves PSKs by
		/// a caller closure, and a construction-time `apq_psk` must outlive any client
		/// rotation.
		public internal(set) var pskStore: PSKStore
		public let codepoints: Codepoints
		// The memberwise initializer is intentionally internal (synthesized): a
		// `CombinerGroup` is produced only by `establish` / `join` / `restore`.
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
	/// Returns the pair and the logical `APQWelcome{t, pq}`; the caller frames it (the
	/// draft §7 codec, or twomlspq-swift's own framing). Runs under the codepoints'
	/// component-id wire width so the `apq_psk` `PreSharedKeyID` and the `AppDataUpdate`
	/// proposal encode at the deployed width.
	public static func establish(
		classical: MLS.Combiner.HalfCreation,
		pq: MLS.Combiner.HalfCreation,
		mode: UInt8,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
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
			let infoExtension = try info.asExtension(
				type: codepoints.apqInfoExtensionType)
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
				classicalProvider, creation: classical, extensions: [infoExtension],
				extraProposals: [
					.proposal(apqPsk.proposal(nonce: nonce)),
					attestationProposal,
				],
				pskStore: store)

			guard let pqWelcome, let classicalWelcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
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
			psk: pskStore.resolver())
		let adopted = transition.group
		let sent = transition.takeOutput()
		let welcome = sent.welcome
		let advanced = try sent.takePending().apply(onto: adopted)
		return (advanced.group, welcome)
	}

	/// Join both halves of a combiner group from an `APQWelcome` (PQ-first, draft §4 /
	/// §4.2.1): join the PQ half, re-derive and register the same `apq_psk` off it,
	/// join the classical half bound by that PSK, then verify the `APQInfo` pair and
	/// that both halves' rosters carry the same members. `JoinerCredentials` are the
	/// joiner's own key material per half (never on the wire).
	public static func join(
		welcome: MLS.Combiner.APQWelcome,
		classicalCredentials: MLS.RFC9420.Group.JoinerCredentials,
		pqCredentials: MLS.RFC9420.Group.JoinerCredentials,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.Combiner.CombinerGroup {
		try codepoints.withWireWidth {
			// PQ half first, resolving no PSK (its creation commit bound none).
			let pqPending = try MLS.RFC9420.Group.joining(
				pqProvider, welcome: welcome.pqWelcome, credentials: pqCredentials,
				psk: { _ in nil })
			let pqRoster = pqPending.roster
			var pqGroup = pqPending.apply().group

			// Re-derive the same apq_psk the creator bound the classical half with.
			let apqPsk = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider, componentID: codepoints.apqComponentID)
			var store = MLS.Combiner.PSKStore()
			store.register(apqPsk)

			let classicalPending = try MLS.RFC9420.Group.joining(
				classicalProvider, welcome: welcome.tWelcome,
				credentials: classicalCredentials, psk: store.resolver())
			let classicalRoster = classicalPending.roster
			let classicalGroup = classicalPending.apply().group

			let group = MLS.Combiner.CombinerGroup(
				classical: classicalGroup, pq: pqGroup, pskStore: store,
				codepoints: codepoints)
			try group.verifyPair()
			try MLS.Combiner.CombinerGroup.checkMembershipConsistent(
				classicalRoster, pqRoster)
			return group
		}
	}
}

extension MLS.Combiner.CombinerGroup {
	/// draft §6 joiner verification for a full pair (both halves at their join epoch):
	/// each half carries an `APQInfo`; the identity fields (group ids, mode, suites)
	/// agree across halves; each names the actual joined group; and each epoch field
	/// matches the observed epoch. Suite *validity* is not judged (a downstream,
	/// Germ-suite concern) — only equality across the halves.
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
				groupID: classical.context.groupID, epoch: classical.context.epoch
			),
			pqObserved: (groupID: pq.context.groupID, epoch: pq.context.epoch))
	}

	/// The pure half of `verifyPair`: identity-fields agreement across the two decoded
	/// `APQInfo` copies, each naming the group it actually rides in, and each epoch
	/// field matching the half's observed epoch — split one clause per guard so a
	/// single-field mismatch (e.g. a stale `pqEpoch`) is independently testable.
	/// `observed` is `(groupID, epoch)` read off each half's live `GroupContext`, so
	/// the check itself takes no `Group` and is exercisable against hand-built values.
	static func checkAPQInfoConsistent(
		classicalInfo: MLS.Combiner.APQInfo,
		pqInfo: MLS.Combiner.APQInfo,
		classicalObserved: (groupID: Data, epoch: UInt64),
		pqObserved: (groupID: Data, epoch: UInt64)
	) throws {
		guard classicalInfo.identityFieldsMatch(pqInfo) else {
			throw MLS.Combiner.Error.apqInfoMismatch
		}
		guard classicalInfo.tSessionGroupID == classicalObserved.groupID,
			classicalInfo.pqSessionGroupID == pqObserved.groupID
		else {
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
	/// requirement, which is about equality of the two sessions' membership. Rosters
	/// are captured at join (the profile surfaces members only at join / per commit),
	/// which is where §4.2.1's "after a join" check belongs.
	static func checkMembershipConsistent(
		_ a: [MLS.RFC9420.RosterEntry], _ b: [MLS.RFC9420.RosterEntry]
	) throws {
		func basicIdentifiers(_ roster: [MLS.RFC9420.RosterEntry]) throws -> [Data] {
			try roster.map { entry in
				guard case .basic(let identity) = entry.presentation.credential
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
