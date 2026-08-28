#if os(macOS) || os(Linux)
import Crypto
import Foundation
import GRPCCore
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSKeySchedule
import MLSProfileRFC9420
import MLSTreeKEM
import MLSTreeMath

/// The mlswg `MLSClient` service backed by `MLS.RFC9420`.
///
/// Scope: the group lifecycle this library implements — create, key
/// package, join, {add,update,remove,PSK,GCE} proposal, commit, handle
/// commit, protect/unprotect, PSK storage. Out-of-scope RPCs (ReInit,
/// branch, external join/signers, new-member add) answer `ABORTED
/// "unsupported"`, matching mls-rs's convention so the runner's output is
/// comparable. Run with the runner's `--public` handshake mode: this
/// server frames handshakes as PublicMessage (private-handshake *sending*
/// is deferred — see phase 7a).
@available(macOS 15, *)
final actor MLSInteropService: MlsClient_MLSClient.SimpleServiceProtocol {
	private let provider = SwiftCryptoProvider()

	/// One flat registry, as mls-rs uses: a transaction id (from
	/// `CreateKeyPackage`, awaiting a `JoinGroup`) and a state id (a live
	/// group) share the space, so `JoinGroup` finds its credentials by the
	/// transaction id the runner threads through.
	private enum Entry {
		case pendingJoin(Credentials)
		case group(ClientState)
	}
	private struct Credentials {
		var keyPackage: MLS.RFC9420.KeyPackage
		var initKey: MLS.HpkeSecretKey
		var encryptionKey: MLS.HpkeSecretKey
		var signingKey: MLS.SignatureSecretKey
		var suite: MLS.CipherSuite
	}
	private struct ClientState {
		var group: MLS.RFC9420.Group
		var credentials: Credentials
		var pending: MLS.RFC9420.Group.CommitOutput?
	}

	private var entries: [UInt32: Entry] = [:]
	private var externalPsks: [Data: Data] = [:]
	private var nextID: UInt32 = 1

	private func allocate() -> UInt32 {
		defer { nextID &+= 1 }
		return nextID
	}

	private func suiteProvider(_ id: UInt32) throws -> any MLS.CipherSuiteProvider {
		guard
			let p = provider.cipherSuiteProvider(
				for: .init(id: UInt16(truncatingIfNeeded: id)))
		else { throw unsupported("cipher suite \(id)") }
		return p
	}

	private func unsupported(_ what: String) -> RPCError {
		RPCError(code: .aborted, message: "unsupported: \(what)")
	}
	private func invalid(_ what: String) -> RPCError {
		RPCError(code: .invalidArgument, message: what)
	}

	/// A fresh signing key pair in the representation the provider's
	/// `sign`/`verify` expect for `suite` — Ed25519 uses `rawRepresentation`
	/// for both halves, the NIST curves use `rawRepresentation` for the
	/// private half and `x963Representation` for the public (see
	/// `SwiftCryptoProvider`). Generated here rather than via the provider
	/// because RFC 9420's core protocol never needs signature keygen, so
	/// `CipherSuiteProvider` deliberately exposes none.
	private static func signingKeyPair(for suite: MLS.CipherSuite)
		-> (MLS.SignatureSecretKey, MLS.SignaturePublicKey)
	{
		switch suite.id {
		case 2:
			let k = P256.Signing.PrivateKey()
			return (
				.init(k.rawRepresentation), .init(k.publicKey.x963Representation)
			)
		case 7:
			let k = P384.Signing.PrivateKey()
			return (
				.init(k.rawRepresentation), .init(k.publicKey.x963Representation)
			)
		case 5:
			let k = P521.Signing.PrivateKey()
			return (
				.init(k.rawRepresentation), .init(k.publicKey.x963Representation)
			)
		default:  // 1, 3 -- Ed25519
			let k = Curve25519.Signing.PrivateKey()
			return (
				.init(k.rawRepresentation), .init(k.publicKey.rawRepresentation)
			)
		}
	}

	/// A `key_package`-sourced, signed leaf + KeyPackage for `identity`.
	private func makeCredentials(
		suite: MLS.CipherSuite, identity: Data,
		_ p: any MLS.CipherSuiteProvider
	) throws -> Credentials {
		let (signingKey, signatureKey) = Self.signingKeyPair(for: suite)
		let (leafSecret, leafPublic) = try p.hpkeGenerateKeyPair()
		let (initSecret, initPublic) = try p.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublic, signatureKey: signatureKey,
			credential: .basic(identity: identity),
			capabilities: .init(
				versions: [.mls10], cipherSuites: [suite], extensions: [],
				proposals: [], credentials: [.init(.basic)]),
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			p, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: suite, initKey: initPublic,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			p, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return Credentials(
			keyPackage: keyPackage, initKey: initSecret,
			encryptionKey: leafSecret, signingKey: signingKey,
			suite: suite)
	}

	private func encoded(_ message: MLS.RFC9420.Message) throws -> Data {
		var writer = MLS.Writer()
		try message.encode(to: &writer)
		return Data(writer.bytes)
	}

	private func requireGroup(_ id: UInt32) throws -> ClientState {
		guard case .group(let state) = entries[id] else {
			throw invalid("no group for state id \(id)")
		}
		return state
	}

	/// The roster helper the runner needs: a BasicCredential identity →
	/// leaf index, over the current tree.
	private func leafIndex(
		ofIdentity identity: Data, in group: MLS.RFC9420.Group
	) throws -> MLS.LeafIndex {
		for (index, record) in group.tree.nonBlankLeaves() {
			let leaf = try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
			if case .basic(let id) = leaf.credential, id == identity { return index }
		}
		throw invalid("no member with the given identity")
	}

	// MARK: - Metadata

	func name(request: MlsClient_NameRequest, context: ServerContext)
		async throws -> MlsClient_NameResponse
	{
		var r = MlsClient_NameResponse()
		r.name = "swift-mls"
		return r
	}

	func supportedCiphersuites(
		request: MlsClient_SupportedCiphersuitesRequest, context: ServerContext
	) async throws -> MlsClient_SupportedCiphersuitesResponse {
		var r = MlsClient_SupportedCiphersuitesResponse()
		r.ciphersuites = provider.supportedCipherSuites.map { UInt32($0.id) }
		return r
	}

	// MARK: - Group entry

	func createGroup(request: MlsClient_CreateGroupRequest, context: ServerContext)
		async throws -> MlsClient_CreateGroupResponse
	{
		let p = try suiteProvider(request.cipherSuite)
		let suite = MLS.CipherSuite(id: UInt16(truncatingIfNeeded: request.cipherSuite))
		let creds = try makeCredentials(suite: suite, identity: request.identity, p)
		let group = try MLS.RFC9420.Group.create(
			p, groupID: request.groupID, leafNode: creds.keyPackage.leafNode,
			leafSecretKey: creds.encryptionKey,
			epochSecret: p.randomBytes(p.hashSize))
		let id = allocate()
		entries[id] = .group(ClientState(group: group, credentials: creds, pending: nil))
		var r = MlsClient_CreateGroupResponse()
		r.stateID = id
		return r
	}

	func createKeyPackage(
		request: MlsClient_CreateKeyPackageRequest, context: ServerContext
	) async throws -> MlsClient_CreateKeyPackageResponse {
		let p = try suiteProvider(request.cipherSuite)
		let suite = MLS.CipherSuite(id: UInt16(truncatingIfNeeded: request.cipherSuite))
		let creds = try makeCredentials(suite: suite, identity: request.identity, p)
		let id = allocate()
		entries[id] = .pendingJoin(creds)
		var r = MlsClient_CreateKeyPackageResponse()
		r.transactionID = id
		r.keyPackage = try encoded(.keyPackage(creds.keyPackage))
		r.initPriv = creds.initKey.data
		r.encryptionPriv = creds.encryptionKey.data
		r.signaturePriv = creds.signingKey.data
		return r
	}

	func joinGroup(request: MlsClient_JoinGroupRequest, context: ServerContext)
		async throws -> MlsClient_JoinGroupResponse
	{
		guard case .pendingJoin(let creds) = entries[request.transactionID] else {
			throw invalid(
				"no pending key package for transaction \(request.transactionID)")
		}
		let p = try suiteProvider(UInt32(creds.suite.id))
		var welcomeReader = MLS.Reader(request.welcome)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(from: &welcomeReader)
		else { throw invalid("welcome is not an mls_welcome message") }

		var externalTree: [MLS.RFC9420.Node?]?
		if !request.ratchetTree.isEmpty {
			var treeReader = MLS.Reader(request.ratchetTree)
			externalTree = try treeReader.decodeVector()
		}
		let group = try MLS.RFC9420.Group.join(
			p, welcome: welcome,
			credentials: .init(
				keyPackage: creds.keyPackage, initKey: creds.initKey,
				encryptionKey: creds.encryptionKey),
			externalTree: externalTree,
			psk: { [externalPsks] id in
				guard case .external(let pskID, _) = id else { return nil }
				return externalPsks[pskID]
			})
		let id = allocate()
		entries[id] = .group(ClientState(group: group, credentials: creds, pending: nil))
		var r = MlsClient_JoinGroupResponse()
		r.stateID = id
		r.epochAuthenticator = group.epoch.epochAuthenticator
		return r
	}

	// MARK: - Proposals (public-framed)

	private func frameProposal(
		_ proposal: MLS.RFC9420.Proposal, state: ClientState,
		_ p: any MLS.CipherSuiteProvider
	) throws -> Data {
		let content = MLS.RFC9420.FramedContent(
			groupID: state.group.context.groupID, epoch: state.group.context.epoch,
			sender: .member(state.group.myLeafIndex), authenticatedData: Data(),
			content: .proposal(proposal))
		let message = try MLS.RFC9420.protectPublic(
			p, content: content, groupContext: state.group.context,
			confirmationTag: nil, signingKey: state.credentials.signingKey,
			membershipKey: state.group.epoch.membershipKey)
		return try encoded(.publicMessage(message))
	}

	func addProposal(request: MlsClient_AddProposalRequest, context: ServerContext)
		async throws -> MlsClient_ProposalResponse
	{
		let state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		var kpReader = MLS.Reader(request.keyPackage)
		guard case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(from: &kpReader)
		else { throw invalid("not a key package") }
		var r = MlsClient_ProposalResponse()
		r.proposal = try frameProposal(.add(keyPackage), state: state, p)
		return r
	}

	func updateProposal(request: MlsClient_UpdateProposalRequest, context: ServerContext)
		async throws -> MlsClient_ProposalResponse
	{
		throw unsupported("UpdateProposal (updater key-handoff deferred)")
	}

	func removeProposal(request: MlsClient_RemoveProposalRequest, context: ServerContext)
		async throws -> MlsClient_ProposalResponse
	{
		let state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		let removed = try leafIndex(ofIdentity: request.removedID, in: state.group)
		var r = MlsClient_ProposalResponse()
		r.proposal = try frameProposal(.remove(removed), state: state, p)
		return r
	}

	func externalPSKProposal(
		request: MlsClient_ExternalPSKProposalRequest, context: ServerContext
	) async throws -> MlsClient_ProposalResponse {
		let state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		let proposal = MLS.RFC9420.Proposal.preSharedKey(
			.external(pskID: request.pskID, nonce: p.randomBytes(p.hashSize)))
		var r = MlsClient_ProposalResponse()
		r.proposal = try frameProposal(proposal, state: state, p)
		return r
	}

	func resumptionPSKProposal(
		request: MlsClient_ResumptionPSKProposalRequest, context: ServerContext
	) async throws -> MlsClient_ProposalResponse {
		throw unsupported("ResumptionPSKProposal (reinit/branch deferred)")
	}

	func groupContextExtensionsProposal(
		request: MlsClient_GroupContextExtensionsProposalRequest, context: ServerContext
	) async throws -> MlsClient_ProposalResponse {
		let state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		var extensions: [MLS.RFC9420.Extension] = []
		for ext in request.extensions {
			extensions.append(
				.init(
					type: .init(
						rawValue: UInt16(
							truncatingIfNeeded: ext.extensionType)),
					data: ext.extensionData))
		}
		var r = MlsClient_ProposalResponse()
		r.proposal = try frameProposal(
			.groupContextExtensions(extensions), state: state, p)
		return r
	}

	// MARK: - Commit / handle

	private func proposalStore(
		from proposalBytes: [Data], _ p: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.ProposalStore {
		var store: MLS.RFC9420.ProposalStore = [:]
		for bytes in proposalBytes {
			var reader = MLS.Reader(bytes)
			guard
				case .publicMessage(let message) = try MLS.RFC9420.Message(
					from: &reader),
				case .proposal(let proposal) = message.content.content
			else { throw invalid("stored proposal is not a public proposal message") }
			let content = MLS.RFC9420.AuthenticatedContent(
				wireFormat: .publicMessage, content: message.content,
				auth: message.auth)
			store[try MLS.RFC9420.proposalRef(p, content)] = .init(
				proposal: proposal, sender: message.content.sender)
		}
		return store
	}

	func commit(request: MlsClient_CommitRequest, context: ServerContext)
		async throws -> MlsClient_CommitResponse
	{
		var state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))

		var proposals: [MLS.RFC9420.ProposalOrRef] = []
		let store = try proposalStore(from: request.byReference, p)
		for ref in store.keys { proposals.append(.reference(ref)) }
		for byValue in request.byValue {
			proposals.append(
				.proposal(
					try decodeProposalDescription(byValue, in: state.group, p)))
		}

		// `force_path` means "populate a path even when it is optional".
		// When a path is *required* (empty commit, or update/remove/GCE),
		// it is always included -- so OR the requirement in rather than
		// letting `committing` throw `pathRequired`.
		let resolvedForPath = proposals.compactMap { entry -> MLS.RFC9420.Proposal? in
			if case .proposal(let proposal) = entry { return proposal }
			if case .reference(let ref) = entry { return store[ref]?.proposal }
			return nil
		}
		let pathRequired =
			resolvedForPath.isEmpty
			|| resolvedForPath.contains {
				switch $0 {
				case .update, .remove, .externalInit, .groupContextExtensions: true
				case .add, .preSharedKey, .reInit: false
				}
			}
		let output = try state.group.committing(
			p, proposals: proposals, proposalStore: store,
			signingKey: state.credentials.signingKey,
			randomness: .generate(p),
			includePath: request.forcePath || pathRequired,
			// external_tree TRUE = deliver the tree out of band (in the
			// CommitResponse, omitted from GroupInfo); FALSE = in band via
			// the GroupInfo extension. So the extension is included when
			// external_tree is *false*.
			includeRatchetTreeExtension: !request.externalTree,
			psk: { [externalPsks] id in
				guard case .external(let pskID, _) = id else { return nil }
				return externalPsks[pskID]
			})
		state.pending = output
		entries[request.stateID] = .group(state)

		var r = MlsClient_CommitResponse()
		r.commit = try encoded(.publicMessage(output.commit))
		if let welcome = output.welcome {
			r.welcome = try encoded(.welcome(welcome))
		}
		if request.externalTree {
			var writer = MLS.Writer()
			try writer.encodeVector(output.group.tree.nodes)
			r.ratchetTree = Data(writer.bytes)
		}
		return r
	}

	private func decodeProposalDescription(
		_ desc: MlsClient_ProposalDescription, in group: MLS.RFC9420.Group,
		_ p: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Proposal {
		switch String(decoding: desc.proposalType, as: UTF8.self) {
		case "add":
			var reader = MLS.Reader(desc.keyPackage)
			guard case .keyPackage(let kp) = try MLS.RFC9420.Message(from: &reader)
			else { throw invalid("add-by-value: not a key package") }
			return .add(kp)
		case "remove":
			return .remove(try leafIndex(ofIdentity: desc.removedID, in: group))
		case "externalPSK":
			return .preSharedKey(
				.external(pskID: desc.pskID, nonce: p.randomBytes(p.hashSize)))
		case "groupContextExtensions":
			var extensions: [MLS.RFC9420.Extension] = []
			for ext in desc.extensions {
				extensions.append(
					.init(
						type: .init(
							rawValue: UInt16(
								truncatingIfNeeded: ext
									.extensionType)),
						data: ext.extensionData))
			}
			return .groupContextExtensions(extensions)
		default:
			throw unsupported("by-value proposal type \(desc.proposalType)")
		}
	}

	func handleCommit(request: MlsClient_HandleCommitRequest, context: ServerContext)
		async throws -> MlsClient_HandleCommitResponse
	{
		var state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		let store = try proposalStore(from: request.proposal, p)
		var commitReader = MLS.Reader(request.commit)
		guard case .publicMessage(let commit) = try MLS.RFC9420.Message(from: &commitReader)
		else { throw invalid("commit is not a public message") }
		try state.group.process(
			p, commit: commit, proposals: store,
			psk: { [externalPsks] id in
				guard case .external(let pskID, _) = id else { return nil }
				return externalPsks[pskID]
			})
		state.pending = nil
		entries[request.stateID] = .group(state)
		var r = MlsClient_HandleCommitResponse()
		r.stateID = request.stateID
		r.epochAuthenticator = state.group.epoch.epochAuthenticator
		return r
	}

	func handlePendingCommit(
		request: MlsClient_HandlePendingCommitRequest, context: ServerContext
	) async throws -> MlsClient_HandleCommitResponse {
		var state = try requireGroup(request.stateID)
		guard let pending = state.pending else {
			throw invalid("no pending commit for state \(request.stateID)")
		}
		state.group = pending.group
		state.pending = nil
		entries[request.stateID] = .group(state)
		var r = MlsClient_HandleCommitResponse()
		r.stateID = request.stateID
		r.epochAuthenticator = state.group.epoch.epochAuthenticator
		return r
	}

	// MARK: - Application messages

	func protect(request: MlsClient_ProtectRequest, context: ServerContext)
		async throws -> MlsClient_ProtectResponse
	{
		var state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		let message = try state.group.protect(
			p, applicationData: request.plaintext,
			authenticatedData: request.authenticatedData,
			signingKey: state.credentials.signingKey)
		entries[request.stateID] = .group(state)
		var r = MlsClient_ProtectResponse()
		r.ciphertext = try encoded(.privateMessage(message))
		return r
	}

	func unprotect(request: MlsClient_UnprotectRequest, context: ServerContext)
		async throws -> MlsClient_UnprotectResponse
	{
		var state = try requireGroup(request.stateID)
		let p = try suiteProvider(UInt32(state.credentials.suite.id))
		var reader = MLS.Reader(request.ciphertext)
		guard case .privateMessage(let message) = try MLS.RFC9420.Message(from: &reader)
		else { throw invalid("ciphertext is not a private message") }
		let opened = try state.group.unprotect(p, message: message)
		entries[request.stateID] = .group(state)
		guard case .application(let data) = opened.content else {
			throw invalid("unprotected message was not application data")
		}
		var r = MlsClient_UnprotectResponse()
		r.plaintext = data
		r.authenticatedData = opened.authenticatedData
		return r
	}

	// MARK: - PSK / auth / lifecycle

	func storePSK(request: MlsClient_StorePSKRequest, context: ServerContext)
		async throws -> MlsClient_StorePSKResponse
	{
		externalPsks[request.pskID] = request.pskSecret
		return MlsClient_StorePSKResponse()
	}

	func stateAuth(request: MlsClient_StateAuthRequest, context: ServerContext)
		async throws -> MlsClient_StateAuthResponse
	{
		let state = try requireGroup(request.stateID)
		var r = MlsClient_StateAuthResponse()
		r.stateAuthSecret = state.group.epoch.epochAuthenticator
		return r
	}

	func export(request: MlsClient_ExportRequest, context: ServerContext)
		async throws -> MlsClient_ExportResponse
	{
		throw unsupported("Export (not exercised by the runner)")
	}

	func free(request: MlsClient_FreeRequest, context: ServerContext)
		async throws -> MlsClient_FreeResponse
	{
		// Tolerant by contract: the runner frees every actor at end-of-test.
		entries[request.stateID] = nil
		return MlsClient_FreeResponse()
	}

	// MARK: - Out of scope (ABORTED "unsupported", matching mls-rs)

	func externalJoin(request: MlsClient_ExternalJoinRequest, context: ServerContext)
		async throws -> MlsClient_ExternalJoinResponse
	{ throw unsupported("ExternalJoin") }
	func groupInfo(request: MlsClient_GroupInfoRequest, context: ServerContext)
		async throws -> MlsClient_GroupInfoResponse
	{ throw unsupported("GroupInfo") }
	func reInitProposal(request: MlsClient_ReInitProposalRequest, context: ServerContext)
		async throws -> MlsClient_ProposalResponse
	{ throw unsupported("ReInitProposal") }
	func reInitCommit(request: MlsClient_CommitRequest, context: ServerContext)
		async throws -> MlsClient_CommitResponse
	{ throw unsupported("ReInitCommit") }
	func handlePendingReInitCommit(
		request: MlsClient_HandlePendingCommitRequest, context: ServerContext
	) async throws -> MlsClient_HandleReInitCommitResponse { throw unsupported("ReInit") }
	func handleReInitCommit(request: MlsClient_HandleCommitRequest, context: ServerContext)
		async throws -> MlsClient_HandleReInitCommitResponse
	{ throw unsupported("ReInit") }
	func reInitWelcome(request: MlsClient_ReInitWelcomeRequest, context: ServerContext)
		async throws -> MlsClient_CreateSubgroupResponse
	{ throw unsupported("ReInitWelcome") }
	func handleReInitWelcome(
		request: MlsClient_HandleReInitWelcomeRequest, context: ServerContext
	) async throws -> MlsClient_JoinGroupResponse { throw unsupported("ReInit") }
	func createBranch(request: MlsClient_CreateBranchRequest, context: ServerContext)
		async throws -> MlsClient_CreateSubgroupResponse
	{ throw unsupported("CreateBranch") }
	func handleBranch(request: MlsClient_HandleBranchRequest, context: ServerContext)
		async throws -> MlsClient_HandleBranchResponse
	{ throw unsupported("HandleBranch") }
	func newMemberAddProposal(
		request: MlsClient_NewMemberAddProposalRequest, context: ServerContext
	) async throws -> MlsClient_NewMemberAddProposalResponse {
		throw unsupported("NewMemberAddProposal")
	}
	func createExternalSigner(
		request: MlsClient_CreateExternalSignerRequest, context: ServerContext
	) async throws -> MlsClient_CreateExternalSignerResponse {
		throw unsupported("CreateExternalSigner")
	}
	func addExternalSigner(
		request: MlsClient_AddExternalSignerRequest, context: ServerContext
	) async throws -> MlsClient_ProposalResponse { throw unsupported("AddExternalSigner") }
	func externalSignerProposal(
		request: MlsClient_ExternalSignerProposalRequest, context: ServerContext
	) async throws -> MlsClient_ProposalResponse { throw unsupported("ExternalSignerProposal") }
}
#endif
