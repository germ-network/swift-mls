import Foundation
import MLSCodec
import MLSCrypto
import MLSFraming
import MLSTreeMath

extension MLS.RFC9420 {
	/// Everything protecting/unprotecting a private message needs from the
	/// secret tree, kept abstract here rather than depending on
	/// `MLSKeySchedule`'s concrete secret-tree type directly: given a leaf,
	/// a generation, and which ratchet (handshake vs. application), produce
	/// or consume that generation's (key, nonce). A caller backs this with
	/// whatever secret-tree state it's actually managing. (An earlier
	/// revision justified the seam by claiming this target doesn't depend
	/// on `MLSKeySchedule`; it does, and always has — the seam survives on
	/// its own merits as the stateless-vector-test boundary, not on a
	/// dependency constraint that never existed.)
	///
	/// This function alone can't enforce the ratchet-hygiene properties
	/// forward secrecy depends on — a conforming implementation must:
	/// bound how far a decryption call is allowed to advance the ratchet
	/// past its last-seen generation; delete a generation's secret once
	/// consumed, so it can't be produced a second time; and refuse to
	/// derive a decryption key for the caller's own leaf (a message can't
	/// legitimately be decrypting its own sender). None of that is
	/// visible from this one call's signature.
	public protocol MessageKeySource {
		func key(
			for leafIndex: MLS.LeafIndex, generation: UInt32,
			contentType: MLS.ContentType
		) throws -> (
			key: Data, nonce: Data
		)
	}

	/// RFC 9420 §6: "Applications MUST use PrivateMessage to encrypt
	/// application messages." Checked here, in `protectPublic` alone — not
	/// in `PublicMessage`'s own decoder, which must still accept an
	/// `application_data`-carrying `PublicMessage` if handed one (e.g. by
	/// `messages.json`'s own `public_message_application` vectors, testing
	/// exactly this shape in isolation from the rule this function enforces).
	public static func protectPublic(
		_ provider: any MLS.CipherSuiteProvider, content: FramedContent,
		groupContext: GroupContext,
		confirmationTag: MLS.ConfirmationTag?, signingKey: MLS.SignatureSecretKey,
		membershipKey: some ContiguousBytes
	) throws -> PublicMessage {
		let (signedContent, signature) = try signPublic(
			provider, content: content, groupContext: groupContext,
			signingKey: signingKey)
		return try sealPublic(
			provider, content: content, signedContent: signedContent,
			signature: signature, confirmationTag: confirmationTag,
			membershipKey: membershipKey)
	}

	/// The signing half of `protectPublic`, split out because commit
	/// construction cannot use the whole: RFC 9420 §12.4.1's confirmation
	/// tag is computed over a transcript hash that *includes this
	/// signature*, so the tag does not exist yet when the signature is
	/// made — and signing twice is not an option, since ECDSA signatures
	/// are randomized on three of the five supported suites. A committer
	/// signs here, chains the transcript, derives the new epoch and its
	/// tag, then seals with `sealPublic`.
	public static func signPublic(
		_ provider: any MLS.CipherSuiteProvider, content: FramedContent,
		groupContext: GroupContext, signingKey: MLS.SignatureSecretKey
	) throws -> (signedContent: MLS.Framing.SignedContent, signature: MLS.Signature) {
		if case .application = content.content {
			throw MLS.FramingError.applicationContentMustNotBePublic
		}

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: try content.mlsEncoded(),
			encodedGroupContext: content.sender.bindsGroupContext
				? try groupContext.mlsEncoded() : nil)
		let signature = MLS.Signature(
			try MLS.signWithLabel(
				provider, privateKey: signingKey, label: "FramedContentTBS",
				content: try signedContent.toBeSigned()))
		return (signedContent, signature)
	}

	/// The tagging half — see `signPublic`.
	public static func sealPublic(
		_ provider: any MLS.CipherSuiteProvider, content: FramedContent,
		signedContent: MLS.Framing.SignedContent, signature: MLS.Signature,
		confirmationTag: MLS.ConfirmationTag?, membershipKey: some ContiguousBytes
	) throws -> PublicMessage {
		let auth = MLS.FramedContentAuthData(
			signature: signature, confirmationTag: confirmationTag)

		var membershipTag: MLS.MembershipTag?
		if content.sender.carriesMembershipTag {
			var authWriter = MLS.Writer()
			try auth.encodeRequiringSignature(
				contentType: content.content.contentType, to: &authWriter)
			membershipTag = try MLS.Framing.membershipTag(
				provider, membershipKey: membershipKey,
				signedContent: signedContent,
				encodedAuthData: Data(authWriter.bytes))
		}

		return PublicMessage(content: content, auth: auth, membershipTag: membershipTag)
	}

	public static func verifyPublic(
		_ provider: any MLS.CipherSuiteProvider, message: PublicMessage,
		groupContext: GroupContext,
		verificationKey: MLS.SignaturePublicKey, membershipKey: some ContiguousBytes
	) throws -> Bool {
		// §6's MUST-NOT is a receive-side rule as much as a send-side one:
		// `PublicMessage`'s own decoder must still accept an
		// application-content message handed to it (e.g. by
		// `messages.json`'s own `public_message_application` records,
		// testing that shape in isolation) — but verifying one as legitimate
		// would defeat the rule `protectPublic` enforces on the way out.
		if case .application = message.content.content {
			throw MLS.FramingError.applicationContentMustNotBePublic
		}

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .publicMessage,
			encodedContent: try message.content.mlsEncoded(),
			encodedGroupContext: message.content.sender.bindsGroupContext
				? try groupContext.mlsEncoded() : nil)

		guard let signature = message.auth.signature else {
			throw MLS.FramingError.signatureRequired
		}
		let signatureValid = try MLS.verifyWithLabel(
			provider, publicKey: verificationKey, label: "FramedContentTBS",
			content: try signedContent.toBeSigned(), signature: signature.data)
		guard signatureValid else { return false }

		guard message.content.sender.carriesMembershipTag else { return true }
		guard let membershipTag = message.membershipTag else {
			throw MLS.FramingError.membershipTagMissing
		}
		var authWriter = MLS.Writer()
		try message.auth.encodeRequiringSignature(
			contentType: message.content.content.contentType, to: &authWriter)
		let expected = try MLS.Framing.membershipTag(
			provider, membershipKey: membershipKey, signedContent: signedContent,
			encodedAuthData: Data(authWriter.bytes))
		return expected == membershipTag
	}

	/// The signing half for private framing — the counterpart to
	/// `signPublic`, split out so a commit can sign, chain its transcript,
	/// derive its confirmation tag, and only then seal. A private commit's
	/// transcript is computed over `wireFormat: .privateMessage`, so it must
	/// sign here, not via `signPublic`. Application content is allowed —
	/// unlike `signPublic`, private framing is where it belongs.
	public static func signPrivate(
		_ provider: any MLS.CipherSuiteProvider, content: FramedContent,
		groupContext: GroupContext, signingKey: MLS.SignatureSecretKey
	) throws -> (signedContent: MLS.Framing.SignedContent, signature: MLS.Signature) {
		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .privateMessage,
			encodedContent: try content.mlsEncoded(),
			encodedGroupContext: content.sender.bindsGroupContext
				? try groupContext.mlsEncoded() : nil)
		let signature = MLS.Signature(
			try MLS.signWithLabel(
				provider, privateKey: signingKey, label: "FramedContentTBS",
				content: try signedContent.toBeSigned()))
		return (signedContent, signature)
	}

	/// The encryption half for private framing — see `signPrivate`. Takes an
	/// already-computed `signature` (and, for a commit, `confirmationTag`) so
	/// the caller owns the sign → transcript → tag → seal order, exactly as
	/// `sealPublic` does for the public path.
	public static func sealPrivate(
		_ provider: any MLS.CipherSuiteProvider, keySource: MessageKeySource,
		content: FramedContent, signature: MLS.Signature, generation: UInt32,
		confirmationTag: MLS.ConfirmationTag?,
		senderDataSecret: some ContiguousBytes, reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> PrivateMessage {
		guard case .member(let leafIndex) = content.sender else {
			throw MLS.FramingError.privateMessageRequiresMemberSender
		}
		let auth = MLS.FramedContentAuthData(
			signature: signature, confirmationTag: confirmationTag)
		let plaintext = try PrivateMessageContent(content: content.content, auth: auth)
			.encode(paddingLength: paddingLength)

		let (key, nonce) = try keySource.key(
			for: leafIndex, generation: generation,
			contentType: content.content.contentType)
		let guardedNonce = reuseGuard.applied(to: nonce)

		let aad = MLS.Framing.PrivateContentAAD(
			groupID: content.groupID, epoch: content.epoch,
			contentType: content.content.contentType,
			authenticatedData: content.authenticatedData)
		var aadWriter = MLS.Writer()
		try aad.encode(to: &aadWriter)
		let ciphertext = try provider.aeadSeal(
			key: key, nonce: guardedNonce, aad: Data(aadWriter.bytes),
			plaintext: plaintext)

		let senderData = MLS.Framing.SenderData(
			leafIndex: leafIndex, generation: generation, reuseGuard: reuseGuard)
		let senderDataAAD = MLS.Framing.SenderDataAAD(
			groupID: content.groupID, epoch: content.epoch,
			contentType: content.content.contentType)
		let (senderDataKey, senderDataNonce) = try MLS.Framing.senderDataKeyNonce(
			provider, secret: senderDataSecret, ciphertextSample: ciphertext)
		let encryptedSenderData = try MLS.Framing.sealSenderData(
			provider, key: senderDataKey, nonce: senderDataNonce,
			senderData: senderData, aad: senderDataAAD)

		return PrivateMessage(
			groupID: content.groupID, epoch: content.epoch,
			contentType: content.content.contentType,
			authenticatedData: content.authenticatedData,
			encryptedSenderData: encryptedSenderData,
			ciphertext: ciphertext)
	}

	/// Sign and seal a `PrivateMessage` in one call — `signPrivate` then
	/// `sealPrivate`. The commit path uses the two halves directly (it has to
	/// interpose transcript-chaining between them); everything else uses this.
	public static func protectPrivate(
		_ provider: any MLS.CipherSuiteProvider, keySource: MessageKeySource,
		content: FramedContent, groupContext: GroupContext, generation: UInt32,
		confirmationTag: MLS.ConfirmationTag?, signingKey: MLS.SignatureSecretKey,
		senderDataSecret: some ContiguousBytes, reuseGuard: MLS.Framing.ReuseGuard,
		paddingLength: Int
	) throws -> PrivateMessage {
		let (_, signature) = try signPrivate(
			provider, content: content, groupContext: groupContext,
			signingKey: signingKey)
		return try sealPrivate(
			provider, keySource: keySource, content: content, signature: signature,
			generation: generation, confirmationTag: confirmationTag,
			senderDataSecret: senderDataSecret, reuseGuard: reuseGuard,
			paddingLength: paddingLength)
	}

	/// The sender-data half of unprotecting, on its own. RFC 9420 §9.2's
	/// "(successfully) decrypt" makes the split load-bearing, not
	/// cosmetic: a stateful store must not consume a generation until the
	/// content AEAD has actually opened, because sender data is sealed
	/// under a secret *every member holds* — so a malicious member can
	/// forge plausible sender data naming any (victim, generation) over
	/// garbage ciphertext, and a store that consumed on key-derivation
	/// would let them permanently destroy the victim's real message at
	/// that generation. Open the sender data, decide (route, refuse own
	/// leaf, bound the jump), derive, open the content, and only then
	/// consume.
	public static func openSenderData(
		_ provider: any MLS.CipherSuiteProvider, message: PrivateMessage,
		senderDataSecret: some ContiguousBytes
	) throws -> MLS.Framing.SenderData {
		let senderDataAAD = MLS.Framing.SenderDataAAD(
			groupID: message.groupID, epoch: message.epoch,
			contentType: message.contentType)
		let (senderDataKey, senderDataNonce) = try MLS.Framing.senderDataKeyNonce(
			provider, secret: senderDataSecret, ciphertextSample: message.ciphertext)
		return try MLS.Framing.openSenderData(
			provider, key: senderDataKey, nonce: senderDataNonce,
			ciphertext: message.encryptedSenderData, aad: senderDataAAD)
	}

	/// The content half — AEAD open, decode, signature verification —
	/// given the already-opened sender data and the derived (key, nonce).
	/// See `openSenderData` for why the caller sits between the halves.
	public static func openPrivateContent(
		_ provider: any MLS.CipherSuiteProvider, message: PrivateMessage,
		senderData: MLS.Framing.SenderData, key: Data, nonce: Data,
		groupContext: GroupContext,
		verificationKey: (MLS.LeafIndex) throws -> MLS.SignaturePublicKey
	) throws -> AuthenticatedContent {
		let guardedNonce = senderData.reuseGuard.applied(to: nonce)

		let aad = MLS.Framing.PrivateContentAAD(
			groupID: message.groupID, epoch: message.epoch,
			contentType: message.contentType,
			authenticatedData: message.authenticatedData)
		var aadWriter = MLS.Writer()
		try aad.encode(to: &aadWriter)
		let plaintext = try provider.aeadOpen(
			key: key, nonce: guardedNonce, aad: Data(aadWriter.bytes),
			ciphertext: message.ciphertext)

		let messageContent = try PrivateMessageContent.decode(
			plaintext, contentType: message.contentType)

		let content = FramedContent(
			groupID: message.groupID, epoch: message.epoch,
			sender: .member(senderData.leafIndex),
			authenticatedData: message.authenticatedData,
			content: messageContent.content)

		let signedContent = MLS.Framing.SignedContent(
			protocolVersion: .mls10, wireFormat: .privateMessage,
			encodedContent: try content.mlsEncoded(),
			encodedGroupContext: content.sender.bindsGroupContext
				? try groupContext.mlsEncoded() : nil)
		guard let signature = messageContent.auth.signature else {
			throw MLS.FramingError.signatureRequired
		}
		let signatureValid = try MLS.verifyWithLabel(
			provider, publicKey: try verificationKey(senderData.leafIndex),
			label: "FramedContentTBS",
			content: try signedContent.toBeSigned(), signature: signature.data)
		guard signatureValid else { throw MLS.CryptoError.signatureVerificationFailed }

		return AuthenticatedContent(
			wireFormat: .privateMessage, content: content, auth: messageContent.auth)
	}

	/// The one-shot composition of the two halves, for stateless callers
	/// (the message-protection vector gate). Consumes via `keySource`
	/// *before* the content AEAD — acceptable only because a stateless
	/// key source has nothing to consume; a stateful store must use the
	/// split.
	public static func unprotectPrivate(
		_ provider: any MLS.CipherSuiteProvider, keySource: MessageKeySource,
		message: PrivateMessage,
		groupContext: GroupContext,
		verificationKey: (MLS.LeafIndex) throws -> MLS.SignaturePublicKey,
		senderDataSecret: some ContiguousBytes
	) throws -> AuthenticatedContent {
		let senderData = try openSenderData(
			provider, message: message, senderDataSecret: senderDataSecret)
		let (key, nonce) = try keySource.key(
			for: senderData.leafIndex, generation: senderData.generation,
			contentType: message.contentType)
		return try openPrivateContent(
			provider, message: message, senderData: senderData, key: key,
			nonce: nonce, groupContext: groupContext,
			verificationKey: verificationKey)
	}
}
