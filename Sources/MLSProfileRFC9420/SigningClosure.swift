import Foundation
import MLSCodec
import MLSCrypto

extension MLS.RFC9420 {
	/// Which of the three authoring signature sites produced a
	/// `SigningRequest` — see ADR 0002. `@nonexhaustive` (SE-0487): a future
	/// revision may add a role without breaking a closure that switches on
	/// this today, so long as it does not do so exhaustively.
	@nonexhaustive
	public enum SignatureRole: Sendable, Equatable, Hashable {
		/// The leaf's own signature (§7.3): the key the leaf's own
		/// `signature_key` field names — the NEW key when this operation is a
		/// rotation (`NewSigningIdentity`), else the signer's current one.
		case leafNode
		/// The enclosing `FramedContent`'s signature: the sender's CURRENT,
		/// pre-commit key. Receivers verify it against the sender's leaf as it
		/// stood BEFORE this operation, so this role never routes to a
		/// rotation's new key — not even on the commit that installs it.
		case framedContent
		/// `GroupInfo`'s signature: the key of the POST-commit tree's `signer`
		/// leaf. `Group.joining` verifies it against the tree AFTER the
		/// commit applies, so a rotating commit's Welcome MUST sign this with
		/// the NEW key or every join from it fails signature verification.
		case groupInfo
	}

	/// What an authoring operation hands its signer closure at the one
	/// choke point every signature funnels through (`MLS.signWithLabel`):
	/// `role` names the site, `signContent` is the already-encoded
	/// `Encode(SignContent)` bytes (`MLS.signContentBytes`) — exactly what a
	/// `CipherSuiteProvider.sign` would otherwise be handed.
	public struct SigningRequest: Sendable {
		public let role: SignatureRole
		public let signContent: Data

		public init(role: SignatureRole, signContent: Data) {
			self.role = role
			self.signContent = signContent
		}
	}

	/// A synchronous, non-escaping-in-spirit signer: named `SigningClosure`,
	/// not `Signer` — `GroupInfo.signer: LeafIndex` is a wire field set in the
	/// very function that takes this parameter, and the near-identical name
	/// would be a standing trap. See ADR 0002 for the seam this closure is
	/// the crux of; `signingKey:` stays first-class sugar over it.
	public typealias SigningClosure = (SigningRequest) throws -> Data

	/// The `signingKey:` sugar's adapter: a stateless key, wrapped as the
	/// trivial closure that ignores `role` and signs with that one key. A
	/// signature-KEY rotation is incoherent under this adapter — the leaf
	/// would declare `NewSigningIdentity.signatureKey` but every role signs
	/// with the same OLD key — so `committing`/`proposeUpdate`'s self-verify
	/// guard is what catches a rotation mistakenly attempted through
	/// `signingKey:` (a credential-only rotation, same key, still works: see
	/// `NewSigningIdentity`).
	public static func signingClosure(
		_ provider: any MLS.CipherSuiteProvider, _ key: MLS.SignatureSecretKey
	) -> SigningClosure {
		{ request in try provider.sign(privateKey: key, content: request.signContent) }
	}

	/// A rotation's signing ring: `.framedContent` stays on `current` (the
	/// enclosing commit/proposal keeps verifying against the sender's
	/// pre-commit leaf); `.leafNode` and `.groupInfo` route to `new` (the
	/// identity `NewSigningIdentity` installs). Library-side so the `switch`
	/// over `SignatureRole` is exhaustive here — a future role added to that
	/// `@nonexhaustive` enum is a compile error in this file, never a silent
	/// fallback to `current`. The ring is for the rotation operation only:
	/// once the commit is affirmed, the app retires it and goes back to the
	/// one-key adapter above with `current := new`.
	public static func signingClosure(
		_ provider: any MLS.CipherSuiteProvider, current: MLS.SignatureSecretKey,
		new: MLS.SignatureSecretKey
	) -> SigningClosure {
		{ request in
			switch request.role {
			case .framedContent:
				try provider.sign(privateKey: current, content: request.signContent)
			case .leafNode, .groupInfo:
				try provider.sign(privateKey: new, content: request.signContent)
			}
		}
	}

	/// The sink helper every authoring site funnels through: encode
	/// `SignContent` once, then hand the closure a role-tagged request.
	static func sign(
		_ closure: SigningClosure, role: SignatureRole, label: String, content: Data
	) throws -> Data {
		try closure(
			.init(
				role: role,
				signContent: try MLS.signContentBytes(
					label: label, content: content))
		)
	}
}
