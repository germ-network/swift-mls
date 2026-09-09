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
		case leafNode
		case framedContent
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
	/// trivial closure that ignores `role` and signs with that one key.
	static func signingClosure(
		_ provider: any MLS.CipherSuiteProvider, _ key: MLS.SignatureSecretKey
	) -> SigningClosure {
		{ request in try provider.sign(privateKey: key, content: request.signContent) }
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
