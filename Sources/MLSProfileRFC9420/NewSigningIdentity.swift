import MLSCodec
import MLSCrypto

extension MLS.RFC9420 {
	/// Caller-supplied new identity for authoring a leaf credential /
	/// signature-key rotation (RFC 9420 §5.3.1). swift-mls has no
	/// Authentication Service: it neither mints nor validates identities. This
	/// only says what identity the new leaf carries — the new `credential`
	/// and `signatureKey` it is built with. Signing is the app's job: its
	/// `sign:` closure answers `.leafNode`/`.groupInfo` with the NEW key (see
	/// `MLS.RFC9420.signingClosure(_:current:new:)`), while `.framedContent`
	/// stays on the CURRENT key.
	public struct NewSigningIdentity: Sendable {
		public var credential: MLS.RFC9420.Credential
		public var signatureKey: MLS.SignaturePublicKey

		public init(
			credential: MLS.RFC9420.Credential, signatureKey: MLS.SignaturePublicKey
		) {
			self.credential = credential
			self.signatureKey = signatureKey
		}
	}
}
