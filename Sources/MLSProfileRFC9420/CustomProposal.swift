import MLSCodec

extension MLS.RFC9420 {
	/// The non-default proposal types this receiver decodes as
	/// `Proposal.custom` — `type ‖ opaque<V>(body)` — rather than rejecting as
	/// `unknownProposalType`. Empty by default, so nothing changes unless a
	/// consumer opts in. A type this library has a typed arm for — RFC 9420's seven
	/// default types (§17.4), or a draft-registered one such as 0x0008
	/// `.appDataUpdate` — is redirected to `.custom` only if it is non-default; a
	/// default type in the set is ignored, never redirected away from its typed arm.
	///
	/// An ambient rather than a per-call flag, like
	/// `MLS.Extensions.ComponentID.componentIDWireWidth`: the receive path
	/// re-encodes the decoded `FramedContent` for the signature check and the
	/// confirmed-transcript-hash input, so every decode of one message must
	/// agree. Scope the **whole** receive — the `Message(mlsEncoded:)` parse and
	/// the `validating` call — under
	/// `MLS.RFC9420.$customProposalTypes.withValue([type]) { … }`.
	@TaskLocal
	public static var customProposalTypes: Set<ProposalType> = []
}
