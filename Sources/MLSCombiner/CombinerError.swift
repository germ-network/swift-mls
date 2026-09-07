import MLSCodec

extension MLS.Combiner {
	/// Failure categories for the generic combiner layer. A consumer (twomlspq-swift)
	/// maps these onto its own error surface.
	public enum Error: Swift.Error, Sendable, Equatable {
		/// An `APQInfo` GroupContext extension is missing where one is required, or is
		/// present but inconsistent across a pair's halves — mismatched identity
		/// fields, a group id that does not name the joined group, or an epoch field
		/// that does not match the observed epoch. A missing `APQInfo` on a welcome is
		/// a downgrade attempt and fails the same way.
		case apqInfoMismatch

		/// An `AppDataUpdate` epoch attestation on a FULL commit failed verification:
		/// wrong component id, `op` not `update`, a malformed `ApqInfoUpdate` payload,
		/// an attested epoch that is not the half's actual post-commit epoch, more than
		/// one attestation on a commit, or the two halves' copies disagreeing.
		case attestationMismatch

		/// The two halves' rosters are not consistent (draft §4.2.1): the sets of
		/// members' Basic-credential identities are not equal, or a member does not
		/// carry a Basic credential.
		case membershipInconsistent

		/// A commit that must be FULL (carry an attestation) carried none, or a commit
		/// that must be PARTIAL carried one — a shape the combiner cannot reconcile.
		case commitShapeMismatch

		/// An establishment or join step produced no Welcome for the added member.
		case missingWelcome
	}
}
