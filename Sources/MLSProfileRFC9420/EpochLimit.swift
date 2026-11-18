import MLSCodec

extension MLS.RFC9420.GroupContext {
	/// The lowest epoch ``MLS/RFC9420/Group/joining(_:welcome:credentials:externalTree:psk:)``
	/// rejects. RFC 9420 §8.1 declares `uint64 epoch;` with no upper bound;
	/// this limit is this implementation's choice, not an RFC rule. It sits
	/// below ``restoreEpochLimit`` so that a joined group can commit at least
	/// 2^62 times and still restore from a snapshot.
	public static let joinEpochLimit: UInt64 = 1 << 62

	/// The lowest epoch snapshot restore rejects. This implementation's
	/// choice, not an RFC rule; see ``joinEpochLimit``.
	public static let restoreEpochLimit: UInt64 = 1 << 63

	/// Throws ``MLS/RFC9420/GroupError/epochOutOfRange(_:)`` when `epoch` is
	/// at or above `limit`.
	func requireEpoch(below limit: UInt64) throws {
		guard epoch < limit else {
			throw MLS.RFC9420.GroupError.epochOutOfRange(epoch)
		}
	}
}
