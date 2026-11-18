import MLSCodec

extension MLS.RFC9420 {
	/// Whether, and against what time, a `key_package` leaf's lifetime is
	/// checked. RFC 9420 §7.3: for a LeafNode in a message being sent, "the
	/// client MUST verify that the current time is within the range of the
	/// lifetime field"; for one received, "it is RECOMMENDED".
	///
	/// The library reads no clock: the caller passes the time. That is this
	/// implementation's choice, not the spec's.
	public enum LifetimeCheck: Sendable, Equatable {
		/// Check against `unixSeconds`, seconds since the Unix epoch (§7.2).
		case at(unixSeconds: UInt64)
		/// Skip the check. On a send path this deviates from §7.3's MUST, and is
		/// for callers that bound leaf validity some other way, for example by
		/// rotating KeyPackages that carry `0…UInt64.max` lifetimes.
		case unchecked

		var unixSeconds: UInt64? {
			if case .at(let unixSeconds) = self { unixSeconds } else { nil }
		}
	}
}
