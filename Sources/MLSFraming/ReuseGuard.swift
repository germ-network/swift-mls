import Foundation
import MLSCodec

extension MLS.Framing {
	/// RFC 9420 §6.3.2: a fresh 4 random bytes per message, XORed into the
	/// leading bytes of the per-generation nonce so two messages sealed
	/// under the same (key, nonce) — a ratchet collision from out-of-order
	/// delivery racing a sender — never reuse it in practice.
	public struct ReuseGuard: Sendable, Equatable {
		public var bytes: Data

		public init(_ bytes: Data) {
			precondition(bytes.count == 4, "ReuseGuard is exactly 4 bytes")
			self.bytes = bytes
		}

		/// XORs `self` into the first 4 bytes of `nonce`, leaving the rest
		/// unchanged. Symmetric — the same call applies and removes the
		/// guard.
		public func applied(to nonce: Data) -> Data {
			var result = nonce
			for i in 0..<4 {
				let index = result.index(result.startIndex, offsetBy: i)
				result[index] ^= bytes[bytes.index(bytes.startIndex, offsetBy: i)]
			}
			return result
		}
	}
}
