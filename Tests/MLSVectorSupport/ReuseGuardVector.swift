/// `reuse_guard.json` (mls-rs, self-contained). Unlike every other vendored
/// vector, `nonce`/`guard`/`result` are JSON arrays of integers, not hex
/// strings.
public struct ReuseGuardVector: Decodable, Sendable {
	public let nonce: [UInt8]
	public let guardBytes: [UInt8]
	public let result: [UInt8]

	enum CodingKeys: String, CodingKey {
		case nonce, result
		case guardBytes = "guard"
	}
}
