/// Shared schema for `key_package_ref.json` and `proposal_ref.json` (both
/// mirrored from mls-rs, self-contained — see `Vectors/README.md`): `input`
/// is a serialized structure, `output` is `RefHash(label, input)` under
/// that structure's own label. Used first in opaque-bytes mode (before any
/// wire structure exists to parse `input` with), later upgraded to a
/// structural round-trip once the structure it names is implemented.
public struct RefVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let input: HexData
	public let output: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case input, output
	}
}
