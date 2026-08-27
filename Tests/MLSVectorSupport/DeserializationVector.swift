import Foundation

/// `deserialization.json` — one varint length header and the length it
/// denotes. The smallest official vector file, and the only one that tests
/// `MLSCodec` in isolation from every other component.
public struct DeserializationVector: Codable, Sendable {
	public let vlbytesHeader: HexData
	public let length: UInt32

	enum CodingKeys: String, CodingKey {
		case vlbytesHeader = "vlbytes_header"
		case length
	}
}
