import Foundation

/// A `Data` value that decodes from and encodes to a lowercase hex string —
/// the encoding every MLS/HPKE test vector JSON file uses for byte fields.
public struct HexData: Codable, Hashable, Sendable, ExpressibleByArrayLiteral {
	public var bytes: Data

	public init(_ bytes: Data) { self.bytes = bytes }
	public init(arrayLiteral elements: UInt8...) { bytes = Data(elements) }

	public init(from decoder: Decoder) throws {
		let hex = try decoder.singleValueContainer().decode(String.self)
		guard let data = HexData.decode(hex) else {
			throw DecodingError.dataCorruptedError(
				in: try decoder.singleValueContainer(),
				debugDescription: "not valid hex: \(hex)"
			)
		}
		bytes = data
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(HexData.encode(bytes))
	}

	static func decode(_ hex: String) -> Data? {
		guard hex.count.isMultiple(of: 2) else { return nil }
		var data = Data(capacity: hex.count / 2)
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
			data.append(byte)
			index = next
		}
		return data
	}

	static func encode(_ data: Data) -> String {
		// Avoids `String(format:)` — a printf-style formatter has had real
		// portability gaps on Linux Foundation historically, and a fixed
		// two-digit hex byte doesn't need one anyway.
		let digits = Array("0123456789abcdef")
		return data.reduce(into: "") { result, byte in
			result.append(digits[Int(byte >> 4)])
			result.append(digits[Int(byte & 0x0F)])
		}
	}
}
