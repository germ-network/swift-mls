import Foundation

/// A type with an RFC 9420 presentation-language encoding.
public protocol MLSEncodable {
    func encode(to writer: inout MLS.Writer) throws
}

/// A type decodable from an RFC 9420 presentation-language encoding.
public protocol MLSDecodable {
    init(from reader: inout MLS.Reader) throws
}

public typealias MLSCodable = MLSEncodable & MLSDecodable

extension MLSEncodable {
    public func mlsEncoded() throws -> Data {
        var writer = MLS.Writer()
        try encode(to: &writer)
        return writer.data
    }
}

extension MLSDecodable {
    /// Decodes a complete message. Trailing bytes are an error: MLS structures
    /// are exactly as long as their contents, so leftovers mean a framing bug.
    public init(mlsEncoded bytes: some Collection<UInt8>) throws {
        var reader = MLS.Reader(bytes)
        self = try reader.decode()
        try reader.finish()
    }
}

extension UInt8: MLSCodable {
    public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt8(self) }
    public init(from reader: inout MLS.Reader) throws { self = try reader.readUInt8() }
}

extension UInt16: MLSCodable {
    public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt16(self) }
    public init(from reader: inout MLS.Reader) throws { self = try reader.readUInt16() }
}

extension UInt32: MLSCodable {
    public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt32(self) }
    public init(from reader: inout MLS.Reader) throws { self = try reader.readUInt32() }
}

// Lets `optional<T>` compose inside a vector — RFC 9420's
// `optional<Node> ratchet_tree<V>` needs `[Node?]` to be a plain
// `[some MLSCodable]` so `encodeVector`/`decodeVector` accept it directly.
extension Optional: MLSEncodable where Wrapped: MLSEncodable {
    public func encode(to writer: inout MLS.Writer) throws {
        try writer.encodeOptional(self)
    }
}

extension Optional: MLSDecodable where Wrapped: MLSDecodable {
    public init(from reader: inout MLS.Reader) throws {
        self = try reader.decodeOptional(Wrapped.self)
    }
}

extension UInt64: MLSCodable {
    public func encode(to writer: inout MLS.Writer) throws { writer.writeUInt64(self) }
    public init(from reader: inout MLS.Reader) throws { self = try reader.readUInt64() }
}
