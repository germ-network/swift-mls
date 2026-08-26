import MLSCodec

extension MLS.RFC9420 {
	/// `struct { uint64 not_before; uint64 not_after; } Lifetime;`
	public struct Lifetime: Sendable, Equatable, MLSCodable {
		public var notBefore: UInt64
		public var notAfter: UInt64

		public init(notBefore: UInt64, notAfter: UInt64) {
			self.notBefore = notBefore
			self.notAfter = notAfter
		}

		public func encode(to writer: inout MLS.Writer) throws {
			writer.writeUInt64(notBefore)
			writer.writeUInt64(notAfter)
		}

		public init(from reader: inout MLS.Reader) throws {
			notBefore = try reader.readUInt64()
			notAfter = try reader.readUInt64()
		}
	}
}
