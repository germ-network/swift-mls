import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420

extension MLS.Combiner {
	/// draft-ietf-mls-combiner-02 §6's `APQInfo` GroupContext extension, carried in
	/// **both** halves' GroupContext and naming the pair:
	/// ```
	/// struct {
	///   opaque t_session_group_id<V>;
	///   opaque PQ_session_group_id<V>;
	///   bool mode;
	///   CipherSuite t_cipher_suite;
	///   CipherSuite pq_cipher_suite;
	///   uint64 t_epoch;
	///   uint64 pq_epoch;
	/// } APQInfo
	/// ```
	/// `mode` is the draft's `bool` (a one-byte `0`/`1` in the MLS presentation
	/// language); it is carried as a `UInt8` here — identical on the wire — and this
	/// module never interprets it (which mode values are legitimate, and the
	/// suite/mode coherence, are Germ-suite policy, downstream).
	///
	/// **Write-once.** It is set into both halves' GroupContext at creation and rides
	/// the Welcome automatically (§4.2.1); it is never rewritten — a
	/// GroupContextExtensions proposal would be needed, which the combiner's flows do
	/// not issue — so its two epoch fields hold the join-point (epoch-1) values, and
	/// per-commit epoch *freshness* is attested by `ApqInfoUpdate` instead. The draft
	/// is silent on rewriting; write-once is this module's resolution of that
	/// underspecified point, matching the deployed consumer.
	///
	/// The suite fields are carried and compared for cross-half equality; their
	/// *validity* (which PQ suites form a coherent APQ pair, and mode-from-suite) is
	/// not checked here — that is Germ-suite policy in twomlspq-swift.
	public struct APQInfo: Sendable, Equatable, MLSCodable {
		public var tSessionGroupID: Data
		public var pqSessionGroupID: Data
		public var mode: UInt8
		public var tCipherSuite: MLS.CipherSuite
		public var pqCipherSuite: MLS.CipherSuite
		public var tEpoch: UInt64
		public var pqEpoch: UInt64

		public init(
			tSessionGroupID: Data,
			pqSessionGroupID: Data,
			mode: UInt8,
			tCipherSuite: MLS.CipherSuite,
			pqCipherSuite: MLS.CipherSuite,
			tEpoch: UInt64,
			pqEpoch: UInt64
		) {
			self.tSessionGroupID = tSessionGroupID
			self.pqSessionGroupID = pqSessionGroupID
			self.mode = mode
			self.tCipherSuite = tCipherSuite
			self.pqCipherSuite = pqCipherSuite
			self.tEpoch = tEpoch
			self.pqEpoch = pqEpoch
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(tSessionGroupID)
			try writer.writeOpaque(pqSessionGroupID)
			writer.writeUInt8(mode)
			try writer.encode(tCipherSuite)
			try writer.encode(pqCipherSuite)
			writer.writeUInt64(tEpoch)
			writer.writeUInt64(pqEpoch)
		}

		public init(from reader: inout MLS.Reader) throws {
			tSessionGroupID = Data(try reader.readOpaque())
			pqSessionGroupID = Data(try reader.readOpaque())
			mode = try reader.readUInt8()
			tCipherSuite = try MLS.CipherSuite(from: &reader)
			pqCipherSuite = try MLS.CipherSuite(from: &reader)
			tEpoch = try reader.readUInt64()
			pqEpoch = try reader.readUInt64()
		}
	}
}

extension MLS.Combiner.APQInfo {
	/// The identity fields both halves must agree on — everything but the per-half
	/// epoch fields (draft §6's `t_epoch`/`pq_epoch`, which a `verifyPair` matches
	/// against each half's observed epoch separately).
	func identityFieldsMatch(_ other: MLS.Combiner.APQInfo) -> Bool {
		tSessionGroupID == other.tSessionGroupID
			&& pqSessionGroupID == other.pqSessionGroupID
			&& mode == other.mode
			&& tCipherSuite == other.tCipherSuite
			&& pqCipherSuite == other.pqCipherSuite
	}

	/// Wrap as an `MLS.RFC9420.Extension` of the given type (the code point from
	/// [`MLS.Combiner.Codepoints`], `0xF0A1` by default) — the GroupContext
	/// extension every combiner group is created with.
	public func asExtension(
		type: MLS.RFC9420.ExtensionType
	) throws -> MLS.RFC9420.Extension {
		MLS.RFC9420.Extension(type: type, data: try mlsEncoded())
	}

	/// Read the `APQInfo` out of a GroupContext's extensions, matching the given
	/// type. `nil` when absent; throws if the extension is present but its
	/// `extension_data` does not decode cleanly — truncation or trailing bytes (a
	/// corrupt `APQInfo` must never read as "absent"). Every group this module creates
	/// or joins carries one, so a caller treats `nil` as a downgrade/omission failure.
	public static func read(
		fromExtensionsOf context: MLS.RFC9420.GroupContext,
		type: MLS.RFC9420.ExtensionType
	) throws -> MLS.Combiner.APQInfo? {
		guard let ext = context.extensions.first(where: { $0.type == type }) else {
			return nil
		}
		var reader = MLS.Reader(ext.data)
		let info = try MLS.Combiner.APQInfo(from: &reader)
		try reader.finish()
		return info
	}
}
