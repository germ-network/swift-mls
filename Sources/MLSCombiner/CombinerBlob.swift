import Foundation
import MLSCodec
import MLSProfileRFC9420

extension MLS.Combiner {
	/// The deployed Germ opaque combiner-blob framing — the wire
	/// `encode_combiner_key_package` emits and `decode_combiner_key_package` reads
	/// (TwoMLSPQ rust/two-mls-pq/src/key_packages.rs): `[version byte]
	/// [opaque t_key_package][opaque pq_key_package]`, where each `opaque<V>` is the
	/// RFC 9420 §2.1.2 varint vector (mls_rs_codec's `byte_vec`) and each half is a
	/// full §6 `MLSMessage` carrying a KeyPackage — the draft-02 §7 `APQKeyPackage`
	/// pair inside Germ's version-byte envelope. Version 3 is the AppBinding
	/// capability cut; older framings are rejected, matching the Rust parser's
	/// prerelease hard-cut policy.
	///
	/// Read-only here by design: the Rust engine stays the blob's author and its
	/// parser the authority on full validation — this reader exists so a host that
	/// only consumes published offers (no Rust slice linked) can still find the
	/// halves.
	public struct CombinerBlob: Sendable, Equatable {
		/// The framing's version byte. v3 = AppBinding capability cut.
		public static let version: UInt8 = 3

		public var tKeyPackage: MLS.RFC9420.Message
		public var pqKeyPackage: MLS.RFC9420.Message

		public init(
			tKeyPackage: MLS.RFC9420.Message, pqKeyPackage: MLS.RFC9420.Message
		) {
			self.tKeyPackage = tKeyPackage
			self.pqKeyPackage = pqKeyPackage
		}

		/// nil when `bytes` is not a well-formed blob of this version: wrong version
		/// byte, a truncated vector, trailing bytes, or a half that fails to decode
		/// as an `MLSMessage`.
		public init?(bytes: Data) {
			var reader = MLS.Reader(bytes)
			guard
				(try? reader.readUInt8()) == Self.version,
				let tBytes = try? reader.readOpaque(),
				let pqBytes = try? reader.readOpaque(),
				reader.isEmpty
			else { return nil }

			guard
				let t = try? Self.message(Data(tBytes)),
				let pq = try? Self.message(Data(pqBytes))
			else { return nil }

			self.init(tKeyPackage: t, pqKeyPackage: pq)
		}

		private static func message(_ bytes: Data) throws -> MLS.RFC9420.Message {
			var reader = MLS.Reader(bytes)
			let message = try MLS.RFC9420.Message(from: &reader)
			try reader.finish()
			return message
		}
	}
}
