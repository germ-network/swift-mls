import Foundation
import MLSCodec
import MLSCrypto

/// The KDFLabel-style structs this component needs that `MLSCrypto`
/// doesn't already provide — `MLSCrypto`'s `Labels.swift` covers
/// ExpandWithLabel/DeriveSecret/SignWithLabel/EncryptWithLabel/RefHash,
/// all defined once for any consumer; PSKLabel is specific to the PSK
/// secret computation and belongs here instead.
extension MLS.KeySchedule {
	/// `struct { PreSharedKeyID id; uint16 index; uint16 count; } PSKLabel;`
	/// where `PreSharedKeyID` is `uint8 psktype (1 = external) ++ opaque
	/// psk_id<V> ++ opaque psk_nonce<V>` — RFC 9420 only defines external
	/// and resumption PSKs, and this component only ever sees an opaque id
	/// and nonce (never a resumption PSK's group id / epoch), so `psktype`
	/// is fixed to `1` here rather than modeled as an open enum. A caller
	/// that needs resumption PSKs is a `MLSFraming`/profile concern, not
	/// this component's.
	static func pskLabel(id: Data, nonce: Data, index: UInt16, count: UInt16) throws -> Data {
		var writer = MLS.Writer()
		writer.writeUInt8(1)  // PSKType.external
		try writer.writeOpaque(id)
		try writer.writeOpaque(nonce)
		writer.writeUInt16(index)
		writer.writeUInt16(count)
		return writer.data
	}
}
