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
	///
	/// Takes `id` already encoded, not built here: `PreSharedKeyID` itself
	/// (`uint8 psktype ++ select(psktype){...} ++ opaque psk_nonce<V>`) is
	/// a real wire type with two shapes — external and resumption — and
	/// this component has "no wire types" as an explicit design goal (see
	/// the project plan). An earlier version of this function
	/// built `PreSharedKeyID` inline with `psktype` fixed to external,
	/// which meant this component could not compute a correct PSK secret
	/// for a resumption PSK at all — caught once `MLSProfileRFC9420`
	/// defined `PreSharedKeyIdentifier` for real and had no way to reach
	/// this function's external-only assumption. The caller (a profile)
	/// now encodes its own `PreSharedKeyID`-shaped type and passes the
	/// bytes straight through.
	static func pskLabel(encodedID: Data, index: UInt16, count: UInt16) -> Data {
		var writer = MLS.Writer()
		writer.writeBytes(encodedID)
		writer.writeUInt16(index)
		writer.writeUInt16(count)
		return writer.data
	}
}
