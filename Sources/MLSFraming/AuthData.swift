import Foundation
import MLSCodec

/// Distinct `Data` wrappers per RFC 9420 role, matching `MLSCrypto/Keys.swift`'s
/// convention: a `Signature` can't be passed where a `MembershipTag` is
/// expected even though both are just bytes.
extension MLS {
	public struct Signature: Hashable, Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}

	/// `MAC`, RFC 9420's own alias for `opaque<V>` wherever a tag from
	/// `CipherSuiteProvider.mac` is carried on the wire.
	public struct MembershipTag: Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}

	public struct ConfirmationTag: Sendable, MLSCodable {
		public var data: Data
		public init(_ data: Data) { self.data = data }
		public func encode(to writer: inout MLS.Writer) throws {
			try writer.writeOpaque(data)
		}
		public init(from reader: inout MLS.Reader) throws {
			data = Data(try reader.readOpaque())
		}
	}
}

// Constant-time equality: swift-crypto exposes none generically (only
// per-primitive, e.g. HashedAuthenticationCode's own ==), and these two
// types are compared directly against attacker-supplied bytes during
// verification. mls-rs uses `subtle::ConstantTimeEq` for the same reason
// (membership_tag.rs, confirmation_tag.rs).
extension MLS.MembershipTag: Equatable {
	public static func == (lhs: Self, rhs: Self) -> Bool {
		MLS.constantTimeEqual(lhs.data, rhs.data)
	}
}

extension MLS.ConfirmationTag: Equatable {
	public static func == (lhs: Self, rhs: Self) -> Bool {
		MLS.constantTimeEqual(lhs.data, rhs.data)
	}
}

extension MLS {
	static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
		guard lhs.count == rhs.count else { return false }
		var diff: UInt8 = 0
		for (a, b) in zip(lhs, rhs) { diff |= a ^ b }
		return diff == 0
	}
}

extension MLS {
	/// RFC 9420 §6.1's `FramedContentAuthData`.
	///
	/// `signature` is `Optional` even though no RFC 9420 message ever
	/// omits it. A later elision-style profile (a commit whose
	/// authenticity rides on its path leaf's signature instead of a
	/// framing one) needs "absent" to be representable — and every type
	/// that transitively holds auth data would otherwise need reshaping to
	/// add it later: `AuthenticatedContent`, the TBM input, the
	/// confirmed-transcript-hash input, `PublicMessage`,
	/// `PrivateMessageContent`. Adding the `Optional` now is free.
	///
	/// Deliberately not `MLSCodable`: decoding needs `contentType` from
	/// outside (confirmation-tag presence depends on it, with no presence
	/// byte on the wire), which `init(from:)` has no way to receive.
	/// mls-rs makes the same call — `FramedContentAuthData::mls_decode` is
	/// an inherent function taking `content_type`, not a trait impl.
	public struct FramedContentAuthData: Sendable, Equatable {
		public var signature: Signature?
		/// Present exactly when the content type is `commit` — driven by
		/// content type, not an `optional<>` presence byte.
		public var confirmationTag: ConfirmationTag?

		public init(signature: Signature?, confirmationTag: ConfirmationTag?) {
			self.signature = signature
			self.confirmationTag = confirmationTag
		}
	}
}

extension MLS.FramedContentAuthData {
	/// `opaque signature<V>` followed by the confirmation tag iff
	/// `contentType == .commit`. Named for its policy, not a plain
	/// `MLSEncodable` conformance — a profile that elides the signature
	/// writes a presence byte instead, over this same shared type; Swift
	/// permits only one conformance per type, so the type is the shared
	/// seam and the codec is not.
	public func encodeRequiringSignature(
		contentType: MLS.ContentType, to writer: inout MLS.Writer
	) throws {
		guard let signature else { throw MLS.FramingError.signatureRequired }
		try signature.encode(to: &writer)
		if contentType == .commit {
			guard let confirmationTag else {
				throw MLS.FramingError.confirmationTagMissing
			}
			try confirmationTag.encode(to: &writer)
		}
	}

	public static func decodeRequiringSignature(
		contentType: MLS.ContentType, from reader: inout MLS.Reader
	) throws -> Self {
		let signature = try MLS.Signature(from: &reader)
		let confirmationTag =
			contentType == .commit ? try MLS.ConfirmationTag(from: &reader) : nil
		return Self(signature: signature, confirmationTag: confirmationTag)
	}
}
