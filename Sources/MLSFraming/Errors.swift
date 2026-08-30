import MLSCodec

extension MLS {
	public enum FramingError: Error, Sendable, Equatable {
		case unknownSenderType(UInt8)
		case privateMessageRequiresMemberSender
		case signatureRequired
		case paddingNotZero
		case membershipTagMissing
		case membershipTagMismatch
		case confirmationTagMissing
		case confirmationTagMismatch
		case applicationContentMustNotBePublic
		case contentTypeMismatch
	}
}
