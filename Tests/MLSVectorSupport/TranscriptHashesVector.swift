public struct TranscriptHashesVector: Decodable, Sendable {
	public let cipherSuite: UInt16
	public let confirmationKey: HexData
	public let authenticatedContent: HexData
	public let interimTranscriptHashBefore: HexData
	public let confirmedTranscriptHashAfter: HexData
	public let interimTranscriptHashAfter: HexData

	enum CodingKeys: String, CodingKey {
		case cipherSuite = "cipher_suite"
		case confirmationKey = "confirmation_key"
		case authenticatedContent = "authenticated_content"
		case interimTranscriptHashBefore = "interim_transcript_hash_before"
		case confirmedTranscriptHashAfter = "confirmed_transcript_hash_after"
		case interimTranscriptHashAfter = "interim_transcript_hash_after"
	}
}
