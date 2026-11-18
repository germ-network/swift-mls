import Foundation
import MLSCodec
import MLSVectorSupport
import Testing

@testable import MLSCrypto

@Suite("HPKE public-key validation")
struct HpkePublicKeyValidationTests {
	static let suites: [MLS.CipherSuite] = [
		.curve25519Aes128, .p256Aes128, .curve25519ChaCha, .p521Aes256, .p384Aes256,
	]
	static let nistSuites: [MLS.CipherSuite] = [.p256Aes128, .p521Aes256, .p384Aes256]
	static let x25519Suites: [MLS.CipherSuite] = [.curve25519Aes128, .curve25519ChaCha]

	/// Every X25519 u-coordinate of small order, plus encodings that reduce
	/// to one: non-canonical u = p, p + 1 (RFC 7748 §5: process as reduced)
	/// and 0 with bit 255 set (§5: mask the most significant bit).
	static let smallOrderX25519: [Data] = [
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
	].map { Data(hex: $0) }

	/// Large-order keys in unusual encodings, which must be accepted:
	/// non-canonical u = p + 2 and 9 with bit 255 set (RFC 7748 §5 says to
	/// reduce the former and mask the latter).
	static let largeOrderNonCanonicalX25519: [Data] = [
		"efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0900000000000000000000000000000000000000000000000000000000000080",
	].map { Data(hex: $0) }

	static func provider(_ suite: MLS.CipherSuite) throws -> any MLS.CipherSuiteProvider {
		try #require(SwiftCryptoProvider().cipherSuiteProvider(for: suite))
	}

	static func expectInvalid(_ body: () throws -> Void) {
		#expect {
			try body()
		} throws: { error in
			if case MLS.CryptoError.invalidPublicKey = error { return true }
			return false
		}
	}

	@Test("accepts freshly generated keys", arguments: suites)
	func acceptsGeneratedKeys(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		try provider.validateHpkePublicKey(publicKey)
	}

	@Test("accepts every recipient key in the HPKE vectors for our suites")
	func acceptsEveryHpkeVectorKey() throws {
		let matches = HpkeVectorTests.matches
		#expect(!matches.isEmpty)
		for (vector, suite) in matches {
			try Self.provider(suite).validateHpkePublicKey(.init(vector.pkRm.bytes))
		}
	}

	@Test("rejects a key one byte short or one byte long", arguments: suites)
	func rejectsWrongLengthKeys(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		Self.expectInvalid {
			try provider.validateHpkePublicKey(.init(publicKey.data.dropLast()))
		}
		Self.expectInvalid {
			try provider.validateHpkePublicKey(.init(publicKey.data + [0]))
		}
	}

	@Test(
		"rejects infinity, compressed prefix, off-curve and out-of-range points",
		arguments: nistSuites)
	func rejectsInvalidNISTPoints(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		let key = try provider.hpkeGenerateKeyPair().1.data
		let coordinate = (key.count - 1) / 2
		let fieldPrime: Data =
			switch suite {
			case .p256Aes128:
				Data(
					hex:
						"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
				)
			case .p384Aes256:
				Data(
					hex:
						"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
				)
			default:
				Data([0x01]) + Data(repeating: 0xff, count: coordinate - 1)
			}
		// y of the on-curve point with x = 0, so (p, y) is rejected only by
		// the coordinate range check, and (0, y) is a valid control.
		let yAtXZero: Data =
			switch suite {
			case .p256Aes128:
				Data(
					hex:
						"66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
				)
			case .p384Aes256:
				Data(
					hex:
						"c306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793406d80d2b91ad54f9048bd487af1ade1"
				)
			default:
				Data(
					hex:
						"012df13601594a883ef2d935e44bb90bf4d6619b74e52af7552f97769011c0719eb439cfab2a88d40fe59a2bed1f43557169a2d0a2ccd280c607b92bbf51ffe0b078"
				)
			}
		try provider.validateHpkePublicKey(
			.init(Data([0x04]) + Data(repeating: 0, count: coordinate) + yAtXZero))

		var offCurve = key
		offCurve[offCurve.endIndex - 1] ^= 0x01
		var compressedPrefix = key
		compressedPrefix[compressedPrefix.startIndex] = 0x02

		let invalid: [Data] = [
			Data([0x00]),
			Data([0x04]) + Data(repeating: 0, count: 2 * coordinate),
			offCurve,
			compressedPrefix,
			Data([0x04]) + fieldPrime + yAtXZero,
		]
		for bytes in invalid {
			Self.expectInvalid { try provider.validateHpkePublicKey(.init(bytes)) }
		}
	}

	@Test("rejects every small-order X25519 key", arguments: x25519Suites)
	func rejectsSmallOrderX25519Keys(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		for u in Self.smallOrderX25519 {
			Self.expectInvalid { try provider.validateHpkePublicKey(.init(u)) }
		}
	}

	@Test("accepts non-canonical X25519 keys of large order", arguments: x25519Suites)
	func acceptsLargeOrderNonCanonicalX25519Keys(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		for u in Self.largeOrderNonCanonicalX25519 {
			try provider.validateHpkePublicKey(.init(u))
		}
	}

	@Test("a conformer without its own check rejects exactly what its hpkeSeal rejects")
	func defaultValidationProbeSeals() throws {
		let inner = try Self.provider(.p256Aes128)
		let wrapper = ForwardingProvider(inner: inner)
		let (_, publicKey) = try inner.hpkeGenerateKeyPair()
		try wrapper.validateHpkePublicKey(publicKey)
		Self.expectInvalid {
			try wrapper.validateHpkePublicKey(.init(publicKey.data.dropLast()))
		}
	}

	@Test("hpkeSeal refuses a small-order X25519 key on every backend", arguments: x25519Suites)
	func sealRefusesSmallOrderX25519Keys(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		for u in Self.smallOrderX25519 {
			Self.expectInvalid {
				_ = try provider.hpkeSeal(
					publicKey: .init(u), info: Data(), aad: nil,
					plaintext: Data([1]))
			}
		}
	}

	@Test("hpkeSeal reports an invalid NIST point as invalidPublicKey", arguments: nistSuites)
	func sealRefusesInvalidNISTPoints(_ suite: MLS.CipherSuite) throws {
		let provider = try Self.provider(suite)
		var offCurve = try provider.hpkeGenerateKeyPair().1.data
		offCurve[offCurve.endIndex - 1] ^= 0x01
		Self.expectInvalid {
			_ = try provider.hpkeSeal(
				publicKey: .init(offCurve), info: Data(), aad: nil,
				plaintext: Data([1]))
		}
	}
}

@Suite("Ed25519 public-key encodings")
struct Ed25519PublicKeyEncodingTests {
	static let suites: [MLS.CipherSuite] = [.curve25519Aes128, .curve25519ChaCha]

	/// RFC 8032 §5.1.3 says decoding fails for these: y ≥ p, or x = 0 with
	/// the sign bit set.
	static let nonCanonical: [Data] = [
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	].map { Data(hex: $0) }

	static let identity = Data(
		hex: "0100000000000000000000000000000000000000000000000000000000000000")

	/// The eight canonical small-order encodings (orders 1, 2, 4, 4, 8, 8, 8, 8).
	static let canonicalSmallOrder: [Data] = [
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	].map { Data(hex: $0) }

	@Test("verify rejects a non-canonical key encoding", arguments: suites)
	func verifyRejectsNonCanonicalKeys(_ suite: MLS.CipherSuite) throws {
		let provider = try HpkePublicKeyValidationTests.provider(suite)
		let signature = Self.identity + Data(repeating: 0, count: 32)
		for key in Self.nonCanonical {
			HpkePublicKeyValidationTests.expectInvalid {
				_ = try provider.verify(
					publicKey: .init(key), content: Data("m".utf8),
					signature: signature)
			}
		}
	}

	/// Canonical small-order keys stay accepted by policy, matching every
	/// peer: RFC 8032 §5.1.7 has no rule rejecting them. The identity key
	/// admits R = identity, S = 0 for any message on both backends.
	@Test("canonical small-order keys are not rejected", arguments: suites)
	func canonicalSmallOrderKeysAreAccepted(_ suite: MLS.CipherSuite) throws {
		let provider = try HpkePublicKeyValidationTests.provider(suite)
		let signature = Self.identity + Data(repeating: 0, count: 32)
		for key in Self.canonicalSmallOrder {
			#expect(throws: Never.self) {
				_ = try provider.verify(
					publicKey: .init(key), content: Data("m".utf8),
					signature: signature)
			}
		}
		#expect(
			try provider.verify(
				publicKey: .init(Self.identity), content: Data("m".utf8),
				signature: signature))
	}
}

/// Forwards every requirement except `validateHpkePublicKey`, so the
/// protocol's default is the one under test.
private struct ForwardingProvider: MLS.CipherSuiteProvider {
	let inner: any MLS.CipherSuiteProvider

	var cipherSuite: MLS.CipherSuite { inner.cipherSuite }
	var hashSize: Int { inner.hashSize }
	var aeadKeySize: Int { inner.aeadKeySize }
	var aeadNonceSize: Int { inner.aeadNonceSize }
	var hpkeSecretKeySize: Int? { inner.hpkeSecretKeySize }

	func randomBytes(_ count: Int) -> Data { inner.randomBytes(count) }
	func hash(_ data: Data) throws -> Data { try inner.hash(data) }
	func kdfExtract(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws -> Data {
		try inner.kdfExtract(salt: salt, ikm: ikm)
	}
	func kdfExpand(prk: some ContiguousBytes, info: Data, length: Int) throws -> Data {
		try inner.kdfExpand(prk: prk, info: info, length: length)
	}
	func sign(privateKey: MLS.SignatureSecretKey, content: Data) throws -> Data {
		try inner.sign(privateKey: privateKey, content: content)
	}
	func verify(publicKey: MLS.SignaturePublicKey, content: Data, signature: Data) throws
		-> Bool
	{
		try inner.verify(publicKey: publicKey, content: content, signature: signature)
	}
	func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data {
		try inner.aeadSeal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
	}
	func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data {
		try inner.aeadOpen(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}
	func hpkeGenerateKeyPair() throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
		try inner.hpkeGenerateKeyPair()
	}
	func hpkeSeal(publicKey: MLS.HpkePublicKey, info: Data, aad: Data?, plaintext: Data)
		throws -> (enc: Data, ciphertext: Data)
	{
		try inner.hpkeSeal(publicKey: publicKey, info: info, aad: aad, plaintext: plaintext)
	}
	func hpkeOpen(
		enc: Data, secretKey: MLS.HpkeSecretKey, info: Data, aad: Data?, ciphertext: Data
	) throws -> Data {
		try inner.hpkeOpen(
			enc: enc, secretKey: secretKey, info: info, aad: aad, ciphertext: ciphertext
		)
	}
	func hpkeDeriveKeyPair(ikm: some ContiguousBytes) throws -> (
		MLS.HpkeSecretKey, MLS.HpkePublicKey
	) {
		try inner.hpkeDeriveKeyPair(ikm: ikm)
	}
}

extension Data {
	fileprivate init(hex: String) {
		var bytes: [UInt8] = []
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			bytes.append(UInt8(hex[index..<next], radix: 16)!)
			index = next
		}
		self.init(bytes)
	}
}
