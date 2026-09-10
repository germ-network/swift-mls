import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSFraming
import Testing

@testable import MLSProfileRFC9420

/// The opt-in seam for RFC 9420 §12.2's "non-default proposal type"s:
/// `Proposal.custom` encodes `type ‖ opaque<V>(body)`, `customProposalTypes`
/// selects which types a receiver decodes that way, and a FULL commit carries the
/// wrapped bytes into the signed, transcript-hashed content. Every receive-side
/// test here parses the sender's *bytes* — validating an in-memory `Proposal`
/// would never run the ambient decode path these tests exist to exercise.
@Suite("Custom (non-default) proposal seam (§12.1 / §12.2)")
struct CustomProposalTests {
	static let provider = ConstructedRejectionTests.provider

	/// 0x0008 — a non-default type that ALSO has a typed arm (`.appDataUpdate`),
	/// so under the ambient a wrapped body must decode as `.custom`, never typed.
	static let typedPoint = MLS.RFC9420.ProposalType(.appDataUpdate)
	/// A §17.4 "Reserved for Private Use" code point (0xF000–0xFFFF) no arm types.
	static let privatePoint = MLS.RFC9420.ProposalType(rawValue: 0xF001)
	/// Distinctive body bytes: the wire-tamper test locates them in the sealed
	/// message, and the no-ambient mutation reads `0xA1` as an operation code.
	static let body = Data((0..<16).map { UInt8(0xA0 + $0) })

	enum TestError: Error { case unexpectedFraming }

	/// `type ‖ opaque<V>(body)`, hand-built from the codec primitives.
	static func wrapped(_ type: MLS.RFC9420.ProposalType, _ body: Data) throws -> Data {
		var writer = MLS.Writer()
		try writer.encode(type)
		try writer.writeOpaque(body)
		return Data(writer.bytes)
	}

	/// Alice's FULL commit (path present) carrying one `.custom`, as the bytes she
	/// transmits. Non-mutating: `groupA` stays at its epoch.
	static func sentCommit(
		_ pair: ConstructedRejectionTests.Pair, type: MLS.RFC9420.ProposalType,
		body: Data, framing: MLS.RFC9420.Group.HandshakeFraming
	) throws -> Data {
		let transition = try pair.groupA.committing(
			Self.provider, proposals: [.proposal(.custom(type: type, body: body))],
			signingKey: pair.alice.signingKey, randomness: .generate(Self.provider),
			framing: framing)
		return try transition.output.message.mlsEncoded()
	}

	/// Bob parses `bytes` and validates the public commit, all under the ambient.
	static func receivePublic(
		_ pair: ConstructedRejectionTests.Pair, bytes: Data,
		accepting types: Set<MLS.RFC9420.ProposalType>
	) throws -> [MLS.RFC9420.CommitEffect] {
		try MLS.RFC9420.$customProposalTypes.withValue(types) {
			guard
				case .publicMessage(let commit) = try MLS.RFC9420.Message(
					mlsEncoded: bytes)
			else { throw TestError.unexpectedFraming }
			let pending = try pair.groupB.validating(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
			return pending.effects.events
		}
	}

	// MARK: codec

	@Test(
		"`.custom` encodes `type ‖ opaque<V>(body)`",
		arguments: [CustomProposalTests.typedPoint, CustomProposalTests.privatePoint])
	func encodesWrapped(type: MLS.RFC9420.ProposalType) throws {
		let proposal = MLS.RFC9420.Proposal.custom(type: type, body: Self.body)
		#expect(proposal.type == type)
		#expect(try proposal.mlsEncoded() == Self.wrapped(type, Self.body))
	}

	/// The load-bearing codec property: the receiver recomputes the transcript
	/// hash from a RE-ENCODE of the decoded content, so decode → encode must be
	/// byte-exact — and at 0x0008 the ambient must beat the typed arm.
	@Test(
		"under the ambient a wrapped body decodes as `.custom` and re-encodes byte-exact",
		arguments: [CustomProposalTests.typedPoint, CustomProposalTests.privatePoint])
	func decodesUnderAmbient(type: MLS.RFC9420.ProposalType) throws {
		let bytes = try Self.wrapped(type, Self.body)
		let decoded = try MLS.RFC9420.$customProposalTypes.withValue([type]) {
			try MLS.RFC9420.Proposal(mlsEncoded: bytes)
		}
		#expect(decoded == .custom(type: type, body: Self.body))
		#expect(try decoded.mlsEncoded() == bytes)
	}

	@Test("without the ambient a typed 0x0008 still decodes as `.appDataUpdate`")
	func defaultPathKeepsTypedArm() throws {
		#expect(MLS.RFC9420.customProposalTypes.isEmpty)
		let proposal = MLS.RFC9420.Proposal.appDataUpdate(
			.init(componentID: 0x1234, operation: .update(Data([9]))))
		#expect(try MLS.RFC9420.Proposal(mlsEncoded: try proposal.mlsEncoded()) == proposal)
	}

	@Test("without the ambient an unknown type is still `unknownProposalType`")
	func defaultPathStillRejectsUnknown() throws {
		let bytes = try Self.wrapped(Self.privatePoint, Self.body)
		#expect(throws: MLS.RFC9420.WireError.unknownProposalType(0xF001)) {
			try MLS.RFC9420.Proposal(mlsEncoded: bytes)
		}
	}

	/// The decode half of the default-type guard: naming a default type in the
	/// set never redirects its spec-defined body away from the typed arm.
	@Test("a default type in the ambient set is ignored: `.remove` stays typed")
	func defaultTypeInSetIgnored() throws {
		let proposal = MLS.RFC9420.Proposal.remove(MLS.LeafIndex(value: 3))
		let bytes = try proposal.mlsEncoded()
		let decoded = try MLS.RFC9420.$customProposalTypes.withValue([.init(.remove)]) {
			try MLS.RFC9420.Proposal(mlsEncoded: bytes)
		}
		#expect(decoded == proposal)
	}

	// MARK: emit guards

	@Test("`.custom` at a default type is refused at commit construction")
	func customAtDefaultTypeRefused() throws {
		let pair = try ConstructedRejectionTests.pair()
		#expect(
			throws: MLS.RFC9420.GroupError.customProposalUsesDefaultType(.init(.update))
		) {
			_ = try pair.groupA.committing(
				Self.provider,
				proposals: [
					.proposal(.custom(type: .init(.update), body: Self.body))
				],
				signingKey: pair.alice.signingKey,
				randomness: .generate(Self.provider))
		}
	}

	@Test("`.custom` and a typed arm at one code point cannot share a commit")
	func customConflictingWithTypedArmRefused() throws {
		let pair = try ConstructedRejectionTests.pair()
		let typed = MLS.RFC9420.Proposal.appDataUpdate(
			.init(componentID: 0xFF01, operation: .remove))
		#expect(
			throws: MLS.RFC9420.GroupError.customProposalConflictsWithTypedArm(
				Self.typedPoint)
		) {
			_ = try pair.groupA.committing(
				Self.provider,
				proposals: [
					.proposal(.custom(type: Self.typedPoint, body: Self.body)),
					.proposal(typed),
				],
				signingKey: pair.alice.signingKey,
				randomness: .generate(Self.provider))
		}
	}

	// MARK: commit integration — the receiver parses the sender's bytes

	/// A matching confirmation tag proves the wrapped bytes Bob re-encoded are the
	/// ones Alice signed and hashed into the transcript (§8.2's input is the
	/// encoded content, which the test also checks contains them verbatim).
	@Test("a wrapped custom proposal rides a full PUBLIC commit: validates from bytes")
	func publicCommitRoundTrip() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bytes = try Self.sentCommit(
			pair, type: Self.typedPoint, body: Self.body, framing: .publicMessage)

		let events = try MLS.RFC9420.$customProposalTypes.withValue([Self.typedPoint]) {
			guard
				case .publicMessage(let commit) = try MLS.RFC9420.Message(
					mlsEncoded: bytes),
				case .commit(let framed) = commit.content.content
			else { throw TestError.unexpectedFraming }
			#expect(framed.path != nil, "a FULL commit")
			let encodedContent = try commit.content.mlsEncoded()
			#expect(
				try encodedContent.range(
					of: Self.wrapped(Self.typedPoint, Self.body)) != nil,
				"the wrapped bytes are in the signed FramedContent")
			// Pin the body directly into the confirmed-transcript-hash INPUT (§8.2:
			// wire_format ‖ content ‖ signature — the same helper the receiver hashes
			// at CommitProcessing step 11), so the property survives a commit that is
			// merely well-signed: drop `content` from that input and this fails while
			// every framing check still passes. The `range(of:)` over `content` above
			// cannot see that regression on its own.
			let signed = MLS.Framing.SignedContent(
				protocolVersion: .mls10, wireFormat: .publicMessage,
				encodedContent: encodedContent, encodedGroupContext: nil)
			var sigWriter = MLS.Writer()
			try sigWriter.encode(#require(commit.auth.signature))
			#expect(
				try signed.confirmedTranscriptHashInput(
					encodedSignature: Data(sigWriter.bytes)
				).range(of: Self.wrapped(Self.typedPoint, Self.body)) != nil,
				"the wrapped bytes are inside the confirmed-transcript-hash input")
			let pending = try pair.groupB.validating(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
			return pending.effects.events
		}
		#expect(events.contains(.customProposal(type: Self.typedPoint, body: Self.body)))
	}

	/// Private framing is where *library* code performs the decode (inside the
	/// AEAD open), so the ambient must reach it through `validating`.
	@Test("a wrapped custom proposal rides a full PRIVATE commit: validates from bytes")
	func privateCommitRoundTrip() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bytes = try Self.sentCommit(
			pair, type: Self.typedPoint, body: Self.body, framing: .privateMessage)

		let events = try MLS.RFC9420.$customProposalTypes.withValue([Self.typedPoint]) {
			guard
				case .privateMessage(let commit) = try MLS.RFC9420.Message(
					mlsEncoded: bytes)
			else { throw TestError.unexpectedFraming }
			let transition = try pair.groupB.validating(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
			switch transition.takeOutput() {
			case .pending(let pending): return pending.effects.events
			case .rejected(let rejection): throw rejection.reason
			}
		}
		#expect(events.contains(.customProposal(type: Self.typedPoint, body: Self.body)))
	}

	/// Send and receive report the same effects; customs follow the membership
	/// stream in proposal-list order, one per proposal.
	@Test("custom effects are reported in proposal-list order, identically on both sides")
	func effectsInListOrder() throws {
		let pair = try ConstructedRejectionTests.pair()
		let other = Data([0x01, 0x02])
		let transition = try pair.groupA.committing(
			Self.provider,
			proposals: [
				.proposal(.custom(type: Self.privatePoint, body: other)),
				.proposal(.custom(type: Self.typedPoint, body: Self.body)),
			],
			signingKey: pair.alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		let bytes = try transition.output.message.mlsEncoded()
		let received = try Self.receivePublic(
			pair, bytes: bytes, accepting: [Self.privatePoint, Self.typedPoint])
		let customs = received.filter {
			if case .customProposal = $0 { true } else { false }
		}
		#expect(
			customs == [
				.customProposal(type: Self.privatePoint, body: other),
				.customProposal(type: Self.typedPoint, body: Self.body),
			])
		#expect(transition.takeOutput().pending.effects.events == received)
	}

	// MARK: mutations — each must fail for the RIGHT reason

	/// 3a: the opt-in is load-bearing. Without the ambient, 0x0008 takes the typed
	/// `AppDataUpdate` arm, which reads `component_id = 0x10A0` off the length
	/// byte + first body byte and then `0xA1` as the operation — not an op code.
	@Test("3a: without the ambient a wrapped 0x0008 chokes on the typed arm (public)")
	func noAmbientTypedArmChokesPublic() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bytes = try Self.sentCommit(
			pair, type: Self.typedPoint, body: Self.body, framing: .publicMessage)
		#expect(throws: MLS.CodecError.unknownEnumValue(0xA1)) {
			_ = try MLS.RFC9420.Message(mlsEncoded: bytes)
		}
	}

	@Test("3a: without the ambient a wrapped 0x0008 chokes on the typed arm (private)")
	func noAmbientTypedArmChokesPrivate() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bytes = try Self.sentCommit(
			pair, type: Self.typedPoint, body: Self.body, framing: .privateMessage)
		guard case .privateMessage(let commit) = try MLS.RFC9420.Message(mlsEncoded: bytes)
		else { throw TestError.unexpectedFraming }
		#expect(throws: MLS.CodecError.unknownEnumValue(0xA1)) {
			_ = try pair.groupB.validating(
				Self.provider, commit: commit, proposals: .init(), psk: { _ in nil }
			)
		}
	}

	@Test("3a: without the ambient a wrapped private-use type is `unknownProposalType`")
	func noAmbientUnknownTypeRejected() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bytes = try Self.sentCommit(
			pair, type: Self.privatePoint, body: Self.body, framing: .publicMessage)
		#expect(throws: MLS.RFC9420.WireError.unknownProposalType(0xF001)) {
			_ = try MLS.RFC9420.Message(mlsEncoded: bytes)
		}
	}

	/// 3b: one body byte flipped post-seal. The wrapped body sits inside the
	/// framing-authenticated content, so the tamper fails framing authentication
	/// (`verifyPublic` checks the signature first, then the membership tag; either
	/// surfaces as `signatureVerificationFailed`) before anything reaches the
	/// confirmation tag.
	@Test("3b: a body byte flipped on the wire fails framing authentication")
	func wireTamperFailsSignature() throws {
		let pair = try ConstructedRejectionTests.pair()
		var bytes = try Self.sentCommit(
			pair, type: Self.typedPoint, body: Self.body, framing: .publicMessage)
		let range = try #require(bytes.range(of: Self.body))
		bytes[range.lowerBound] ^= 0xFF
		#expect {
			_ = try Self.receivePublic(pair, bytes: bytes, accepting: [Self.typedPoint])
		} throws: { error in
			guard case MLS.CryptoError.signatureVerificationFailed = error else {
				return false
			}
			return true
		}
	}

	/// 3c: a validly framed commit whose confirmation tag was computed over a
	/// DIFFERENT transcript is rejected at the tag, after every framing check passes.
	/// Alice's genuine commit over B′ yields a path and a tag over B′; re-framing that
	/// path with body B — re-signed and membership-tagged by Alice — clears signature
	/// and membership authentication and reaches step 15, where the tag (bound to B′'s
	/// transcript) mismatches the receiver's over B's. This pins that the tag check is
	/// REACHED for a custom-bearing commit; the body's presence in the transcript
	/// input itself is pinned directly in `publicCommitRoundTrip` (this crafted shape
	/// re-signs, so it cannot separate body-binding from signature-binding).
	@Test("3c: a validly framed commit tagged over a different transcript fails the tag")
	func bodyOutsideTagRejected() throws {
		let pair = try ConstructedRejectionTests.pair()
		let bodyPrime = Data(Self.body.reversed())
		let real = try pair.groupA.committing(
			Self.provider,
			proposals: [.proposal(.custom(type: Self.typedPoint, body: bodyPrime))],
			signingKey: pair.alice.signingKey, randomness: .generate(Self.provider),
			framing: .publicMessage)
		guard case .publicMessage(let realMessage) = real.output.message,
			case .commit(let realCommit) = realMessage.content.content,
			let tagOverPrime = realMessage.auth.confirmationTag
		else { throw TestError.unexpectedFraming }

		// The path secrets are encrypted against the provisional GroupContext,
		// which predates this commit's transcript — so the same path decaps
		// whatever the proposal body is.
		let content = MLS.RFC9420.FramedContent(
			groupID: pair.groupA.context.groupID, epoch: pair.groupA.context.epoch,
			sender: .member(pair.groupA.myLeafIndex), authenticatedData: Data(),
			content: .commit(
				.init(
					proposals: [
						.proposal(
							.custom(
								type: Self.typedPoint,
								body: Self.body))
					],
					path: realCommit.path)))
		let crafted = try MLS.RFC9420.protectPublic(
			Self.provider, content: content, groupContext: pair.groupA.context,
			confirmationTag: tagOverPrime, signingKey: pair.alice.signingKey,
			membershipKey: pair.groupA.epoch.membershipKey)
		let bytes = try MLS.RFC9420.Message.publicMessage(crafted).mlsEncoded()

		#expect(throws: MLS.RFC9420.GroupError.confirmationTagMismatch) {
			_ = try Self.receivePublic(pair, bytes: bytes, accepting: [Self.typedPoint])
		}
	}
}
