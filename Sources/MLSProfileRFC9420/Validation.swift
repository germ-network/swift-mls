import Foundation
import MLSCodec
import MLSCrypto
import MLSTreeMath

extension MLS.RFC9420.Credential {
	public var credentialType: MLS.RFC9420.CredentialType {
		switch self {
		case .basic: MLS.RFC9420.CredentialType(.basic)
		case .other(let type, _): type
		}
	}
}

extension MLS.RFC9420 {
	/// `struct { ExtensionType extension_types<V>; ProposalType
	/// proposal_types<V>; CredentialType credential_types<V>; }
	/// RequiredCapabilities;` — RFC 9420 §11.1.
	public struct RequiredCapabilities: Sendable, Equatable, MLSCodable {
		public var extensionTypes: [ExtensionType]
		public var proposalTypes: [ProposalType]
		public var credentialTypes: [CredentialType]

		public init(
			extensionTypes: [ExtensionType] = [], proposalTypes: [ProposalType] = [],
			credentialTypes: [CredentialType] = []
		) {
			self.extensionTypes = extensionTypes
			self.proposalTypes = proposalTypes
			self.credentialTypes = credentialTypes
		}

		public func encode(to writer: inout MLS.Writer) throws {
			try writer.encodeVector(extensionTypes)
			try writer.encodeVector(proposalTypes)
			try writer.encodeVector(credentialTypes)
		}

		public init(from reader: inout MLS.Reader) throws {
			extensionTypes = try reader.decodeVector()
			proposalTypes = try reader.decodeVector()
			credentialTypes = try reader.decodeVector()
		}
	}

	/// The extension and proposal types RFC 9420 §7.2 calls "default":
	/// assumed implemented by every client, and therefore "MUST NOT be
	/// listed" in a leaf's `capabilities`. Load-bearing in two checks
	/// below, because two other sections read as if they contradict §7.2:
	///
	/// - §7.3 says *unconditionally* that every ID in a leaf's
	///   `extensions` must be listed in `capabilities.extensions` — but a
	///   leaf carrying `application_id` (a default type) is *forbidden*
	///   from listing it. §7.2's own wording resolves it: "The types of
	///   any **non-default** extensions that appear ... MUST be included."
	///   Default types are exempt.
	/// - §11.1 says default proposal and extension types "need not be
	///   listed in RequiredCapabilities in order to be safely used", and a
	///   `required_capabilities` that *does* name one would be a
	///   requirement no §7.2-conforming leaf could ever satisfy. Default
	///   types are exempt there too. **Credential types are explicitly
	///   not exempt** — §11.1: "Note that this is not true for credential
	///   types."
	///
	/// The peers split on this (OpenMLS exempts default types, mls-rs
	/// does not), which is exactly the situation where the text, not a
	/// peer, decides.
	static let defaultExtensionTypes: Set<ExtensionType> = [
		.init(.applicationID), .init(.ratchetTree), .init(.requiredCapabilities),
		.init(.externalPub), .init(.externalSenders),
	]
	static let defaultProposalTypes: Set<ProposalType> = [
		.init(.add), .init(.update), .init(.remove), .init(.preSharedKey),
		.init(.reInit), .init(.externalInit), .init(.groupContextExtensions),
	]
}

extension [MLS.RFC9420.Extension] {
	/// The decoded `required_capabilities` extension, or nil if absent.
	public func requiredCapabilities() throws -> MLS.RFC9420.RequiredCapabilities? {
		guard
			let ext = first(where: {
				$0.type == MLS.RFC9420.ExtensionType(.requiredCapabilities)
			})
		else { return nil }
		var reader = MLS.Reader(ext.data)
		let parsed = try MLS.RFC9420.RequiredCapabilities(from: &reader)
		try reader.finish()
		return parsed
	}
}

extension MLS.RFC9420.LeafNode {
	/// Where a leaf under §7.3 policy validation was found — the
	/// discriminator for §7.3's `leaf_node_source` bullet, richer than
	/// `Placement` because the Update case needs the leaf being replaced
	/// (§7.3: "verify ... that encryption_key represents a different
	/// public key than the encryption_key in the leaf node being
	/// replaced").
	public enum ValidationContext: Sendable {
		/// In a KeyPackage: source must be `key_package`.
		case keyPackage
		/// In an Update proposal replacing `replacing`: source must be
		/// `update`, and the encryption key must differ from the replaced
		/// leaf's.
		case updateProposal(replacing: MLS.RFC9420.LeafNode)
		/// In a Commit's UpdatePath: source must be `commit`.
		case commitUpdatePath
		/// Met in a ratchet-tree walk (joining): any source is legal —
		/// a member added and never updated keeps `key_package`.
		case treeWalk
	}

	/// RFC 9420 §7.3's policy half — everything except the signature
	/// (`verifySignature`) and §5.3.1 credential validation (an
	/// application concern; credentials here are opaque by design).
	///
	/// `currentTime` nil skips the lifetime range check. That is the
	/// deliberate receive-path default, not an oversight: §7.3 makes the
	/// receive-side lifetime check RECOMMENDED, explicitly not mandatory
	/// ("the LeafNode might have expired in the time between when the
	/// message was sent and when it was received") — and concretely,
	/// hundreds of official-vector leaves carry a `not_after` in 2024, so
	/// a "now" default would fail the conformance gate on expired but
	/// otherwise valid history.
	///
	/// `maxTotalLifetime` nil skips §7.2's maximum-total-lifetime bound.
	/// Also deliberate: §7.2 makes the maximum an *application* MUST
	/// ("Applications MUST define a maximum total lifetime"), and most
	/// official-vector leaves carry `not_after == UInt64.max`, so any
	/// library-chosen default would both usurp the application's decision
	/// and fail the gate.
	public func validatePolicy(
		_ context: ValidationContext,
		groupRequirements: MLS.RFC9420.RequiredCapabilities?,
		memberCredentialTypes: some Collection<MLS.RFC9420.CredentialType>,
		memberCapabilities: some Collection<MLS.RFC9420.Capabilities>,
		currentTime: UInt64? = nil,
		maxTotalLifetime: UInt64? = nil
	) throws {
		// §7.3: "Verify that the extensions in the LeafNode are supported
		// by checking that the ID for each extension in the extensions
		// field is listed in the capabilities.extensions field" — with
		// §7.2's default types exempt (see `defaultExtensionTypes`).
		for ext in extensions {
			guard
				MLS.RFC9420.defaultExtensionTypes.contains(ext.type)
					|| capabilities.extensions.contains(ext.type)
			else {
				throw MLS.RFC9420.GroupError.unsupportedExtensionInLeaf(ext.type)
			}
		}

		// §7.3: the leaf's own credential type must be in its own
		// capabilities (a leaf that doesn't support its own credential is
		// incoherent), and — mutual support — supported by every member,
		// while this leaf supports every credential type in use.
		let ownType = credential.credentialType
		guard capabilities.credentials.contains(ownType) else {
			throw MLS.RFC9420.GroupError.credentialTypeNotInOwnCapabilities
		}
		for member in memberCapabilities where !member.credentials.contains(ownType) {
			throw MLS.RFC9420.GroupError.credentialTypeUnsupportedByMember
		}
		for inUse in memberCredentialTypes where !capabilities.credentials.contains(inUse) {
			throw MLS.RFC9420.GroupError.memberCredentialUnsupportedByLeaf
		}

		// §7.3: required_capabilities. Default extension/proposal types
		// exempt per §11.1; credential types never exempt.
		if let required = groupRequirements {
			for type in required.extensionTypes
			where
				!MLS.RFC9420.defaultExtensionTypes.contains(type)
				&& !capabilities.extensions.contains(type)
			{
				throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
			}
			for type in required.proposalTypes
			where
				!MLS.RFC9420.defaultProposalTypes.contains(type)
				&& !capabilities.proposals.contains(type)
			{
				throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
			}
			for type in required.credentialTypes
			where !capabilities.credentials.contains(type) {
				throw MLS.RFC9420.GroupError.requiredCapabilitiesNotMet
			}
		}

		// §7.3: the source discriminator, and Update's changed-key rule.
		switch (context, source) {
		case (.keyPackage, .keyPackage), (.commitUpdatePath, .commit), (.treeWalk, _):
			break
		case (.updateProposal(let replaced), .update):
			guard encryptionKey != replaced.encryptionKey else {
				throw MLS.RFC9420.GroupError.updateDidNotChangeEncryptionKey
			}
		case (.keyPackage, _), (.commitUpdatePath, _), (.updateProposal, _):
			throw MLS.RFC9420.GroupError.wrongLeafNodeSource
		}

		// §7.3 lifetime bullets — see the doc comment for why both
		// bounds are optional.
		if case .keyPackage(let lifetime) = source {
			if let now = currentTime {
				guard lifetime.notBefore <= now, now <= lifetime.notAfter else {
					throw MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange
				}
			}
			if let maxTotal = maxTotalLifetime {
				let total = lifetime.notAfter.subtractingReportingOverflow(
					lifetime.notBefore)
				guard !total.overflow, total.partialValue <= maxTotal else {
					throw MLS.RFC9420.GroupError.leafNodeLifetimeTooLong
				}
			}
		}
	}
}

extension MLS.RFC9420.KeyPackage {
	/// The KeyPackage's own signature — RFC 9420 §10.1's third bullet.
	/// The RFC's literal wording is "using the public key in
	/// leaf_node.credential", but a basic credential carries only an
	/// identity, no key; the key that verifies (confirmed against the
	/// official vectors, and what both peers implement) is
	/// `leaf_node.signature_key`.
	public func verifySignature(_ provider: any MLS.CipherSuiteProvider) throws {
		let valid = try MLS.verifyWithLabel(
			provider, publicKey: leafNode.signatureKey, label: "KeyPackageTBS",
			content: try toBeSigned(), signature: signature)
		guard valid else { throw MLS.CryptoError.signatureVerificationFailed }
	}

	/// RFC 9420 §10.1, all four bullets, for a KeyPackage received in an
	/// Add proposal. §7.3's signature half runs too — an Add is exactly
	/// where an unverified leaf could otherwise enter the tree.
	public func validate(
		_ provider: any MLS.CipherSuiteProvider,
		groupContext: MLS.RFC9420.GroupContext,
		groupRequirements: MLS.RFC9420.RequiredCapabilities?,
		memberCredentialTypes: some Collection<MLS.RFC9420.CredentialType>,
		memberCapabilities: some Collection<MLS.RFC9420.Capabilities>
	) throws {
		// Structural checks first, signatures last: §10.1 lists bullets,
		// not a sequence, and a structural violation (a reused init key,
		// a wrong suite) also breaks the signature it sits under -- so
		// checking structure first is what makes each rejection
		// *distinguishable*, and therefore testable without a signing
		// oracle.
		guard version == groupContext.version else {
			throw MLS.RFC9420.GroupError.protocolVersionMismatch
		}
		guard cipherSuite == groupContext.cipherSuite else {
			throw MLS.RFC9420.GroupError.cipherSuiteMismatch
		}
		guard leafNode.encryptionKey != initKey else {
			throw MLS.RFC9420.GroupError.keyPackageInitKeyReused
		}
		try leafNode.validatePolicy(
			.keyPackage,
			groupRequirements: groupRequirements,
			memberCredentialTypes: memberCredentialTypes,
			memberCapabilities: memberCapabilities)
		try verifySignature(provider)
		try leafNode.verifySignature(provider, placement: .keyPackage)
	}
}
