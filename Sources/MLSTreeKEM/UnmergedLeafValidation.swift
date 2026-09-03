import MLSCodec
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// Two separate requirements, checked together because both are
	/// properties of the same vector.
	///
	/// RFC 9420 §7.1: "The entries in the unmerged_leaves vector MUST be
	/// sorted in increasing order." *Strictly* increasing — adjacent
	/// equals are rejected, not merely tolerated as "still sorted." A
	/// duplicate isn't a tidiness nit: `resolution(of:)` maps every entry
	/// to a node index unconditionally, so a repeated entry appears twice
	/// in that node's resolution and shifts every later ciphertext
	/// position in an `UpdatePath`.
	///
	/// (mls-rs's `validate_unmerged` uses a non-strict `is_sorted()` here
	/// and would accept the duplicate; OpenMLS rejects it at decode with
	/// an adjacent-pair `<`. Following OpenMLS, and §7.1's own wording,
	/// rather than mls-rs.)
	///
	/// Then §12.4.3.1's "verify the integrity of the ratchet tree", the
	/// half `validateParentHashChain` doesn't cover: every entry must be
	/// justified by an actual leaf whose direct-path walk reaches that
	/// parent through nothing but blanks and "yes, I'm unmerged here"
	/// claims — this walk follows mls-rs's `validate_unmerged`, including
	/// its implicit coverage of "the leaf is a non-blank descendant" (a
	/// blank leaf is never walked at all, so any entry naming one is never
	/// consumed and fails the final check).
	public func validateUnmergedLeaves() throws {
		for i in stride(from: UInt32(1), to: serializedNodeCount, by: 2) {
			guard let p = parent(at: i) else { continue }
			guard
				zip(p.unmergedLeaves, p.unmergedLeaves.dropFirst())
					.allSatisfy({ $0.value < $1.value })
			else {
				throw MLS.TreeKEM.TreeError.unmergedLeavesNotSorted
			}
		}

		var remaining: [UInt32: Set<MLS.LeafIndex>] = [:]
		for i in stride(from: UInt32(1), to: serializedNodeCount, by: 2) {
			guard let p = parent(at: i), !p.unmergedLeaves.isEmpty else { continue }
			remaining[i] = Set(p.unmergedLeaves)
		}

		for (leafIndex, _) in nonBlankLeaves() {
			var n = 2 * leafIndex.value
			while let ancestor = MLS.TreeMath.parent(n, leafCount: leafCount) {
				guard !isBlank(at: ancestor) else {
					n = ancestor
					continue
				}
				guard let ancestorNode = parent(at: ancestor),
					ancestorNode.unmergedLeaves.contains(leafIndex)
				else {
					break
				}
				remaining[ancestor]?.remove(leafIndex)
				n = ancestor
			}
		}

		guard remaining.values.allSatisfy({ $0.isEmpty }) else {
			throw MLS.TreeKEM.TreeError.unmergedLeafNotAtExpectedPosition
		}
	}

	/// No encryption key may appear at more than one node in the tree.
	/// Deliberately broader than any single section states it: §12.4.3.1's
	/// bullet is scoped to parents ("Verify that the encryption key in the
	/// parent node does not appear in any other node of the tree"), §7.3
	/// covers the leaf side per-member ("Verify that the following fields
	/// are unique among the members of the group: signature_key,
	/// encryption_key"), and §16.7 states the general form ("The
	/// encryption and signature keys stored in the encryption_key and
	/// signature_key fields of ratchet tree nodes MUST be distinct from
	/// one another"). Checking all node kinds in one sweep covers all
	/// three at once — otherwise a resolution could hand a receiver a key
	/// it can't tell apart from its own, or two subtrees could silently
	/// share a path secret's key material.
	public func validateNoDuplicateEncryptionKeys() throws {
		var seen: Set<MLS.HpkePublicKey> = []
		for i in 0..<serializedNodeCount {
			let key: MLS.HpkePublicKey?
			switch node(at: i) {
			case .leaf(let record): key = record.encryptionKey
			case .parent(let parentNode): key = parentNode.encryptionKey
			case nil: key = nil
			}
			guard let key else { continue }
			guard seen.insert(key).inserted else {
				throw MLS.TreeKEM.TreeError.duplicateEncryptionKey(node: i)
			}
		}
	}
}
