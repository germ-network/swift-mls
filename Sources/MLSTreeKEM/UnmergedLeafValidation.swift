import MLSCodec
import MLSTreeMath

extension MLS.TreeKEM.RatchetTree {
	/// RFC 9420 §12.4.3.1's "verify the integrity of the ratchet tree",
	/// the half `validateParentHashChain` doesn't cover: every
	/// `unmerged_leaves` entry must be sorted ascending, and every entry
	/// must be justified by an actual leaf whose direct-path walk reaches
	/// that parent through nothing but blanks and "yes, I'm unmerged
	/// here" claims — mirrors mls-rs's `validate_unmerged` exactly,
	/// including its implicit coverage of "the leaf is a non-blank
	/// descendant" (a blank leaf is never walked at all, so any entry
	/// naming one is never consumed and fails the final check).
	public func validateUnmergedLeaves() throws {
		for i in stride(from: UInt32(1), to: physicalNodeCount, by: 2) {
			guard let p = parent(at: i) else { continue }
			guard
				p.unmergedLeaves
					== p.unmergedLeaves.sorted(by: { $0.value < $1.value })
			else {
				throw MLS.TreeKEM.TreeError.unmergedLeavesNotSorted
			}
		}

		var remaining: [UInt32: Set<MLS.LeafIndex>] = [:]
		for i in stride(from: UInt32(1), to: physicalNodeCount, by: 2) {
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

	/// RFC 9420 §12.4.3.1's key-uniqueness requirement: no encryption key
	/// (leaf or parent) may appear at more than one node in the tree —
	/// otherwise a resolution could hand a receiver a key it can't tell
	/// apart from its own, or two subtrees could silently share a path
	/// secret's key material.
	public func validateNoDuplicateEncryptionKeys() throws {
		var seen: Set<MLS.HpkePublicKey> = []
		for i in 0..<physicalNodeCount {
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
