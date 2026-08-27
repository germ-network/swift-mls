import Foundation
import MLSCodec
import MLSCrypto

extension MLS.TreeKEM {
	/// RFC 9420 §7.4: `path_secret[n] = DeriveSecret(path_secret[n-1],
	/// "path")` — advances once per *unfiltered* direct-path entry ("one
	/// for each node on the leaf's filtered direct path"), not once per
	/// tree level; a
	/// filtered entry (empty copath resolution) gets no derivation step at
	/// all, it's skipped entirely. Get this backwards and every tree with
	/// a blank copath — most interesting trees — silently derives wrong
	/// secrets.
	static func nextPathSecret(_ provider: any MLS.CipherSuiteProvider, from secret: Data)
		throws
		-> Data
	{
		try MLS.deriveSecret(provider, secret: secret, label: "path")
	}

	/// RFC 9420 §7.4: `node_secret[n] = DeriveSecret(path_secret[n],
	/// "node")`, then `KEM.DeriveKeyPair(node_secret[n])`. Public: a caller
	/// reconstructing which node keys it currently holds (e.g. from a
	/// stored path secret at some ancestor) needs exactly this, not just
	/// the internal encap/decap machinery.
	public static func nodeKeyPair(
		_ provider: any MLS.CipherSuiteProvider, pathSecret: Data
	) throws -> (
		secretKey: MLS.HpkeSecretKey, publicKey: MLS.HpkePublicKey
	) {
		let ikm = try MLS.deriveSecret(provider, secret: pathSecret, label: "node")
		return try provider.hpkeDeriveKeyPair(ikm: ikm)
	}

	/// RFC 9420 §12.4.1: "Define commit_secret as the value
	/// path_secret[n+1] derived from the last path secret value
	/// (path_secret[n]) derived for the UpdatePath" — i.e. one more §7.4
	/// "path" step, there being no distinct commit-secret label. A
	/// pathless commit's `commit_secret` is instead "the all-zero vector
	/// of length KDF.Nh," computed by the caller, not this function
	/// (there's no path secret to step past).
	static func commitSecret(_ provider: any MLS.CipherSuiteProvider, rootPathSecret: Data)
		throws
		-> Data
	{
		try nextPathSecret(provider, from: rootPathSecret)
	}
}
