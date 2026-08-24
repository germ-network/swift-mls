import Foundation
import MLSCodec
import MLSCrypto

extension MLS.TreeKEM {
	/// `path_secret[i+1] = DeriveSecret(path_secret[i], "path")` — advances
	/// once per *unfiltered* direct-path entry, not once per tree level; a
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

	/// `DeriveKeyPair(DeriveSecret(path_secret, "node"))`. Public: a caller
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

	/// One step past the last path secret in the chain — `commit_secret`
	/// for a commit that actually has a path. A pathless commit's
	/// `commit_secret` is `Nh` zero bytes, computed by the caller, not
	/// this function (there's no path secret to step past).
	static func commitSecret(_ provider: any MLS.CipherSuiteProvider, rootPathSecret: Data)
		throws
		-> Data
	{
		try nextPathSecret(provider, from: rootPathSecret)
	}
}
