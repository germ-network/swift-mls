#!/usr/bin/env bash
# Refreshes the vendored test vectors under Tests/MLSVectorSupport/Vectors/
# from upstream. Vectors are committed to the repo (small, deterministic
# JSON) rather than fetched at test time, so `swift test` never depends on
# network access. Re-run this script and commit the diff when upstream
# publishes new vectors, or when a later phase needs a vector this script
# doesn't fetch yet — extend it, don't fetch by hand.
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=Tests/MLSVectorSupport/Vectors
mkdir -p "$DEST"

echo "Fetching crypto-basics.json (mlswg/mls-implementations)..."
curl -sSfL "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/crypto-basics.json" \
    -o "$DEST/crypto-basics.json"

echo "Fetching and trimming HPKE base-mode vectors (cfrg/draft-irtf-cfrg-hpke)..."
echo "  Trimmed to mode=0 (base), kem_id in {16 P256, 18 P521, 32 X25519} — the KEMs"
echo "  we implement — kdf_id in {1, 3} (the pairings present upstream for those KEMs)."
echo "  'encryptions'/'exports' capped at 3 entries each: enough to exercise seal/open"
echo "  and export end-to-end without vendoring hundreds of redundant messages per case."
curl -sSfL "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json" \
    | python3 -c '
import json, sys
vectors = json.load(sys.stdin)
kept = []
for v in vectors:
    if v["mode"] == 0 and v["kem_id"] in (16, 18, 32) and v["kdf_id"] in (1, 3):
        v = dict(v)
        v["encryptions"] = v.get("encryptions", [])[:3]
        v["exports"] = v.get("exports", [])[:3]
        kept.append(v)
json.dump(kept, sys.stdout, indent=2)
' > "$DEST/hpke-base-mode.json"

echo "Fetching phase-2 official vectors (mlswg/mls-implementations)..."
for name in tree-math key-schedule secret-tree; do
    curl -sSfL "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/${name}.json" \
        -o "$DEST/${name}.json"
done

echo "Fetching phase-3 official vectors (mlswg/mls-implementations)..."
for name in psk_secret message-protection transcript-hashes messages welcome deserialization; do
    curl -sSfL "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/${name}.json" \
        -o "$DEST/${name}.json"
done

echo "Fetching phase-4 official vectors (mlswg/mls-implementations)..."
echo "  Vendored whole, not suite-filtered at fetch time (see Vectors/README.md) --"
echo "  filtering to supported suites happens at test-load time instead, matching"
echo "  message-protection.json's own pattern."
for name in tree-validation tree-operations treekem; do
    curl -sSfL "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/${name}.json" \
        -o "$DEST/${name}.json"
done

echo "Done. Not fetched here — no official mlswg equivalent exists (see Vectors/README.md"
echo "for what each is and why it's still vendored, or why a similarly-named mls-rs"
echo "vector was deliberately NOT used):"
echo "  mls-rs-signatures.json, mls-rs-sender-data-key.json, key_package_ref.json,"
echo "  proposal_ref.json, reuse_guard.json — mirrored by hand from mls-rs-pq/mls-rs/test_data/"
echo "  framing.json, membership_tag.json, message_padding_test_vector.json — not vendored"
echo "  at all; superseded by official files or non-normative, see Vectors/README.md"
