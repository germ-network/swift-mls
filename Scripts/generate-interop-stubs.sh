#!/usr/bin/env bash
# Regenerate the checked-in Swift gRPC stubs for mls-interop-server.
# Needs protoc + protoc-gen-swift + protoc-gen-grpc-swift-2 on PATH
# (brew install swift-protobuf grpc-swift).
set -euo pipefail
PROTO="${1:?path to directory containing mls_client.proto}"
OUT="$(dirname "$0")/../Sources/mls-interop-server/Generated"
protoc --proto_path="$PROTO" \
  --swift_out="$OUT" \
  --grpc-swift-2_out="$OUT" \
  mls_client.proto
# The executable target is macOS/Linux only (grpc-swift needs macOS 15 /
# iOS 18, above this library's iOS 17 floor); guard the generated stubs so
# the whole-package iOS build compiles them to nothing.
for f in "$OUT/mls_client.pb.swift" "$OUT/mls_client.grpc.swift"; do
  printf '#if os(macOS) || os(Linux)\n%s\n#endif\n' "$(cat "$f")" > "$f"
done
echo "Regenerated (and platform-guarded) stubs in $OUT"
