#!/usr/bin/env bash
# Build the interop server, start it, and run the mlswg Go runner over the
# in-scope configs across every supported cipher suite. Requires a built
# runner (see interop/test-runner in mlswg/mls-implementations) passed as $1.
set -euo pipefail
RUNNER="${1:?path to the built mlswg test-runner}"
CONFIGS="${2:?path to the runner's configs directory}"
PORT="${PORT:-50051}"
# Optional second client for cross-implementation interop, e.g. mls-rs's
# harness_client on 50009: PEER=127.0.0.1:50009. When set, the runner runs
# every actor->client assignment (swift<->peer both directions).
PEER="${PEER:-}"
swift build -c release --product mls-interop-server
.build/release/mls-interop-server "$PORT" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1
for cfg in application welcome_join commit; do
  for suite in 1 2 3 5 7; do
    peer_arg=()
    [ -n "$PEER" ] && peer_arg=(-client "$PEER")
    if "$RUNNER" -client "127.0.0.1:$PORT" "${peer_arg[@]}" \
        -config "$CONFIGS/$cfg.json" -suite "$suite" -public >/dev/null 2>&1; then
      echo "$cfg suite $suite: PASS"
    else
      echo "$cfg suite $suite: FAIL (deferred features answer ABORTED)"
    fi
  done
done
