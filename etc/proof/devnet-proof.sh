#!/usr/bin/env bash
# Proves an L2 claim on the running local devnet with `base proof run`, records the
# preimage archive, and replays it offline with `base proof replay`.
#   etc/proof/devnet-proof.sh [blocks]   # claim = safe head, agreed = claim - blocks
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DIR=.devnet
BASE=zig-out/bin/base
BLOCKS="${1:-8}"
# shellcheck disable=SC1091
. "$DIR/devnet.env"
L1="http://127.0.0.1:$PORT_L1_HTTP"
L2="http://127.0.0.1:$PORT_VERIFIER_HTTP"

status=$(curl -s --max-time 2 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus","params":[]}' \
  "http://127.0.0.1:$PORT_VERIFIER_RPC")
safe=$(printf '%s' "$status" | grep -o '"safe_l2":{[^}]*}' | grep -o '"number":[0-9]*' |
  head -n1 | cut -d: -f2)
[ -n "$safe" ] || { echo "devnet-proof: no verifier sync status (is the devnet up?)"; exit 1; }
[ "$safe" -gt "$BLOCKS" ] || { echo "devnet-proof: safe head $safe too low"; exit 1; }
agreed=$((safe - BLOCKS))
archive="$DIR/proof-$safe.nfpa"

echo "devnet-proof: proving block $safe from agreed block $agreed"
"$BASE" proof run --l1 "$L1" --l2 "$L2" --rollup-config "$DIR/rollup.json" \
  --l1-genesis "$DIR/l1-genesis.json" --agreed "$agreed" --claimed "$safe" --out "$archive"
echo "devnet-proof: replaying $archive offline"
"$BASE" proof replay "$archive"
wrong=0x$(printf 'ab%.0s' $(seq 1 32))
if "$BASE" proof run --l1 "$L1" --l2 "$L2" --rollup-config "$DIR/rollup.json" \
  --l1-genesis "$DIR/l1-genesis.json" --agreed "$agreed" --claimed "$safe" \
  --claim-root "$wrong"; then
  echo "devnet-proof: a wrong claim held"; exit 1
fi
echo "devnet-proof: ok"
