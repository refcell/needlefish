#!/usr/bin/env bash
# Proves an L2 range on the running local devnet through the TEE path: `base prover-service`
# takes a `tee` request, `base prover-worker --backend tee` runs the host and a local-mode
# enclave (dev key 0 of the public mnemonic), and the script polls until the signed proof.
#   etc/proof/devnet-tee.sh [blocks]   # claim = safe head, agreed = claim - blocks
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DIR=.devnet
BASE=${BASE:-zig-out/bin/base}
BLOCKS="${1:-4}"
SERVICE_PORT=${SERVICE_PORT:-7310}
# shellcheck disable=SC1091
. "$DIR/devnet.env"
L1="http://127.0.0.1:$PORT_L1_HTTP"
BEACON="http://127.0.0.1:$PORT_L1_BEACON"
L2="http://127.0.0.1:$PORT_VERIFIER_HTTP"
ROLLUP="http://127.0.0.1:$PORT_VERIFIER_RPC"
SERVICE="http://127.0.0.1:$SERVICE_PORT"

rpc() { # url method params
  curl -s -m 3 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1"
}
# The node answers "not available yet" while it fetches an uncached block; retry.
output_at() { # number
  local response
  for _ in $(seq 1 20); do
    response=$(rpc "$ROLLUP" optimism_outputAtBlock "[\"$(printf '0x%x' "$1")\"]")
    case "$response" in *'"result"'*) printf '%s' "$response"; return 0 ;; esac
    sleep 0.25
  done
  printf '%s' "$response"
}
field() { grep -o "\"$1\":\"0x[0-9a-f]*\"" | head -n1 | cut -d'"' -f4; }

safe=$(rpc "$ROLLUP" optimism_syncStatus '[]' | grep -o '"safe_l2":{[^}]*}' |
  grep -o '"number":[0-9]*' | head -n1 | cut -d: -f2)
[ -n "$safe" ] || { echo "devnet-tee: no verifier sync status (is the devnet up?)"; exit 1; }
[ "$safe" -gt "$BLOCKS" ] || { echo "devnet-tee: safe head $safe too low"; exit 1; }
agreed=$((safe - BLOCKS))
agreed_output=$(output_at "$agreed")
agreed_root=$(printf '%s' "$agreed_output" | field outputRoot)
agreed_hash=$(printf '%s' "$agreed_output" | grep -o '"blockRef":{[^}]*}' | field hash)
claimed_root=$(output_at "$safe" | field outputRoot)
# The safe head was derived from the latest L1 block, which the finalized one may predate.
l1_block=$(rpc "$L1" eth_getBlockByNumber '["latest",false]')
l1_head=$(printf '%s' "$l1_block" | field hash)
l1_number=$(($(printf '%s' "$l1_block" | field number)))
for value in "$agreed_root" "$agreed_hash" "$claimed_root" "$l1_head"; do
  [ ${#value} -eq 66 ] || { echo "devnet-tee: could not read the claim roots"; exit 1; }
done

work=$(mktemp -d "$DIR/tee.XXXXXX")
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT
# Dev account 0 of the public `test ... junk` mnemonic; never a real key.
printf 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' >"$work/enclave.key"

"$BASE" prover-service --listen "$SERVICE" >"$work/service.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do curl -s -m 1 "$SERVICE" >/dev/null 2>&1 && break; sleep 0.2; done
"$BASE" prover-worker --backend tee --enclave-key-file "$work/enclave.key" \
  --prover-rpc "$SERVICE" --l1 "$L1" --l1-beacon "$BEACON" --l2 "$L2" \
  --rollup-config "$DIR/rollup.json" --l1-genesis "$DIR/l1-genesis.json" \
  --worker-id tee-smoke --poll-interval-ms 200 --enclave-allow-custom-chain \
  >"$work/worker.log" 2>&1 &
pids+=($!)

session="tee-$safe"
request="{\"proof\":{\"session_id\":\"$session\",\"request\":{\"proof_type\":\"tee\",\"payload\":{"
request+="\"proof\":{\"l1_head\":\"$l1_head\",\"agreed_l2_head_hash\":\"$agreed_hash\","
request+="\"agreed_l2_output_root\":\"$agreed_root\",\"claimed_l2_output_root\":\"$claimed_root\","
request+="\"claimed_l2_block_number\":$safe,\"l1_head_number\":$l1_number,"
request+="\"intermediate_block_interval\":$BLOCKS},\"tee_kind\":\"aws_nitro\"}}},"
request+="\"retry_failed\":false}"
echo "devnet-tee: requesting a TEE proof of block $safe from agreed block $agreed"
rpc "$SERVICE" prover_proveBlockRange "[$request]" | grep -q "\"$session\"" ||
  { echo "devnet-tee: request refused"; cat "$work/service.log"; exit 1; }

for _ in $(seq 1 600); do
  response=$(rpc "$SERVICE" prover_getProof "[{\"session_id\":\"$session\"}]")
  case "$response" in
  *'"status":"succeeded"'*)
    printf '%s\n' "$response" | grep -q '"tee_signer"' ||
      { echo "devnet-tee: no TEE signer in $response"; exit 1; }
    printf '%s' "$response" >"$work/proof.json"
    zero=0x$(printf '00%.0s' $(seq 1 20))
    "$BASE" proof verify-tee --response "$work/proof.json" --proposer "$zero" \
      --starting-block "$agreed" --prev-output-root "$agreed_root" \
      --claimed-output-root "$claimed_root" --claimed-block "$safe" \
      --signer 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
    echo "devnet-tee: ok"
    exit 0
    ;;
  *'"status":"failed"'*)
    echo "devnet-tee: proof failed: $response"
    tail -n 20 "$work/worker.log"
    exit 1
    ;;
  esac
  sleep 0.5
done
echo "devnet-tee: timed out"
tail -n 20 "$work/worker.log"
exit 1
