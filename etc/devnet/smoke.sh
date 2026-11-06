#!/usr/bin/env bash
# End-to-end devnet smoke test (docs/DEVNET.md "Smoke test"). Run after `just devnet up`.
# Exits non-zero at the first failed step and says why.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DIR=.devnet
BASE=zig-out/bin/base
TIMEOUT_S="${SMOKE_TIMEOUT_S:-120}"
[ -f "$DIR/devnet.env" ] || { echo "smoke: run 'just devnet up' first"; exit 1; }
# shellcheck disable=SC1091
. "$DIR/devnet.env"
L1="http://127.0.0.1:$PORT_L1_HTTP"
SEQ="http://127.0.0.1:$PORT_SEQUENCER_HTTP"
VER="http://127.0.0.1:$PORT_VERIFIER_HTTP"
VER_CL="http://127.0.0.1:$PORT_VERIFIER_RPC"

rpc() {
  curl -s --max-time 2 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1" || true
}
field() { { grep -o "\"$1\":\"[^\"]*\"" || true; } | head -n1 | cut -d'"' -f4; }
fail() { echo "smoke: FAIL $*"; exit 1; }
ok() { echo "smoke: ok   $*"; }

# until DESCRIPTION COMMAND... — retries COMMAND every second until TIMEOUT_S.
until_ok() {
  local what="$1"; shift
  for _ in $(seq 1 "$TIMEOUT_S"); do
    if "$@"; then return 0; fi
    sleep 1
  done
  fail "$what (timed out after ${TIMEOUT_S}s)"
}

for url in "$L1" "$SEQ" "$VER"; do
  [ -n "$(rpc "$url" eth_chainId '[]' | field result)" ] || fail "no JSON-RPC at $url"
done

# 0. Liveness: the sequencer EL head advances (the sequencer CL drives it over the engine
# API). Fails fast and names the stalled side instead of timing out on the transfer.
l2_head() { echo $(($(rpc "$SEQ" eth_blockNumber '[]' | field result))); }
first_l2=$(l2_head)
l2_advances() { [ "$(l2_head)" -gt "$first_l2" ]; }
# Denim at genesis: a block every L2_BLOCK_TIME_MS (200 ms). Poll every 200 ms for up to
# 50 block intervals (10 s), in whole polls so bash needs no fractional arithmetic.
interval_ms="${L2_BLOCK_TIME_MS:-$((L2_BLOCK_TIME * 1000))}"
polls=$((interval_ms * 50 / 200))
for _ in $(seq 1 "$polls"); do l2_advances && break; sleep 0.2; done
l2_advances || fail "sequencer L2 head stuck at $first_l2 for $((polls / 5))s: seq-cl" \
  "is not building blocks through the engine API (see $DIR/logs/seq-cl.log)"
ok "sequencer L2 head advancing (block $(l2_head))"

# L1 scan start for step 2, taken before the L2 transfer can possibly be batched.
start_l1=$(($(rpc "$L1" eth_blockNumber '[]' | field result)))

# 1. Sequencing: an L2 transfer from the smoke user lands in a block.
tx=$("$BASE" devnet transfer --rpc "$SEQ" --chain-id "$L2_CHAIN_ID" --key-index "$USER_INDEX" \
  --to "$DEPLOYER_ADDRESS" --value 1000) || fail "could not send L2 transfer"
receipt_ok() {
  local receipt; receipt=$(rpc "$SEQ" eth_getTransactionReceipt "[\"$tx\"]")
  [ "$(echo "$receipt" | field status)" = "0x1" ] || return 1
  block_hex=$(echo "$receipt" | field blockNumber)
}
until_ok "L2 transfer $tx included" receipt_ok
block=$((block_hex))
ok "L2 transfer $tx included in block $block"

# 2. Batching: a channel on L1 decodes to a batch for the transfer's L2 block.
l2_timestamp=$(($(rpc "$SEQ" eth_getBlockByNumber "[\"$block_hex\",false]" | field timestamp)))
batch_seen() {
  "$BASE" devnet batches --rpc "$L1" --from "$start_l1" --inbox "$BATCH_INBOX" 2>/dev/null \
    | grep -q "singular batch: timestamp $l2_timestamp,"
}
until_ok "batch for L2 block $block (timestamp $l2_timestamp) on L1" batch_seen
ok "batch for L2 block $block decoded from L1 inbox $BATCH_INBOX"

# 3. Derivation: the verifier's safe head reaches the block with the same hash.
seq_hash=$(rpc "$SEQ" eth_getBlockByNumber "[\"$block_hex\",false]" | field hash)
derived() {
  local safe; safe=$(rpc "$VER_CL" optimism_syncStatus '[]' \
    | grep -o '"safe_l2":{[^}]*}' | grep -o '"number":[0-9]*' | head -n1 | cut -d: -f2)
  [ -n "$safe" ] && [ "$safe" -ge "$block" ] || return 1
  [ "$(rpc "$VER" eth_getBlockByNumber "[\"$block_hex\",false]" | field hash)" = "$seq_hash" ]
}
until_ok "verifier safe head reaches block $block with hash $seq_hash" derived
ok "verifier derived block $block ($seq_hash)"

# 3a. Gossip: the verifier found the sequencer through discv5 and gossips with it.
gossip_peer() {
  local count; count=$(rpc "$VER_CL" opp2p_peerCount '[]' | grep -o '"connectedGossip":[0-9]*' \
    | cut -d: -f2)
  [ -n "$count" ] && [ "$count" -ge 1 ]
}
until_ok "verifier has a gossip peer (opp2p_peerCount connectedGossip >= 1)" gossip_peer
ok "verifier gossips with a peer found through discv5"

# 3b. Metrics: the verifier's Prometheus safe-head label reached the block.
VER_METRICS="http://127.0.0.1:${PORT_VERIFIER_METRICS:-7301}/metrics"
metrics_safe() {
  local value; value=$(curl -s --max-time 2 "$VER_METRICS" \
    | grep '^base_node_block_labels{label="safe"}' | awk '{print $2}' | cut -d. -f1)
  [ -n "$value" ] && [ "$value" -ge "$block" ]
}
until_ok "verifier metrics report safe head >= $block" metrics_safe
ok "verifier metrics report the safe head"

# 4. Deposits: ETH sent to the L1 portal appears on L2 for the sender.
# Balances exceed 64 bits, so convert and compare with bc.
balance() {
  local hex; hex=$(rpc "$1" eth_getBalance "[\"$USER_ADDRESS\",\"latest\"]" | field result)
  echo "ibase=16; $(echo "${hex#0x}" | tr 'a-f' 'A-F')" | bc
}
greater() { [ "$(echo "$1 > $2" | bc)" = "1" ]; }
before_seq=$(balance "$SEQ")
before_ver=$(balance "$VER")
"$BASE" devnet transfer --rpc "$L1" --chain-id "$L1_CHAIN_ID" --key-index "$USER_INDEX" \
  --to "$PORTAL" --value 1000000000000000000 >/dev/null || fail "could not send L1 deposit"
deposited() { greater "$(balance "$SEQ")" "$before_seq" && greater "$(balance "$VER")" "$before_ver"; }
until_ok "deposit credited on sequencer and verifier" deposited
ok "deposit credited on L2"

# 5. Load: a short seeded load test from dev accounts 2-4 (no devnet role uses them) must
# confirm every transaction it submits without a revert (infra-tools lane, `base load-test`).
# Dev account 8 first deploys the workload contracts (token, storage writer, looper).
load=$("$BASE" load-test --rpc-url "$SEQ" --chain-id "$L2_CHAIN_ID" --rate 20 --duration-s 5 \
  --drain-s 30 --accounts 2,3,4 --funder-index 8 \
  --mix transfer=40,calldata=20,erc20_transfer=10,storage=10,precompile=10,looper=10 \
  --looper-iterations 1000 2>&1) || fail "load test: $load"
submitted=$(echo "$load" | awk '/^submitted/ {print $2}')
confirmed=$(echo "$load" | awk '/^confirmed/ {print $2}')
reverted=$(echo "$load" | awk '/^reverted/ {print $2}')
[ -n "$submitted" ] && [ "$submitted" -gt 0 ] && [ "$submitted" = "$confirmed" ] &&
  [ "$reverted" = 0 ] ||
  fail "load test confirmed $confirmed of $submitted ($reverted reverted): $load"
ok "load test: $confirmed/$submitted confirmed, $(echo "$load" | grep '^latency' | tr -s ' ')"

echo "smoke: all checks passed"
