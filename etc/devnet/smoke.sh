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
    | grep -o '"safe_l2":{[^}]*}' | grep -o '"number":[0-9]*' | cut -d: -f2)
  [ -n "$safe" ] && [ "$safe" -ge "$block" ] || return 1
  [ "$(rpc "$VER" eth_getBlockByNumber "[\"$block_hex\",false]" | field hash)" = "$seq_hash" ]
}
until_ok "verifier safe head reaches block $block with hash $seq_hash" derived
ok "verifier derived block $block ($seq_hash)"

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

echo "smoke: all checks passed"
