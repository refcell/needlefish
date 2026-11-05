#!/usr/bin/env bash
# Devnet process supervisor (docs/DEVNET.md). Native processes, state under .devnet/.
#
#   devnet.sh up       init configs, start every available component
#   devnet.sh down     stop everything started by `up`
#   devnet.sh status   pids and chain heads
#   devnet.sh logs     tail all logs
#   devnet.sh smoke    end-to-end checks (docs/DEVNET.md "Smoke test")
#
# A component whose binary has not landed yet is reported and skipped, so `up` works
# at every stage of the rewrite. Set DEVNET_OPTIMIZE=Debug for faster rebuilds.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DIR=.devnet
BIN=zig-out/bin
BASE="$BIN/base"
mkdir -p "$DIR/logs" "$DIR/pids"

log() { printf 'devnet: %s\n' "$*"; }

# Resolves the command for component binary NAME: a dedicated binary if one exists,
# else a `base NAME` subcommand if `base` lists it. Prints nothing when unavailable.
resolve() {
  local name="$1"
  if [ -x "$BIN/$name" ]; then echo "$BIN/$name"; return; fi
  if "$BASE" 2>&1 | grep -qE "^  $name( |$)"; then echo "$BASE $name"; fi
}

env_load() {
  # shellcheck disable=SC1091
  . "$DIR/devnet.env"
}

pid_alive() { [ -f "$DIR/pids/$1.pid" ] && kill -0 "$(cat "$DIR/pids/$1.pid")" 2>/dev/null; }

# start NAME BINARY ARGS... — runs one component in the background.
start() {
  local name="$1" binary="$2"; shift 2
  local cmd; cmd=$(resolve "$binary")
  if [ -z "$cmd" ]; then log "$name: '$binary' not built yet, skipping"; return 0; fi
  if pid_alive "$name"; then log "$name: already running"; return 0; fi
  mkdir -p "$DIR/$name"
  # shellcheck disable=SC2086
  nohup $cmd "$@" >"$DIR/logs/$name.log" 2>&1 &
  echo $! >"$DIR/pids/$name.pid"
  log "$name: started (pid $!, log $DIR/logs/$name.log)"
}

# rpc URL METHOD PARAMS — prints the raw JSON-RPC response, empty on failure.
rpc() {
  curl -s --max-time 2 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1" || true
}

json_field() { { grep -o "\"$1\":\"[^\"]*\"" || true; } | head -n1 | cut -d'"' -f4; }

wait_rpc() {
  local url="$1" name="$2"
  for _ in $(seq 1 50); do
    [ -n "$(rpc "$url" eth_chainId '[]' | json_field result)" ] && return 0
    sleep 0.2
  done
  log "$name: no RPC at $url (see $DIR/logs/$name.log)"; return 1
}

genesis_hash() { rpc "$1" eth_getBlockByNumber '["0x0",false]' | json_field hash; }

# The devnet uses fixed ports, so only one runs per machine. A cold `up` refuses to start
# when one is taken: otherwise our components die with AddressInUse and `smoke` silently
# checks whichever devnet owns the ports.
ports_free() {
  local name port taken=0
  for name in $COMPONENTS; do pid_alive "$name" && return 0; done
  for port in "$PORT_L1_HTTP" "$PORT_L1_BEACON" "$PORT_SEQUENCER_HTTP" \
    "$PORT_SEQUENCER_ENGINE" "$PORT_SEQUENCER_RPC" "$PORT_VERIFIER_HTTP" \
    "$PORT_VERIFIER_ENGINE" "$PORT_VERIFIER_RPC" "$PORT_BATCHER_METRICS"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      log "port $port is in use (another devnet?)"; taken=1
    fi
  done
  [ "$taken" = 0 ] || { log "not starting: free the ports above first"; exit 1; }
}

# Fails `up` when a component exited during startup (a port clash, a bad flag).
all_alive() {
  local name dead=0
  for name in $COMPONENTS; do
    if [ -f "$DIR/pids/$name.pid" ] && ! pid_alive "$name"; then
      log "$name exited during startup:"; tail -n 3 "$DIR/logs/$name.log" >&2; dead=1
    fi
  done
  [ "$dead" = 0 ] || { log "up failed; 'just devnet down' cleans up"; exit 1; }
}

up() {
  zig build -Doptimize="${DEVNET_OPTIMIZE:-ReleaseSafe}"
  fresh_state
  env_load
  ports_free
  local l1="http://127.0.0.1:$PORT_L1_HTTP"
  local seq_el="http://127.0.0.1:$PORT_SEQUENCER_HTTP"
  local ver_el="http://127.0.0.1:$PORT_VERIFIER_HTTP"
  start l1 node --dev-l1 --chain "$DIR/l1-genesis.json" --datadir "$DIR/l1" \
    --http.port "$PORT_L1_HTTP" --beacon.port "$PORT_L1_BEACON" --block-time "$L1_BLOCK_TIME"
  # The sequencer EL builds through the builder/core payload service (200 ms slots, 150 ms
  # cutoff); the verifier EL only imports.
  start_l2_el seq-el "$PORT_SEQUENCER_HTTP" "$PORT_SEQUENCER_ENGINE" --builder.enabled
  start_l2_el ver-el "$PORT_VERIFIER_HTTP" "$PORT_VERIFIER_ENGINE"
  patch_rollup "$l1" "$seq_el" "$ver_el"
  start_consensus
  start batcher batcher --rollup-config "$DIR/rollup.json" --l1 "$l1" \
    --sequencer-urls "$seq_el=http://127.0.0.1:$PORT_SEQUENCER_RPC" --key-index "$BATCHER_INDEX" \
    --metrics.port "$PORT_BATCHER_METRICS" --blob-sidecar-version 0 # Dev L1: Osaka off.
  sleep 1
  all_alive
  log "up; 'just devnet status' to inspect, 'just devnet smoke' to verify"
}

COMPONENTS="l1 seq-el seq-cl batcher ver-el ver-cl"

# A cold `up` (nothing running) starts from a fresh genesis: a stale genesis timestamp
# makes the dev L1 backfill hours of blocks and leaves the sequencer that far behind.
# DEVNET_KEEP=1 keeps the existing chain state and configs.
fresh_state() {
  local name
  for name in $COMPONENTS; do
    if pid_alive "$name"; then
      log "$name running: keeping existing state"; "$BASE" devnet init --out "$DIR"; return
    fi
  done
  if [ "${DEVNET_KEEP:-0}" = 1 ]; then "$BASE" devnet init --out "$DIR"; return; fi
  for name in $COMPONENTS; do rm -rf "${DIR:?}/$name"; done
  "$BASE" devnet init --out "$DIR" --force
}

# start_l2_el NAME HTTP_PORT ENGINE_PORT [EXTRA_FLAGS...]
start_l2_el() {
  start "$1" node --chain "$DIR/l2-genesis.json" --datadir "$DIR/$1" --http.port "$2" \
    --authrpc.port "$3" --authrpc.jwtsecret "$DIR/jwt.hex" "${@:4}"
}

# Rewrites rollup.json with the real genesis hashes once the ELs answer.
patch_rollup() {
  if ! pid_alive l1 || ! pid_alive seq-el; then
    log "rollup.json: ELs not running, genesis hashes left zero"; return 0
  fi
  wait_rpc "$1" l1 && wait_rpc "$2" seq-el || return 0
  local l1_hash l2_hash; l1_hash=$(genesis_hash "$1"); l2_hash=$(genesis_hash "$2")
  if pid_alive ver-el && wait_rpc "$3" ver-el; then
    local ver_hash; ver_hash=$(genesis_hash "$3")
    [ "$ver_hash" = "$l2_hash" ] || log "WARNING: verifier genesis $ver_hash != $l2_hash"
  fi
  "$BASE" devnet rollup --out "$DIR" --timestamp "$GENESIS_TIMESTAMP" \
    --l1-hash "$l1_hash" --l2-hash "$l2_hash"
  log "rollup.json: l1 genesis $l1_hash, l2 genesis $l2_hash"
}

start_consensus() {
  local common=(--rollup-config "$DIR/rollup.json" --l1 "http://127.0.0.1:$PORT_L1_HTTP"
    --l1-beacon "http://127.0.0.1:$PORT_L1_BEACON" --l2-jwt "$DIR/jwt.hex")
  # Unsafe-block gossip: the verifier dials the sequencer's enode (logged at startup).
  local p2p=(--p2p.listen.ip 127.0.0.1 --p2p.no-discovery --p2p.no-bootstore)
  start seq-cl consensus "${common[@]}" --l2 "http://127.0.0.1:$PORT_SEQUENCER_ENGINE" \
    --rpc.port "$PORT_SEQUENCER_RPC" --rpc.enable-admin --sequencer \
    --sequencer.key-index "$SEQUENCER_INDEX" \
    "${p2p[@]}" --p2p.listen.tcp 9222 --p2p.listen.udp 9223
  local enode="" tries=0
  while [ -z "$enode" ] && [ "$tries" -lt 50 ]; do
    enode=$(grep -o 'enode=enode://[^ ]*' "$DIR/logs/seq-cl.log" 2>/dev/null | head -n1 |
      sed 's/^enode=//') || true
    [ -n "$enode" ] || sleep 0.2
    tries=$((tries + 1))
  done
  local gossip=()
  if [ -n "$enode" ]; then
    gossip=(--p2p.bootnodes "$enode")
  else
    log "ver-cl: sequencer enode not found, starting without a gossip peer"
  fi
  local signer; signer=$("$BASE" devnet account "$SEQUENCER_INDEX")
  start ver-cl consensus "${common[@]}" --l2 "http://127.0.0.1:$PORT_VERIFIER_ENGINE" \
    --rpc.port "$PORT_VERIFIER_RPC" "${p2p[@]}" --p2p.listen.tcp 9232 --p2p.listen.udp 9233 \
    --p2p.unsafe.block.signer "$signer" ${gossip[@]+"${gossip[@]}"} \
    --metrics.enabled --metrics.port "${PORT_VERIFIER_METRICS:-7301}"
}

down() {
  local any=0
  for file in "$DIR"/pids/*.pid; do
    [ -e "$file" ] || continue
    local name; name=$(basename "$file" .pid)
    if kill -0 "$(cat "$file")" 2>/dev/null; then
      kill "$(cat "$file")" && log "$name: stopped"; any=1
    fi
    rm -f "$file"
  done
  [ "$any" -eq 1 ] || log "nothing running"
}

status() {
  [ -f "$DIR/devnet.env" ] || { log "not initialized ('just devnet up')"; return 0; }
  env_load
  for name in $COMPONENTS; do
    if pid_alive "$name"; then
      printf '  %-8s running (pid %s)\n' "$name" "$(cat "$DIR/pids/$name.pid")"
    else
      printf '  %-8s stopped\n' "$name"
    fi
  done
  for pair in "l1:$PORT_L1_HTTP" "seq-el:$PORT_SEQUENCER_HTTP" "ver-el:$PORT_VERIFIER_HTTP"; do
    local head; head=$(rpc "http://127.0.0.1:${pair#*:}" eth_blockNumber '[]' | json_field result)
    printf '  %-8s head %s\n' "${pair%%:*}" "${head:-?}"
  done
  for pair in "seq-cl:$PORT_SEQUENCER_RPC" "ver-cl:$PORT_VERIFIER_RPC"; do
    local sync; sync=$(rpc "http://127.0.0.1:${pair#*:}" optimism_syncStatus '[]')
    printf '  %-8s sync %s\n' "${pair%%:*}" "${sync:0:160}"
  done
}

case "${1:-status}" in
  up) up ;;
  down) down ;;
  status) status ;;
  logs) tail -n 100 -F "$DIR"/logs/*.log ;;
  smoke) exec etc/devnet/smoke.sh ;;
  *) echo "usage: devnet.sh up|down|status|logs|smoke"; exit 2 ;;
esac
