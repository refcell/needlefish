#!/usr/bin/env bash
# Runs one devnet component inside the compose network (docker-compose.yml). State lives in
# /devnet, the host's .devnet/ bind mount, so `just devnet smoke` checks this devnet too.
# Mirrors etc/devnet/devnet.sh `up`; components reach each other at fixed IPv4 addresses.
set -euo pipefail
DIR=/devnet
mkdir -p "$DIR/logs"

L1_IP=172.30.0.10
SEQ_EL_IP=172.30.0.11
SEQ_CL_IP=172.30.0.12
VER_EL_IP=172.30.0.14

log() { printf 'devnet-docker: %s\n' "$*" >&2; }

rpc() {
  curl -s --max-time 2 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1" || true
}

json_field() { { grep -o "\"$1\":\"[^\"]*\"" || true; } | head -n1 | cut -d'"' -f4; }

# wait_for WHAT TRIES CHECK... — polls every 0.2 s; fails the component after TRIES polls.
wait_for() {
  local what="$1" tries="$2"; shift 2
  for _ in $(seq 1 "$tries"); do "$@" && return 0; sleep 0.2; done
  log "timed out waiting for $what"; exit 1
}

answers() { [ -n "$(rpc "$1" eth_chainId '[]' | json_field result)" ]; }
genesis_hash() { rpc "$1" eth_getBlockByNumber '["0x0",false]' | json_field hash; }

# run NAME BINARY ARGS... — the component in the foreground, its log also in /devnet/logs.
run() {
  local name="$1"; shift
  mkdir -p "$DIR/$name"
  exec "$@" > >(tee "$DIR/logs/$name.log") 2>&1
}

load_env() { . "$DIR/devnet.env"; }

l1_url() { echo "http://$L1_IP:$PORT_L1_HTTP"; }

l2_el() {
  local name="$1" http="$2" engine="$3"; shift 3
  run "$name" base node --chain "$DIR/l2-genesis.json" --datadir "$DIR/$name" \
    --http.addr 0.0.0.0 --http.port "$http" --authrpc.port "$engine" \
    --authrpc.jwtsecret "$DIR/jwt.hex" "$@"
}

consensus_common() {
  echo --rollup-config "$DIR/rollup.json" --l1 "$(l1_url)" \
    --l1-beacon "http://$L1_IP:$PORT_L1_BEACON" --l2-jwt "$DIR/jwt.hex" --rpc.addr 0.0.0.0 \
    --p2p.listen.ip 0.0.0.0
}

# The sequencer CL's ENR from its "p2p listening" log line (advertised at SEQ_CL_IP).
sequencer_record() {
  grep -o 'enr=enr:[^ ]*' "$DIR/logs/seq-cl.log" 2>/dev/null | head -n1 | sed 's/^enr=//'
}

has_record() { [ -n "$(sequencer_record)" ]; }

component() {
  case "$1" in
    setup)
      # A fresh chain every `docker-up`: a stale genesis timestamp makes the L1 backfill.
      # Old logs go too: ver-cl reads the sequencer's ENR from seq-cl.log.
      rm -rf "${DIR:?}"/{l1,seq-el,seq-cl,batcher,ver-el,ver-cl} "$DIR/rollup.ready"
      rm -f "$DIR"/logs/*.log
      base devnet init --out "$DIR" --force ;;
    l1)
      load_env
      run l1 base node --dev-l1 --chain "$DIR/l1-genesis.json" --datadir "$DIR/l1" \
        --http.addr 0.0.0.0 --http.port "$PORT_L1_HTTP" --beacon.port "$PORT_L1_BEACON" \
        --block-time "$L1_BLOCK_TIME" ;;
    seq-el) load_env; l2_el seq-el "$PORT_SEQUENCER_HTTP" "$PORT_SEQUENCER_ENGINE" --builder.enabled ;;
    ver-el) load_env; l2_el ver-el "$PORT_VERIFIER_HTTP" "$PORT_VERIFIER_ENGINE" ;;
    rollup)
      load_env
      local l1 seq_el; l1=$(l1_url); seq_el="http://$SEQ_EL_IP:$PORT_SEQUENCER_HTTP"
      wait_for l1 150 answers "$l1"
      wait_for seq-el 150 answers "$seq_el"
      base devnet rollup --out "$DIR" --timestamp "$GENESIS_TIMESTAMP" \
        --l1-hash "$(genesis_hash "$l1")" --l2-hash "$(genesis_hash "$seq_el")"
      touch "$DIR/rollup.ready" ;;
    seq-cl)
      load_env
      # shellcheck disable=SC2046
      run seq-cl base consensus $(consensus_common) \
        --l2 "http://$SEQ_EL_IP:$PORT_SEQUENCER_ENGINE" --rpc.port "$PORT_SEQUENCER_RPC" \
        --rpc.enable-admin --sequencer --sequencer.key-index "$SEQUENCER_INDEX" \
        --p2p.listen.tcp 9222 --p2p.listen.udp 9223 --p2p.advertise.ip "$SEQ_CL_IP" \
        --p2p.bootstore "$DIR/seq-cl/bootstore.json" ;;
    ver-cl)
      load_env
      wait_for "the sequencer ENR" 150 has_record
      local signer; signer=$(base devnet account "$SEQUENCER_INDEX")
      # shellcheck disable=SC2046
      run ver-cl base consensus $(consensus_common) \
        --l2 "http://$VER_EL_IP:$PORT_VERIFIER_ENGINE" --rpc.port "$PORT_VERIFIER_RPC" \
        --p2p.listen.tcp 9232 --p2p.listen.udp 9233 --p2p.advertise.ip 172.30.0.15 \
        --p2p.bootstore "$DIR/ver-cl/bootstore.json" --p2p.bootnodes "$(sequencer_record)" \
        --p2p.unsafe.block.signer "$signer" \
        --metrics.enabled --metrics.addr 0.0.0.0 --metrics.port "${PORT_VERIFIER_METRICS:-7301}" ;;
    batcher)
      load_env
      run batcher base batcher --rollup-config "$DIR/rollup.json" --l1 "$(l1_url)" \
        --sequencer-urls "http://$SEQ_EL_IP:$PORT_SEQUENCER_HTTP=http://$SEQ_CL_IP:$PORT_SEQUENCER_RPC" \
        --key-index "$BATCHER_INDEX" --metrics.port "$PORT_BATCHER_METRICS" \
        --blob-sidecar-version 0 ;; # Dev L1: Osaka off.
    *) log "unknown component '$1'"; exit 2 ;;
  esac
}

component "${1:?component name}"
