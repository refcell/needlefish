#!/usr/bin/env bash
# Phase B4 of docs/BENCHMARK_PLAN.md: node to node through the Engine API, on a synthetic
# chain both nodes import from genesis.
#
#   etc/bench/node-bench.sh [accounts] [load seconds]     (defaults 1000000, 120)
#
# 1. Writes a devnet genesis (`base devnet init`) and prefills it with <accounts> funded
#    accounts, so the account trie is deeper than a fresh devnet's.
# 2. Runs the needlefish devnet (etc/devnet/devnet.sh: L1, sequencer, batcher, verifier) and
#    `base load-test` against the sequencer for <load seconds> with a transfer, ERC-20 and
#    storage-write mix, then exports every L2 block as an Engine API payload
#    (etc/bench/node-import.sh export).
# 3. Imports the same payloads into a fresh needlefish node and a fresh base/base node
#    (`base-reth-node`, its default storage), one at a time: `engine_newPayloadV4`, then
#    `engine_forkchoiceUpdatedV3`, timing each newPayload. Both must return VALID for every
#    block. Then repeats each import with the page cache dropped first.
#
# Builds: needlefish ReleaseFast (what `just release` ships), base/base `release` for
# x86-64 generic (what its Docker images ship). Results go to .cache/bench/node/.
# Needs: Zig 0.17.1, a Rust toolchain, clang (base/base's MDBX bindings), curl, jq, openssl,
# GNU time, sudo for drop_caches.
set -euo pipefail

accounts=${1:-1000000}
seconds=${2:-120}
out=.cache/bench/node
rust_dir=${BENCH_RUST_DIR:-.cache/bench/base}
needlefish=.cache/bench/bin/nf-ReleaseFast-native/bin/base
reth=$rust_dir/target/release/base-reth-node
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
mkdir -p "$out"

build() {
    [ -x "$needlefish" ] || zig build -Doptimize=ReleaseFast --prefix .cache/bench/bin/nf-ReleaseFast-native
    [ -x "$reth" ] || (cd "$rust_dir" && cargo build --profile release --locked -p base-reth-node)
}

# Adds <count> accounts 0x10..00 + i with 1 wei each to the genesis alloc.
prefill() { # prefill <genesis> <count>
    local genesis=$1 count=$2 entries=$out/prefill.json
    awk -v n="$count" 'BEGIN { for (i = 1; i <= n; i++) printf "\"0x10%038x\":{\"balance\":\"0x1\"},", i }' >"$entries"
    awk -v file="$entries" '
        /"alloc": *\{/ && !done { sub(/"alloc": *\{/, "&" ); print; while ((getline line < file) > 0) printf "%s", line; print ""; done = 1; next }
        { print }' "$genesis" >"$genesis.tmp"
    mv "$genesis.tmp" "$genesis"
    jq -e '.alloc | length' "$genesis" >/dev/null
}

chain() { # devnet with a prefilled genesis, a load test, and the exported payloads
    etc/devnet/devnet.sh down >/dev/null 2>&1 || true
    rm -rf .devnet
    "$needlefish" devnet init --out .devnet --force
    prefill .devnet/l2-genesis.json "$accounts"
    # base-reth-node requires an activation admin for a Beryl-enabled chain; needlefish
    # reads the same field. No workload transaction touches the activation registry.
    jq '.config.activationAdminAddress = "0x4200000000000000000000000000000000000018"' \
        .devnet/l2-genesis.json >.devnet/l2-genesis.json.tmp
    mv .devnet/l2-genesis.json.tmp .devnet/l2-genesis.json
    cp .devnet/l2-genesis.json "$out/l2-genesis.json"
    cp .devnet/jwt.hex "$out/jwt.hex"
    # `up` keeps the prefilled genesis (DEVNET_KEEP) and builds zig-out/bin/base.
    DEVNET_KEEP=1 DEVNET_OPTIMIZE=ReleaseFast etc/devnet/devnet.sh up
    . .devnet/devnet.env
    local l2=http://127.0.0.1:$PORT_SEQUENCER_HTTP
    zig-out/bin/base load-test --rpc-url "$l2" --chain-id 901  --rate 200 \
        --duration-s "$seconds" --mix transfer=40,erc20_transfer=30,storage=30 --senders 200 \
        >"$out/load-test.txt" 2>&1
    local head
    head=$(curl -sf -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "$l2" |
        jq -r .result)
    etc/bench/node-import.sh export "$l2" 1 "$((head))" "$out/payloads.jsonl"
    etc/devnet/devnet.sh down
}

wait_engine() { # wait_engine <port>
    local tries=0
    until curl -s -o /dev/null "http://127.0.0.1:$1"; do
        tries=$((tries + 1))
        [ "$tries" -lt 600 ] || { echo "engine on $1 did not start" >&2; exit 1; }
        sleep 0.2
    done
}

import_into() { # import_into <name> <cold|warm>
    local name=$1 mode=$2 data=$out/$1-data pid
    rm -rf "$data"
    mkdir -p "$data"
    if [ "$name" = needlefish ]; then
        "$needlefish" node --chain "$out/l2-genesis.json" --datadir "$data" \
            --http.port 18545 --authrpc.port 18551 --authrpc.jwtsecret "$out/jwt.hex" \
            >"$out/$name-$mode.log" 2>&1 &
    else
        "$reth" node --chain "$out/l2-genesis.json" --datadir "$data" --http --http.port 18545 \
            --authrpc.port 18551 --authrpc.jwtsecret "$out/jwt.hex" --port 0 --discovery.port 0 \
            --disable-discovery --log.stdout.filter warn >"$out/$name-$mode.log" 2>&1 &
    fi
    pid=$!
    wait_engine 18551
    [ "$mode" = cold ] && { sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null; }
    etc/bench/node-import.sh import http://127.0.0.1:18551 "$out/jwt.hex" \
        "$out/payloads.jsonl" "$out/$name-$mode.txt"
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    du -sb "$data" | awk -v n="$name" -v m="$mode" '{ print n, m, "datadir bytes", $1 }' \
        >>"$out/disk.txt"
}

build
[ -s "$out/payloads.jsonl" ] || chain
: >"$out/disk.txt"
for mode in warm cold; do
    import_into needlefish "$mode"
    import_into base "$mode"
done
for file in "$out"/*-warm.txt "$out"/*-cold.txt; do
    awk -v name="$(basename "$file" .txt)" '{
        for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
        t[NR] = v["new_payload_ns"]; total += v["new_payload_ns"]; gas += v["gas"]
    } END {
        n = asort(t)
        printf "%s: %d blocks, %.1f Mgas, newPayload median %.2f ms, p90 %.2f ms, p99 %.2f ms, total %.1f ms\n",
            name, n, gas / 1e6, t[int((n + 1) / 2)] / 1e6, t[int(n * 0.9 + 0.999)] / 1e6,
            t[int(n * 0.99 + 0.999)] / 1e6, total / 1e6
    }' "$file"
done
cat "$out/disk.txt"
