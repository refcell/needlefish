#!/usr/bin/env bash
# Phase B4 of docs/BENCHMARK_PLAN.md: node to node. Exports blocks from a running L2 node as
# Engine API payloads, then imports them into a fresh node through `engine_newPayloadV4` and
# `engine_forkchoiceUpdatedV3`, one block at a time, timing each newPayload call.
#
#   etc/bench/node-import.sh export <rpc url> <first> <last> <payloads.jsonl>
#   etc/bench/node-import.sh import <engine url> <jwt hex file> <payloads.jsonl> <out.txt>
#
# `import` writes one line per block:
#
#   IMPORT block=<n> txs=<k> gas=<g> new_payload_ns=<t> fcu_ns=<f> status=<VALID|...>
#
# and stops at the first payload that is not VALID. Times are curl's `time_total` (request
# sent to response read, localhost), the same client for both nodes. Needs curl, jq, openssl.
set -euo pipefail

rpc() { # rpc <url> <method> <params json>
    curl -sf -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1"
}

export_blocks() { # export_blocks <rpc> <first> <last> <out>
    local url=$1 first=$2 last=$3 out=$4 number hex block raws
    : >"$out"
    for ((number = first; number <= last; number++)); do
        hex=$(printf '0x%x' "$number")
        block=$(rpc "$url" eth_getBlockByNumber "[\"$hex\",false]" | jq -c .result)
        # One JSON-RPC batch per block for its raw transactions, in index order.
        raws=$(jq -c --arg hex "$hex" '[range(.transactions | length) | {jsonrpc: "2.0",
            id: ., method: "eth_getRawTransactionByBlockNumberAndIndex",
            params: [$hex, ("0x" + (if . == 0 then "0" else
                ([recurse(if . >= 16 then (. / 16 | floor) else empty end) | . % 16]
                | reverse | map("0123456789abcdef"[.:.+1]) | join("")) end))]}]' <<<"$block")
        if [ "$raws" != '[]' ]; then
            raws=$(curl -sf -X POST -H 'content-type: application/json' --data "$raws" "$url" |
                jq -c 'sort_by(.id) | map(.result)')
        fi
        jq -c --argjson transactions "$raws" '{
            payload: {
                parentHash, feeRecipient: .miner, stateRoot, receiptsRoot, logsBloom,
                prevRandao: .mixHash, blockNumber: .number, gasLimit, gasUsed, timestamp,
                extraData, baseFeePerGas, blockHash: .hash, transactions: $transactions,
                withdrawals: [], blobGasUsed, excessBlobGas, withdrawalsRoot
            },
            parentBeaconBlockRoot
        }' <<<"$block" >>"$out"
    done
}

# HS256 Engine API token for now (iat must be within 60 s of the node's clock).
jwt() { # jwt <hex secret file>
    local header payload secret signature
    header=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    payload=$(printf '{"iat":%d}' "$(date +%s)" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    secret=$(tr -d '\n' <"$1" | sed 's/^0x//')
    signature=$(printf '%s.%s' "$header" "$payload" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secret" -binary |
        openssl base64 -A | tr '+/' '-_' | tr -d '=')
    printf '%s.%s.%s' "$header" "$payload" "$signature"
}

engine() { # engine <url> <jwt file> <body file>: prints "<seconds> <response>" and a newline
    local token
    token=$(jwt "$2")
    curl -s -X POST -H 'content-type: application/json' -H "authorization: Bearer $token" \
        --data-binary "@$3" -w '\n%{time_total}\n' "$1" | tac | tr '\n' ' '
    echo
}

import_blocks() { # import_blocks <engine url> <jwt file> <payloads> <out>
    local url=$1 secret=$2 payloads=$3 out=$4 body seconds response status hash
    local fcu_seconds number txs gas
    body=$(mktemp)
    : >"$out"
    while read -r line; do
        jq -c '{jsonrpc: "2.0", id: 1, method: "engine_newPayloadV4",
            params: [.payload, [], .parentBeaconBlockRoot, []]}' <<<"$line" >"$body"
        read -r seconds response < <(engine "$url" "$secret" "$body")
        status=$(jq -r '.result.status // .error.message' <<<"$response")
        number=$(jq -r '.payload.blockNumber' <<<"$line")
        txs=$(jq '.payload.transactions | length' <<<"$line")
        gas=$(jq -r '.payload.gasUsed' <<<"$line")
        hash=$(jq -r '.payload.blockHash' <<<"$line")
        number=$((number))
        gas=$((gas))
        fcu_seconds=0
        if [ "$status" = VALID ]; then
            jq -nc --arg hash "$hash" '{jsonrpc: "2.0", id: 1,
                method: "engine_forkchoiceUpdatedV3",
                params: [{headBlockHash: $hash, safeBlockHash: $hash,
                    finalizedBlockHash: $hash}, null]}' >"$body"
            read -r fcu_seconds response < <(engine "$url" "$secret" "$body")
        fi
        awk -v n="$number" -v k="$txs" -v g="$gas" -v t="$seconds" -v f="$fcu_seconds" \
            -v s="$status" 'BEGIN { printf "IMPORT block=%d txs=%d gas=%d new_payload_ns=%.0f " \
            "fcu_ns=%.0f status=%s\n", n, k, g, t * 1e9, f * 1e9, s }' >>"$out"
        [ "$status" = VALID ] || { echo "block $number: $status" >&2; rm -f "$body"; exit 1; }
    done <"$payloads"
    rm -f "$body"
}

case ${1:-} in
export) export_blocks "$2" "$3" "$4" "$5" ;;
import) import_blocks "$2" "$3" "$4" "$5" ;;
*)
    sed -n '2,15p' "$0"
    exit 2
    ;;
esac
