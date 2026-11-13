#!/usr/bin/env bash
# A public OP Stack L2 sequenced by needlefish, settling on a public L1 (Ethereum Sepolia).
# See docs/PUBLIC_L2.md.
#
#   public-l2.sh keys     generate the role keys (once) and print their addresses
#   public-l2.sh deploy   deploy the base/contracts L1 system, write genesis and rollup.json
#   public-l2.sh up       start every process as a user systemd unit (nfl2-*)
#   public-l2.sh down     stop them
#   public-l2.sh status   units, heads, and balances
#
# Environment:
#   NF_L2_DIR      state directory (keys, configs, data dirs, logs); never committed
#   NF_CONTRACTS   base/contracts checkout with `just deps` run (forge script source)
#   L1_RPC         L1 JSON-RPC as http://IPv4:port (the needlefish binaries take no TLS; for
#                  a public HTTPS endpoint `up` starts `base https-bridge`, see L1_UPSTREAM)
#   L1_UPSTREAM    HTTPS L1 RPC and beacon to bridge: "RPC_URL,BEACON_URL" (empty: none)
#   L1_BEACON      beacon API as http://IPv4:port (empty: calldata batches only)
#   BASE           the needlefish binary (default zig-out/bin/base)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
REPO=$PWD

NF_L2_DIR=${NF_L2_DIR:-$HOME/.cache/needlefish/public-l2}
NF_CONTRACTS=${NF_CONTRACTS:-$HOME/.cache/needlefish/base-contracts}
BASE=${BASE:-$REPO/zig-out/bin/base}
L1_RPC=${L1_RPC:-http://127.0.0.1:31545}
L1_BEACON=${L1_BEACON-http://127.0.0.1:31052}
L1_UPSTREAM=${L1_UPSTREAM-https://ethereum-sepolia-rpc.publicnode.com,https://ethereum-sepolia-beacon-api.publicnode.com}
L2_CHAIN_ID=${L2_CHAIN_ID:-20261112}
GAME_TYPE=621
# L2 blocks per dispute game, with an intermediate root every tenth: 1800 is one game every
# 6 min, about 240 Sepolia transactions a day from the proposer. Every upgrade is active from
# genesis, so the contracts use the subsecond-block ("fast") intervals; the slow pair, set
# to a tenth for the same root count, never applies. A multiple of 100.
GAME_INTERVAL=${GAME_INTERVAL:-1800}
# Blocks the verifier EL keeps witnesses for. The prover proves a game once L1 finalized it,
# about 13 min (3900 blocks) after its last block, so the window covers finality, a game,
# and the proving time with room for a stalled prover to catch up: 16384 blocks is 55 min.
# A game whose blocks leave the window can never be proven, and every later game waits on it.
WITNESS_WINDOW=${WITNESS_WINDOW:-16384}
# Blocks the sequencer EL keeps across a restart. A durable `base node` keeps 1024 unless its
# proofs window is longer, and a consensus node resetting its pipeline after an engine restart
# walks its safe head back one channel timeout of L1 origins (50 L1 blocks, about 3000 L2
# blocks): with fewer the sequencer can never resume.
SEQ_RETAIN=${SEQ_RETAIN:-8192}
# The deploy lands well before the L2 starts, so its fork activations are history by then.
GENESIS_LEAD_S=${GENESIS_LEAD_S:-1200}

# Ports: none collide with the nf-* Base nodes or the local devnet.
PORT_BRIDGE_RPC=31545
PORT_BRIDGE_BEACON=31052
PORT_SEQ_HTTP=31645
PORT_SEQ_ENGINE=31651
PORT_SEQ_CL=31745
PORT_SEQ_P2P=31322 # TCP; UDP (discv5) is the next port
PORT_VER_HTTP=31845
PORT_VER_ENGINE=31851
PORT_VER_CL=31945
PORT_VER_P2P=31422 # TCP; UDP (discv5) is the next port
PORT_BATCHER_METRICS=31300
PORT_PROVER=31310
PORT_PROPOSER_HEALTH=31320
PORT_PROPOSER_METRICS=31321
PORT_CHALLENGER_HEALTH=31330
PORT_CHALLENGER_METRICS=31331

KEYS=$NF_L2_DIR/keys
CONFIG=$NF_L2_DIR/config
ROLES="deployer batcher proposer challenger sequencer enclave user rogue"

log() { printf 'public-l2: %s\n' "$*"; }
die() { log "$*" >&2; exit 1; }
key() { cat "$KEYS/$1.key"; }
addr() { cast wallet address --private-key "$(key "$1")"; }
deployed() { jq -er --arg k "$1" '.[$k]' "$CONFIG/deployments.json"; }

rpc() { # url method params
  curl -s -m 10 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1"
}

need_tools() {
  local tool
  for tool in cast forge jq curl "$BASE"; do
    command -v "$tool" >/dev/null || die "missing $tool"
  done
}

cmd_keys() {
  mkdir -p "$KEYS"
  chmod 700 "$KEYS"
  local role
  for role in $ROLES; do
    if [ ! -s "$KEYS/$role.key" ]; then
      (umask 077 && cast wallet new --json |
        jq -r '.data | (if type == "array" then .[0] else . end) | .private_key' \
          >"$KEYS/$role.key")
    fi
    printf '%-11s %s\n' "$role" "$(addr "$role")"
  done
}

# Two empty contracts stand in for the Nitro attestation validator and the SP1 verifier:
# signers are registered without attestation (DevTEEProverRegistry) and there is no ZK prover.
deploy_placeholders() {
  [ -f "$CONFIG/placeholders.env" ] && return 0
  local nitro sp1
  nitro=$(forge_create)
  sp1=$(forge_create)
  printf 'NITRO=%s\nSP1=%s\n' "$nitro" "$sp1" >"$CONFIG/placeholders.env"
}

forge_create() {
  (cd "$NF_CONTRACTS" && forge create test/mocks/MockNitroValidator.sol:MockNitroValidator \
    --rpc-url "$L1_RPC" --private-key "$(key deployer)" --broadcast 2>/dev/null) |
    awk '/Deployed to:/ {print $3}'
}

# Fork activations: all Base upgrades through Denim (200 ms blocks), activated at P, an L1
# time in the past at deploy. ProtocolVersions imports past activations without notice, and
# the proof program pins the same schedule (`schedule_id.pin`) from rollup.json.
write_deploy_config() {
  local T=$1 P=$2 anchor_root=$3
  # shellcheck disable=SC1091
  . "$CONFIG/placeholders.env"
  jq --arg owner "$(addr deployer)" --arg batcher "$(addr batcher)" \
    --arg seq "$(addr sequencer)" --arg prop "$(addr proposer)" \
    --arg chal "$(addr challenger)" --arg nitro "$NITRO" --arg sp1 "$SP1" \
    --arg root "$anchor_root" --argjson T "$T" --argjson P "$P" --argjson l2 "$L2_CHAIN_ID" \
    --argjson interval "$GAME_INTERVAL" \
    --argjson l1 "$(cast chain-id --rpc-url "$L1_RPC")" '
    .finalSystemOwner = $owner | .proxyAdminOwner = $owner | .guardian = $owner
    | .baseFeeVaultRecipient = $owner | .l1FeeVaultRecipient = $owner
    | .operatorFeeVaultRecipient = $owner | .sequencerFeeVaultRecipient = $owner
    | .batchSenderAddress = $batcher | .p2pSequencerAddress = $seq
    | .teeProposer = $prop | .teeChallenger = $chal
    | .l1ChainId = $l1 | .l2ChainId = $l2 | .fundDevAccounts = false
    | .l2GenesisBlockGasLimit = "0x3938700" | .l2BlockTime = 2
    | .l2GenesisTimestamp = $T | .l2GenesisBlockNumber = 0
    | .nitroValidator = $nitro | .sp1Verifier = $sp1
    | .teeImageHash = ("0x" + ("01" * 32)) | .zkRangeHash = ("0x" + ("01" * 32))
    | .zkAggregationHash = ("0x" + ("01" * 32)) | .multiproofConfigHash = ("0x" + ("01" * 32))
    | .multiproofGenesisOutputRoot = $root | .multiproofGenesisBlockNumber = 0
    | .multiproofSlowBlockInterval = ($interval / 10)
    | .multiproofSlowIntermediateBlockInterval = ($interval / 100)
    | .multiproofFastBlockInterval = $interval
    | .multiproofFastIntermediateBlockInterval = ($interval / 10)
    | .proofMaturityDelaySeconds = 600 | .disputeGameFinalityDelaySeconds = 600
    | .delayedWETHWithdrawalDelay = 600
    | .protocolVersionsInitialSchedule = [range(14) | $P]
    | .protocolVersionsInitialMinimumVersion = "0x1000000000000000000000000"' \
    "$NF_CONTRACTS/deploy-config/local.json" >"$NF_CONTRACTS/deploy-config/nf-public-l2.json"
  cp "$NF_CONTRACTS/deploy-config/nf-public-l2.json" "$CONFIG/deploy-config.json"
}

# SystemDeploy (base/contracts). Without --broadcast it only simulates: the proxies are
# CREATE2 addresses, so the simulation names the L1 addresses the L2 genesis needs.
system_deploy() { # [--broadcast]
  rm -f "$NF_CONTRACTS/deployments/nf-public-l2.json"
  (cd "$NF_CONTRACTS" &&
    FOUNDRY_SCRIPT_EXECUTION_PROTECTION=false \
      DEPLOY_CONFIG_PATH=deploy-config/nf-public-l2.json \
      DEPLOYMENT_OUTFILE=deployments/nf-public-l2.json \
      forge script scripts/deploy/SystemDeploy.s.sol:SystemDeploy --rpc-url "$L1_RPC" \
      --private-key "$(key deployer)" --slow "$@") >"$CONFIG/system-deploy.log" 2>&1 ||
    { tail -n 20 "$CONFIG/system-deploy.log"; die "SystemDeploy failed"; }
  cp "$NF_CONTRACTS/deployments/nf-public-l2.json" "$CONFIG/deployments.json"
}

# The L2 genesis: base/contracts L2Genesis allocs in a needlefish genesis template.
write_l2_genesis() {
  local T=$1 P=$2 out=$3
  (cd "$NF_CONTRACTS" &&
    NF_OWNER=$(addr deployer) NF_L1_CHAIN_ID=$(cast chain-id --rpc-url "$L1_RPC") \
      NF_L2_CHAIN_ID=$L2_CHAIN_ID NF_L1_CDM=$(deployed L1CrossDomainMessengerProxy) \
      NF_L1_BRIDGE=$(deployed L1StandardBridgeProxy) \
      NF_L1_ERC721_BRIDGE=$(deployed L1ERC721BridgeProxy) \
      NF_ALLOCS_OUT=snapshots/nf-public-l2-allocs.json \
      forge script scripts/nf/NfL2Genesis.s.sol:NfL2Genesis) >"$CONFIG/l2-genesis.log" 2>&1 ||
    { tail -n 20 "$CONFIG/l2-genesis.log"; die "L2Genesis failed"; }
  local template
  template=$(mktemp -d)
  "$BASE" devnet init --out "$template" --timestamp "$T" >/dev/null
  jq --slurpfile allocs "$NF_CONTRACTS/snapshots/nf-public-l2-allocs.json" \
    --argjson id "$L2_CHAIN_ID" --argjson P "$P" '
    .config.chainId = $id
    | .config |= with_entries(if (.key | test("^(regolith|canyon|delta|ecotone|fjord|granite|holocene|isthmus|jovian)Time$")) then .value = $P else . end)
    | .config.base |= map_values($P)
    | .alloc = ($allocs[0] | with_entries(.value |= del(.nonce | select(. == "0x0"))))' \
    "$template/l2-genesis.json" >"$out"
  cp "$template/jwt.hex" "$CONFIG/jwt.hex"
  rm -rf "$template"
}

# keccak256(version 0 ++ state root ++ L2ToL1MessagePasser storage root ++ block hash) of
# the L2 genesis, read from a throwaway `base node` on the genesis file.
genesis_output_root() {
  local genesis=$1 dir pid block hash state storage
  dir=$(mktemp -d)
  "$BASE" node --chain "$genesis" --http.port 31999 >"$dir/node.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 50); do
    block=$(rpc http://127.0.0.1:31999 eth_getBlockByNumber '["0x0",false]' | jq -c '.result // empty')
    [ -n "$block" ] && break
    sleep 0.2
  done
  hash=$(jq -r .hash <<<"$block")
  state=$(jq -r .stateRoot <<<"$block")
  storage=$(rpc http://127.0.0.1:31999 eth_getProof \
    '["0x4200000000000000000000000000000000000016",[],"0x0"]' | jq -r .result.storageHash)
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  rm -rf "$dir"
  [ ${#storage} -eq 66 ] && [ ${#hash} -eq 66 ] || die "could not read the L2 genesis"
  printf '%s\n' "$hash" >"$CONFIG/l2-genesis-hash"
  cast keccak "$(cast concat-hex "0x$(printf '0%.0s' $(seq 1 64))" "$state" "$storage" "$hash")"
}

# The last L1 block at or before T: the rollup's L1 genesis.
l1_genesis_block() {
  local T=$1 number timestamp
  while [ "$(cast block latest -f timestamp --rpc-url "$L1_RPC")" -le "$T" ]; do sleep 6; done
  number=$(cast block latest -f number --rpc-url "$L1_RPC")
  while :; do
    timestamp=$(cast block "$number" -f timestamp --rpc-url "$L1_RPC")
    [ "$timestamp" -le "$T" ] && break
    number=$((number - 1))
  done
  printf '%s %s\n' "$number" "$(cast block "$number" -f hash --rpc-url "$L1_RPC")"
}

sysconfig() { # getter, 0 when the contract has no such getter
  cast call "$(deployed SystemConfigProxy)" "$1" --rpc-url "$L1_RPC" 2>/dev/null |
    awk 'NR == 1 {print $1}' | grep . || echo 0
}

write_rollup_config() {
  local T=$1 P=$2 l1_number=$3 l1_hash=$4 out=$5 template
  template=$(mktemp -d)
  "$BASE" devnet init --out "$template" --timestamp "$T" >/dev/null
  jq --argjson T "$T" --argjson P "$P" --argjson n "$l1_number" --arg h "$l1_hash" \
    --arg l2 "$(cat "$CONFIG/l2-genesis-hash")" --argjson l1id "$(cast chain-id --rpc-url "$L1_RPC")" \
    --argjson l2id "$L2_CHAIN_ID" --arg batcher "$(addr batcher)" \
    --arg scalar "$(cast to-uint256 "$(sysconfig 'scalar()(uint256)')")" \
    --argjson gas "$(sysconfig 'gasLimit()(uint64)')" \
    --argjson bfs "$(sysconfig 'basefeeScalar()(uint32)')" \
    --argjson bbfs "$(sysconfig 'blobbasefeeScalar()(uint32)')" \
    --arg inbox "$(sysconfig 'batchInbox()(address)')" \
    --arg portal "$(deployed OptimismPortalProxy)" --arg sc "$(deployed SystemConfigProxy)" \
    --arg pv "$(deployed ProtocolVersionsProxy)" '
    .genesis.l1 = {hash: $h, number: $n} | .genesis.l2 = {hash: $l2, number: 0}
    | .genesis.l2_time = $T
    | .genesis.system_config.batcherAddr = ($batcher | ascii_downcase)
    | .genesis.system_config.scalar = $scalar | .genesis.system_config.gasLimit = $gas
    | .genesis.system_config.baseFeeScalar = $bfs
    | .genesis.system_config.blobBaseFeeScalar = $bbfs
    | .l1_chain_id = $l1id | .l2_chain_id = $l2id
    | with_entries(if (.key | test("^(regolith|canyon|delta|ecotone|fjord|granite|holocene|pectra_blob_schedule|isthmus|jovian)_time$")) then .value = $P else . end)
    | .base |= map_values($P)
    | .batch_inbox_address = ($inbox | ascii_downcase)
    | .deposit_contract_address = ($portal | ascii_downcase)
    | .l1_system_config_address = ($sc | ascii_downcase)
    | .protocol_versions_address = ($pv | ascii_downcase)' \
    "$template/rollup.json" >"$out"
  rm -rf "$template"
}

# Local-mode enclave signers (TEE image hash 0) and the chain's config hash, so the
# needlefish TEE prover's proofs verify on L1 (contracts/NfPostDeploy.s.sol).
post_deploy() {
  local config_hash
  config_hash=$("$BASE" proof config-hash "$CONFIG/rollup.json")
  (cd "$NF_CONTRACTS" &&
    NF_FACTORY=$(deployed DisputeGameFactoryProxy) NF_PROXY_ADMIN=$(deployed ProxyAdmin) \
      NF_TEE_REGISTRY=$(deployed TEEProverRegistryProxy) NF_GAME_TYPE=$GAME_TYPE \
      NF_SIGNERS=$(addr enclave) NF_CONFIG_HASH=$config_hash \
      forge script scripts/nf/NfPostDeploy.s.sol:NfPostDeploy --rpc-url "$L1_RPC" \
      --private-key "$(key deployer)" --broadcast --start-fresh --slow) >"$CONFIG/post-deploy.log" 2>&1 ||
    { tail -n 20 "$CONFIG/post-deploy.log"; die "post deploy failed"; }
  printf '%s\n' "$config_hash" >"$CONFIG/config-hash"
}

cmd_deploy() {
  need_tools
  [ $((GAME_INTERVAL % 100)) -eq 0 ] || die "GAME_INTERVAL must be a multiple of 100"
  [ -s "$KEYS/deployer.key" ] || die "run 'keys' first"
  [ -f "$CONFIG/rollup.json" ] && die "$CONFIG/rollup.json exists; this chain is deployed"
  mkdir -p "$CONFIG"
  ln -sfn "$REPO/etc/public-l2/contracts" "$NF_CONTRACTS/scripts/nf"
  local now T P root
  now=$(cast block latest -f timestamp --rpc-url "$L1_RPC")
  T=$((now + GENESIS_LEAD_S))
  # Upgrades activate 8 h back: a pipeline reset walks back the channel timeout in force at
  # its safe head's time minus Denim's 6 h sequencer drift (base/base `pipeline/core.rs`).
  # Granite any later makes that the pre-Granite 300 L1 blocks (18000 L2 blocks), past what
  # the sequencer EL keeps, so a restart in the chain's first hours could never resume.
  P=$((now - 8 * 3600))
  printf 'T=%s\nP=%s\n' "$T" "$P" >"$CONFIG/times.env"
  log "L2 genesis time $T, upgrades activated at $P"
  deploy_placeholders
  write_deploy_config "$T" "$P" "0x$(printf '0%.0s' $(seq 1 63))1"
  system_deploy
  write_l2_genesis "$T" "$P" "$CONFIG/l2-genesis.json"
  root=$(genesis_output_root "$CONFIG/l2-genesis.json")
  log "L2 genesis $(cat "$CONFIG/l2-genesis-hash"), output root $root"
  write_deploy_config "$T" "$P" "$root"
  local simulated
  simulated=$(jq -S '{L1CrossDomainMessengerProxy, L1StandardBridgeProxy, L1ERC721BridgeProxy}' \
    "$CONFIG/deployments.json")
  system_deploy --broadcast --start-fresh
  [ "$simulated" = "$(jq -S '{L1CrossDomainMessengerProxy, L1StandardBridgeProxy,
    L1ERC721BridgeProxy}' "$CONFIG/deployments.json")" ] ||
    die "deployed bridge proxies differ from the simulation the L2 genesis used"
  log "L1 contracts deployed; waiting for L1 to pass the L2 genesis time"
  local l1
  l1=$(l1_genesis_block "$T")
  write_rollup_config "$T" "$P" "${l1% *}" "${l1#* }" "$CONFIG/rollup.json"
  post_deploy
  log "deployed: L1 genesis block ${l1% *}, config hash $(cat "$CONFIG/config-hash")"
}

# --- processes -----------------------------------------------------------------------------

unit() { # name command...
  local name=$1
  shift
  systemctl --user is-active --quiet "nfl2-$name" && { log "$name: running"; return 0; }
  systemctl --user reset-failed "nfl2-$name" 2>/dev/null || true
  mkdir -p "$NF_L2_DIR/logs"
  systemd-run --user --quiet --unit "nfl2-$name" --property=Restart=on-failure \
    --property=RestartSec=5 --working-directory="$NF_L2_DIR" \
    /bin/sh -c "exec \"\$0\" \"\$@\" >>\"$NF_L2_DIR/logs/$name.log\" 2>&1" "$@"
  log "$name: started (log $NF_L2_DIR/logs/$name.log)"
}

wait_http() { # url
  for _ in $(seq 1 100); do
    rpc "$1" eth_chainId '[]' | grep -q result && return 0
    sleep 0.3
  done
  die "$1 did not answer"
}

sequencer_enr() {
  for _ in $(seq 1 100); do
    local enr
    enr=$(grep -o 'enr=enr:[^ ]*' "$NF_L2_DIR/logs/seq-cl.log" 2>/dev/null | tail -n 1 | cut -d= -f2-)
    [ -n "$enr" ] && { printf '%s\n' "$enr"; return 0; }
    sleep 0.3
  done
  die "no sequencer ENR in seq-cl.log"
}

cmd_up() {
  [ -f "$CONFIG/rollup.json" ] || die "run 'deploy' first"
  local L2=http://127.0.0.1 da=calldata beacon_args=()
  if [ -n "$L1_UPSTREAM" ]; then
    unit bridge "$BASE" https-bridge \
      --routes "$PORT_BRIDGE_RPC=${L1_UPSTREAM%,*},$PORT_BRIDGE_BEACON=${L1_UPSTREAM#*,}"
    sleep 1
  fi
  if [ -n "$L1_BEACON" ]; then
    da=blobs
    beacon_args=(--l1-beacon "$L1_BEACON")
  fi
  unit seq-el "$BASE" node --chain "$CONFIG/l2-genesis.json" --datadir "$NF_L2_DIR/seq-el" \
    --http.port "$PORT_SEQ_HTTP" --authrpc.port "$PORT_SEQ_ENGINE" \
    --authrpc.jwtsecret "$CONFIG/jwt.hex" --builder.enabled \
    --proofs-history --proofs-history.window "$SEQ_RETAIN"
  unit ver-el "$BASE" node --chain "$CONFIG/l2-genesis.json" --datadir "$NF_L2_DIR/ver-el" \
    --http.port "$PORT_VER_HTTP" --authrpc.port "$PORT_VER_ENGINE" \
    --authrpc.jwtsecret "$CONFIG/jwt.hex" --proofs-history --proofs-history.window "$WITNESS_WINDOW"
  wait_http "$L2:$PORT_SEQ_HTTP"
  wait_http "$L2:$PORT_VER_HTTP"
  mkdir -p "$NF_L2_DIR/seq-cl" "$NF_L2_DIR/ver-cl"
  unit seq-cl "$BASE" consensus --rollup-config "$CONFIG/rollup.json" --l1 "$L1_RPC" \
    "${beacon_args[@]}" --l2 "$L2:$PORT_SEQ_ENGINE" --l2-jwt "$CONFIG/jwt.hex" \
    --rpc.port "$PORT_SEQ_CL" --rpc.enable-admin --sequencer \
    --metrics.enabled --metrics.addr 127.0.0.1 --metrics.port $((PORT_SEQ_CL + 1)) \
    --p2p.sequencer.key.path "$KEYS/sequencer.key" \
    --p2p.listen.ip 127.0.0.1 --p2p.listen.tcp "$PORT_SEQ_P2P" --p2p.listen.udp $((PORT_SEQ_P2P + 1)) \
    --p2p.bootstore "$NF_L2_DIR/seq-cl/bootstore.json" \
    --safedb.path "$NF_L2_DIR/seq-cl/safedb.bin" --checkpoint.path "$NF_L2_DIR/seq-cl/checkpoint.bin"
  local enr
  enr=$(sequencer_enr) || exit 1
  unit ver-cl "$BASE" consensus --rollup-config "$CONFIG/rollup.json" --l1 "$L1_RPC" \
    "${beacon_args[@]}" --l2 "$L2:$PORT_VER_ENGINE" --l2-jwt "$CONFIG/jwt.hex" \
    --rpc.port "$PORT_VER_CL" --p2p.listen.ip 127.0.0.1 \
    --metrics.enabled --metrics.addr 127.0.0.1 --metrics.port $((PORT_VER_CL + 1)) \
    --p2p.listen.tcp "$PORT_VER_P2P" --p2p.listen.udp $((PORT_VER_P2P + 1)) \
    --p2p.bootstore "$NF_L2_DIR/ver-cl/bootstore.json" --p2p.bootnodes "$enr" \
    --safedb.path "$NF_L2_DIR/ver-cl/safedb.bin" --checkpoint.path "$NF_L2_DIR/ver-cl/checkpoint.bin"
  unit batcher "$BASE" batcher --rollup-config "$CONFIG/rollup.json" --l1 "$L1_RPC" \
    --l2 "$L2:$PORT_SEQ_HTTP" --rollup-rpc "$L2:$PORT_SEQ_CL" --private-key "$(key batcher)" \
    --data-availability "$da" --metrics.port "$PORT_BATCHER_METRICS" --num-confirmations 2
  unit prover-service "$BASE" prover-service --listen "$L2:$PORT_PROVER"
  unit prover-worker "$BASE" prover-worker --backend tee --enclave-key-file "$KEYS/enclave.key" \
    --prover-rpc "$L2:$PORT_PROVER" --l1 "$L1_RPC" "${beacon_args[@]}" --l2 "$L2:$PORT_VER_HTTP" \
    --rollup-config "$CONFIG/rollup.json" --worker-id public-l2 --enclave-allow-custom-chain
  unit proposer "$BASE" proposer --prover-rpc "$L2:$PORT_PROVER" --l1-eth-rpc "$L1_RPC" \
    --l2-eth-rpc "$L2:$PORT_VER_HTTP" --rollup-rpc "$L2:$PORT_VER_CL" \
    --anchor-state-registry-addr "$(deployed AnchorStateRegistryProxy)" \
    --dispute-game-factory-addr "$(deployed DisputeGameFactoryProxy)" --game-type "$GAME_TYPE" \
    --private-key "$(key proposer)" --health.port "$PORT_PROPOSER_HEALTH" \
    --metrics.enabled --metrics.port "$PORT_PROPOSER_METRICS"
  unit challenger "$BASE" challenger --l1-eth-rpc "$L1_RPC" --l2-eth-rpc "$L2:$PORT_VER_HTTP" \
    --dispute-game-factory-addr "$(deployed DisputeGameFactoryProxy)" \
    --anchor-state-registry-addr "$(deployed AnchorStateRegistryProxy)" \
    --game-type "$GAME_TYPE" --private-key "$(key challenger)" \
    --zk-rpc-url "$L2:$PORT_PROVER" \
    --health.port "$PORT_CHALLENGER_HEALTH" --metrics.enabled \
    --metrics.port "$PORT_CHALLENGER_METRICS"
}

cmd_down() {
  local name
  for name in challenger proposer prover-worker prover-service batcher ver-cl seq-cl ver-el \
    seq-el bridge; do
    systemctl --user stop "nfl2-$name" 2>/dev/null && log "$name: stopped" || true
  done
}

head_of() { rpc "$1" optimism_syncStatus '[]' | jq -c "{unsafe: .result.unsafe_l2.number,
  safe: .result.safe_l2.number, finalized: .result.finalized_l2.number}"; }

cmd_status() {
  systemctl --user list-units 'nfl2-*' --no-pager --no-legend | awk '{print $1, $3, $4}'
  printf 'sequencer %s\nverifier  %s\n' "$(head_of "http://127.0.0.1:$PORT_SEQ_CL")" \
    "$(head_of "http://127.0.0.1:$PORT_VER_CL")"
  local role
  for role in $ROLES; do
    printf '%-11s %s ETH\n' "$role" \
      "$(cast balance "$(addr "$role")" --ether --rpc-url "$L1_RPC" 2>/dev/null || echo '?')"
  done
}

# --- exercises -----------------------------------------------------------------------------

l2_output() { # block -> output root (verifier's rollup node)
  # The node answers "output not available yet" while it fetches a block that is not
  # finalized, and keeps the fetched output only briefly, so ask again quickly.
  local _ root
  for _ in $(seq 1 60); do
    root=$(rpc "http://127.0.0.1:$PORT_VER_CL" optimism_outputAtBlock \
      "[\"$(printf '0x%x' "$1")\"]" | jq -er .result.outputRoot 2>/dev/null) &&
      { echo "$root"; return 0; }
    sleep 0.3
  done
  return 1
}

# Sends VALUE ether from the user key to the portal: a deposit to the same address on L2.
cmd_deposit() {
  local value=${1:-0.01}
  cast send "$(deployed OptimismPortalProxy)" --value "${value}ether" --private-key "$(key user)" \
    --rpc-url "$L1_RPC" --json | jq -r '"deposit tx \(.transactionHash) block \(.blockNumber) status \(.status)"'
}

# Withdraws VALUE ether from the user's L2 balance to its L1 address with `base withdrawer`
# (`initiate`, then `run` proves against a game and finalizes once the game resolves).
cmd_withdraw() {
  local command=${1:-run} value_wei l2=$PORT_VER_HTTP
  value_wei=$(cast to-wei "${2:-0.001}")
  # `base node` does not forward transactions: the initiating one goes to the sequencer.
  # Proving reads historical state proofs, which the verifier keeps (--proofs-history).
  [ "$command" = initiate ] && l2=$PORT_SEQ_HTTP
  BASE_WITHDRAWER_PRIVATE_KEY=$(key user) "$BASE" withdrawer "$command" \
    --l1-rpc-url "$L1_RPC" --l2-rpc-url "http://127.0.0.1:$l2" \
    --portal "$(deployed OptimismPortalProxy)" --l1-chain-id "$(cast chain-id --rpc-url "$L1_RPC")" \
    --l2-chain-id "$L2_CHAIN_ID" --journal "$NF_L2_DIR/withdrawer.journal" \
    --target "$(addr user)" --value-wei "$value_wei"
}

# A bad claim: a game whose final output root is wrong, TEE-proven by a second dev signer
# ("rogue", registered as signer and proposer by the owner). It extends the newest game (or
# the anchor) by one interval with the correct intermediate roots except the last. The
# challenger must find it and nullify it with a proof of the correct root.
cmd_bad_claim() {
  local factory registry impl count parent start start_root interval step roots="" i root
  factory=$(deployed DisputeGameFactoryProxy)
  registry=$(deployed TEEProverRegistryProxy)
  impl=$(cast call "$factory" 'gameImpls(uint32)(address)' "$GAME_TYPE" --rpc-url "$L1_RPC")
  local rogue rogue_key
  rogue_key=$(key rogue)
  rogue=$(addr rogue)
  if [ "$(cast call "$registry" 'isValidProposer(address)(bool)' "$rogue" --rpc-url "$L1_RPC")" != true ]; then
    cast send "$registry" 'setProposer(address,bool)' "$rogue" true --private-key "$(key deployer)" \
      --rpc-url "$L1_RPC" >/dev/null
    cast send "$registry" 'addDevSigner(address,bytes32)' "$rogue" "$(cast to-uint256 0)" \
      --private-key "$(key deployer)" --rpc-url "$L1_RPC" >/dev/null
    cast send "$rogue" --value 0.01ether --private-key "$(key deployer)" --rpc-url "$L1_RPC" >/dev/null
  fi
  count=$(cast call "$factory" 'gameCount()(uint256)' --rpc-url "$L1_RPC" | awk '{print $1}')
  parent=$(deployed AnchorStateRegistryProxy)
  read -r start_root start < <(cast call "$parent" 'getAnchorRoot()(bytes32,uint256)' \
    --rpc-url "$L1_RPC" | awk '{print $1}' | paste -sd' ')
  for ((i = count - 1; i >= 0; i--)); do
    local game
    game=$(cast call "$factory" 'gameAtIndex(uint256)(uint32,uint64,address)' "$i" \
      --rpc-url "$L1_RPC" | sed -n 3p)
    [ "$(cast call "$game" 'gameType()(uint32)' --rpc-url "$L1_RPC")" = "$GAME_TYPE" ] || continue
    [ "$(cast call "$game" 'status()(uint8)' --rpc-url "$L1_RPC")" = 0 ] || continue
    [ "$(cast call "$game" 'gameCreator()(address)' --rpc-url "$L1_RPC")" = "$rogue" ] && continue
    parent=$game
    start=$(cast call "$game" 'l2SequenceNumber()(uint256)' --rpc-url "$L1_RPC" | awk '{print $1}')
    start_root=$(cast call "$game" 'rootClaim()(bytes32)' --rpc-url "$L1_RPC")
    break
  done
  read -r interval step < <(cast call "$impl" 'intervalsForStartingBlock(uint256)(uint256,uint256)' \
    "$start" --rpc-url "$L1_RPC" | awk '{print $1}' | paste -sd' ')
  local target=$((start + interval)) bad
  bad=$(cast keccak "needlefish bad claim $target")
  for ((i = start + step; i <= target; i += step)); do
    root=$(l2_output "$i") || die "no output root for block $i yet"
    [ "$i" -eq "$target" ] && root=$bad
    roots="$roots${root#0x}"
  done
  local timestamp schedule l1_number l1_hash config_hash image journal signature extra init
  timestamp=$(cast block "$target" -f timestamp --rpc-url "http://127.0.0.1:$PORT_VER_HTTP")
  schedule=$(cast call "$(cast call "$impl" 'PROTOCOL_VERSIONS()(address)' --rpc-url "$L1_RPC")" \
    'activatedScheduleId(uint64)(bytes32)' "$timestamp" --rpc-url "$L1_RPC")
  l1_number=$(($(cast block-number --rpc-url "$L1_RPC") - 2))
  l1_hash=$(cast block "$l1_number" -f hash --rpc-url "$L1_RPC")
  config_hash=$(cast call "$impl" 'CONFIG_HASH()(bytes32)' --rpc-url "$L1_RPC")
  image=$(cast call "$impl" 'TEE_IMAGE_HASH()(bytes32)' --rpc-url "$L1_RPC")
  journal=$(cast keccak "$(cast concat-hex "$rogue" "$l1_hash" "$start_root" \
    "$(printf '0x%016x' "$start")" "$bad" "$(printf '0x%016x' "$target")" "0x$roots" \
    "$config_hash" "$image" "$schedule")")
  signature=$(cast wallet sign --no-hash "$journal" --private-key "$rogue_key")
  extra=$(cast concat-hex "$(cast to-uint256 "$target")" "$parent" "0x$roots")
  init=$(cast concat-hex 0x00 "$l1_hash" "$(cast to-uint256 "$l1_number")" "$signature")
  log "bad claim: block $target (parent $parent at $start), root $bad"
  cast send "$factory" 'createWithInitData(uint32,bytes32,bytes,bytes)' "$GAME_TYPE" "$bad" \
    "$extra" "$init" --private-key "$rogue_key" --rpc-url "$L1_RPC" --json |
    jq -r '"bad claim tx \(.transactionHash) status \(.status)"'
  cast call "$factory" 'games(uint32,bytes32,bytes)(address,uint64)' "$GAME_TYPE" "$bad" "$extra" \
    --rpc-url "$L1_RPC" | head -n 1 | sed 's/^/bad claim game /'
}

case "${1:-}" in
deposit) shift; cmd_deposit "$@" ;;
withdraw) shift; cmd_withdraw "$@" ;;
bad-claim) cmd_bad_claim ;;
keys) cmd_keys ;;
deploy) cmd_deploy ;;
up) cmd_up ;;
down) cmd_down ;;
status) cmd_status ;;
*) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
