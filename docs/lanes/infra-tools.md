# Lane: infra-tools

Owns `src/infra/*` (submodules `websocket_proxy`, `roxy`, `load_test`, `withdrawer`,
`basectl`, `audit`, `snapshotter`, `tx_manager`) and the matching `bin/base`
subcommands (`basectl`, `websocket-proxy`, `roxy`, `load-test`, `withdrawer`,
`balance-monitor`). Reference: base/base `crates/infra/{basectl,websocket-proxy,roxy,
load-tests,withdrawer,audit,snapshotter,telemetry}` and `crates/utilities/{tx-manager,
balance-monitor,health,optimism-rpc}`. Out of scope for now: `zk-*`, `snark-e2e`,
`challenger-e2e`, `fee-jobs`, `sidecrush`, `shadow-metrics` (add later if valuable).

Reuse, do not duplicate: HTTP/WS/JSON-RPC/metrics/health/retry/balance_monitor from
`src/utilities`, tx types and signing from `src/common`. Small additive edits in those
modules are fine (a `pub`, a hook); larger changes go through the owning lane. All IO
through `src/utilities/io` so every tool runs in the simulator. Bounded queues, static
allocation after startup.

## Backlog
- [x] `infra/tx_manager` core: nonce tracking, fee bumping (EIP-1559 + blob fee), resubmit on
  timeout, receipt confirmation depth, bounded pending set (port
  `utilities/tx-manager`). Sim tests with a fake L1 that drops/reorders txs; fuzz the
  fee-bump state machine. Coordinate with batcher-devnet: it may switch to this later.
- [x] `infra/tx_manager` driver: JSON-RPC driver over the sans-IO core (fee suggestion,
  local EIP-1559 signing, `eth_sendRawTransaction`, receipt + canonical-block check, gas
  estimation). The devnet exercise is part of `load-test` below.
- [x] `infra/tx_manager` blob driver: EIP-4844 sends with sidecars (reuse `batcher/blobs`).
- [x] `infra/websocket_proxy`: dropped; it only fanned out the flashblocks feed, and
  needlefish has no flashblocks (AGENTS.md rule 10).
- [x] `infra/roxy`: HTTP JSON-RPC server scaffold with health endpoint, then a
  load-balancing RPC proxy over N upstreams with health checks, retry, and method
  allowlist (port `roxy`, extend toward base/base's intent). Sim test with a failing
  upstream.
- [x] `infra/load_test`: seeded workload generator (funded dev accounts from the
  public test-junk mnemonic, transfer/ERC-20/calldata payload mixes, key stream),
  open-loop rate runner, latency/inclusion metrics, report (port `load-tests/src/*`).
  `bin/base load-test` against the devnet; deterministic in sim with a fixed seed.
- [ ] `infra/withdrawer`: L2→L1 withdrawal flow: initiate on L2, prove against an
  output root/dispute game, finalize after the challenge window; journal so a restart
  resumes (port `withdrawer/src/*`). Sim/devnet test over the proof lane's contracts.
- [x] `bin/base balance-monitor`: wire `src/utilities/balance_monitor` into a
  subcommand with metrics + health endpoints (`src/infra/balance_monitor` exporter).
- [x] `infra/basectl` core: `sync-status`, `block`, `txpool`, `batcher`, `p2p`,
  `sequencer`, `conductor`, `proofs`, `upgrade-readiness`, `doctor` as plain-text CLI
  commands over the node/consensus/batcher RPCs (port `basectl/src/{commands,rpc}`).
  TUI is out of scope until the CLI commands are complete.
- [x] `infra/audit`: transaction-event audit archiver (port `audit-archiver`): Vector
  NDJSON ingest, `base_getTransactionEvents*` JSON-RPC, metrics + health, `base audit`.
- [x] `infra/snapshotter`: datadir snapshot create/restore for the node (port
  `snapshotter/src/*`), coordinate with trie-db for a consistent DB checkpoint.
- [x] Devnet smoke: load-test step added to `just devnet smoke` (websocket-proxy dropped by
  rule 10).
- [ ] Devnet smoke: withdrawer step once the devnet deploys a proving portal (the stand-in
  portal in `batcher/devnet/portal.zig` only emits deposits).
- [x] `infra/sidecrush`: block-production health sidecar (port `sidecrush`): poll the EL
  head, flag stalls and slow blocks against the 200 ms cadence, metrics + health endpoints,
  `base sidecrush`. SimIo tests for stall, recovery, and RPC failure.
- [x] `infra/load_test` key stream + chain prep: derive N sender keys from a seed, fund them
  in batches from a funder account through the tx manager, deploy workload contracts
  (ERC-20, storage, looper) from hand-assembled bytecode (port `workload/{key_stream,
  chain_prep,accounts}.rs`). Lets the devnet load test exceed 10 dev accounts.
- [x] `infra/load_test` payloads: `storage`, `precompile`, `looper` (gas-heavy), and a real
  ERC-20 transfer against the deployed token (port `payloads/*`); `--json` report.
- [x] `infra/roxy` rate limits: per-client token buckets (bounded table, idlest evicted),
  client IPs through `utilities/trusted_proxy`, 429 + JSON-RPC -32016 like proxyd.
- [x] `infra/tx_manager` metrics core (`metrics.zig`): submitted, completed by outcome,
  bumps, pending, submit-to-completion latency histogram; `Completion.submitted_at_ms`.
- [ ] Export tx_manager metrics from `load-test` and `withdrawer` (`--metrics-port`), after
  their in-flight workers land.
- [x] `infra/fee_jobs` + `base fee-jobs disburse|process|sweep` (port `fee-jobs`): precondition
  reads, one tx_manager send, fail on revert (tx_manager now reports receipt status).
- [ ] `base fee-jobs confirm`: prove/finalize `FeeDisburser` withdrawals via the withdrawer
  (after `infra/withdrawer` lands).
- [ ] `infra/telemetry` EL reachability probe: needs RLPx (ECIES + devp2p Hello), which no
  lane has yet; revisit when execution p2p exists.
- [x] `infra/roxy` method routing (proxyd `rpc_method_mappings`): `--routes m=0|1;...` pins
  methods to upstreams (e.g. raw-tx sends to the sequencer); retries stay inside the route.
- [x] `infra/roxy` block-lag exclusion (proxyd `consensus_max_block_lag`): per-upstream
  `eth_blockNumber` polling; upstreams over `--lag-max-blocks` behind are skipped, fail open.

## Decisions
- tx_manager is sans-IO: `Manager` emits `fetch_nonce`/`publish`/`query_receipt` actions and
  consumes results; drivers (JSON-RPC, simulator) perform I/O. Keeps fee/retry/abort logic
  deterministic and simulator-friendly, and avoids pulling the batcher's sync RPC client.
- The batcher keeps its own `batcher/txmgr` (frame/blob specific). The infra manager is the
  general-purpose one; batcher-devnet may migrate later.
- Per-send published versions are a bounded ring (`hashes_max`); the oldest is forgotten
  only on a bump, which happens only while nothing is mined, so no mined version is lost.
- The driver reuses `batcher/rpc` (injected-transport JSON-RPC client) and `batcher/txdata`
  signing instead of duplicating them; binaries plug in `bin/base/http_transport.zig`.
- `balance-monitor` is a standalone tool (base/base only has the library layer): `/metrics`,
  `/`, `/healthz`, plus `/readyz` (503 once reads are older than N poll intervals). Flags use
  `utilities/cli` with `BASE_BALANCE_MONITOR_*` env fallback.
- tx_manager blob mode is part of the same `Driver` (`blobs_per_send_max > 0`), not a second
  driver: nonce, bump, and receipt logic stay shared. Commitments/proofs are computed once
  per send (`BlobStore`); bumps re-sign fees only. Blob candidates are plain carriers (no
  calldata, no value, gas 21000) because `batcher/txdata/blob.sign` builds that shape.
  Sidecar v1 (cell proofs) is the default, as L1 mempools require it since Osaka.
- snapshotter: zero dependencies, so no Docker socket and no S3. The tip check matches base/base
  (10 s freshness, skip and leave the node running); stop/start are operator shell commands
  (`--stop-cmd`/`--start-cmd`, start also runs after a failure); the store is a directory.
  needlefish has one `node.db`, so it is split into fixed-size chunks stored by BLAKE3
  content address (reuse without comparing against the previous manifest); no compression
  yet. Restore verifies every chunk and renames a temp file into place. A consistent copy
  needs the node stopped; an online engine checkpoint export (trie-db) is future work.
- sidecrush polls `latest` over HTTP (one poll per 200 ms slot by default) and measures age
  as local time since the head number advanced (base/base's `newHeads` semantics), because
  whole-second header timestamps cannot resolve 200 ms blocks. Thresholds keep base/base's
  defaults (2 s grace, 3 s unhealthy). The StatsD heartbeat becomes per-state Prometheus
  tick counters.
- fee-jobs takes its first nonce from `latest` (the shared driver's tag), not base/base's
  `pending`: overlapping runs on one key may replace rather than queue behind each other.
  The key is env-only (`BASE_FEE_JOBS_PRIVATE_KEY`), never a flag.
- roxy lag: one dedicated poll client per upstream (polls never queue behind requests); an
  unknown head never counts as lagging, and a route whose only upstreams lag still serves.
  No "latest" tag rewriting to the common head (proxyd consensus mode) yet.
- roxy routes: a batch whose methods share no upstream is rejected (-32600) rather than split
  across upstreams (proxyd splits); splitting needs response reassembly, left for later.
  A failing pinned upstream is never failed over outside its route.
- roxy rate limiting keys on the client IP only (no API keys yet); an evicted bucket refills
  to the full burst, so table pressure can only loosen limits, never block a client wrongly.
- load-test first slice: transfer/calldata/erc20-transfer payloads (erc20 targets a fixed
  address; deploying a token is future work), open-loop pacer with 2x catch-up, one
  tx_manager driver per sender, latency via reservoir sampling. Default senders are dev
  accounts 2,3,4,8,9 so the devnet's role accounts (0,1,5,6,7) keep their nonces.
- Deviation from base/base: "nonce too low" before any publish also resets the nonce cache
  so the next send refetches the chain nonce instead of failing the same way.
- roxy (base/base ships only the scaffold): the http server gained deferred responses
  (`defer_response`/`resume_deferred`, 504 on `io_timeout_ns`, 503 on stop) so a handler can
  wait on an upstream without blocking. Per upstream a fixed pool of http clients, one request
  each; a bounded pending set (full: 503 at once, no queueing beyond it).
- roxy retries transport errors and 5xx on a different upstream (at most `--retries` + 1
  sends, never the same upstream twice), including non-idempotent methods, like ProxyD; with
  no upstream left the last 5xx is forwarded as-is, a transport failure becomes 502 + -32603.
- roxy passive health: `failures_to_eject` consecutive failures eject for a backoff doubling
  per ejection in a row (capped); re-admitted on probation (one failure re-ejects). All
  ejected: fail open to the earliest-returning one; a success there re-admits at once.
  No active `eth_chainId` probe yet (the fail-open traffic acts as the probe).
- roxy allowlist: methods are matched after JSON unescaping and with ASCII-case-insensitive
  `method`/`id` keys (geth's encoding/json accepts `"Method"`); duplicate `method` keys are
  invalid. A batch with any disallowed entry is rejected whole: every entry gets -32601
  (allowed entries say why). Parse errors get -32700, bad shapes -32600, batches over 100
  -32600. Without an allowlist bodies are forwarded unparsed.
- roxy flags: `BASE_ROXY_*` env prefix (base/base uses `ROXY_LISTEN_ADDR`); upstreams are
  `http://IPv4:PORT` only (no DNS, no TLS), matching the other `bin/base` tools.
- basectl: each command is fetch (through `batcher/rpc`, so tests use a fake transport) ->
  fixed-size report (owned `Text`/`List`, no allocation) -> text or `--json` render. Read-only
  commands only; base/base's mutating actions (batcher start/stop, peer add/ban, txpool clear,
  conductor transfer/pause, sequencer start/stop, prover propose/submit) are not ported.
- basectl takes endpoints from flags (`--l1-rpc`, `--l2-rpc`, `--rollup-rpc`, `--batcher-rpc`,
  `--conductor-rpc`, env `BASE_BASECTL_*`) defaulting to the devnet ports, instead of
  base/base's named chain configs; an empty URL disables an endpoint.
- basectl conductor/sequencer read one node (the given conductor + rollup RPC) rather than
  discovering the cluster; the raft membership is still listed from
  `conductor_clusterMembership`.
- basectl reads that get JSON-RPC -32601 render "unavailable (method not served)" and never
  fail a command on their own. Not served by needlefish yet: `admin_nodeInfo` (EL identity
  in `p2p`) and every `conductor_*` method (no conductor server). `txpool` falls back from
  `txpool_status` to counting `txpool_content`.
- basectl proofs lists dispute games from the L1 `DisputeGameFactory` (`--factory`, eth_call
  `gameCount`/`gameAtIndex`/`status`/`l2BlockNumber`/`rootClaim`); prover-service views are
  out of scope.
- basectl doctor checks: endpoint reachability, L1/L2 chain ids vs `optimism_rollupConfig`,
  L1/L2/unsafe heads advancing over two samples (`--sample-interval-ms`), safe and finalized
  lag (base/base 150/300 safe defaults; finalized 2000/7200 is ours), CL/EL peers (warn below
  5, fail below `--peer-fail-below`, default 1 as base/base's fail-at-zero), batcher stopped,
  and sequencer active vs conductor leadership. base/base's public-tip, bootnode, reth.toml,
  and external reachability checks need config/services we do not have and are omitted.
- audit: base/base's Postgres + S3 archive becomes a bounded in-memory store
  (`src/infra/audit/store.zig`): a slot ring plus a byte arena, sized at startup
  (`--events-max`, `--store-bytes-max`), oldest events evicted first, chained hash indexes
  for event id, tx hash, block number/hash, bundle id/hash, and the rejected list. Optional
  durability is one append-only CRC-checked segment file (`--data-dir`): each accepted batch
  is written and fsynced before the response (a failed write answers 503 and stores
  nothing), replayed at startup (a torn or corrupt tail is truncated), and compacted to the
  live events once it passes `--segment-bytes-max`.
- audit retention keeps base/base's hot/warm/cold classes by event type (defaults 3/7/30
  days, `hot <= warm <= cold <= 90`): events older than their class window are rejected at
  ingest, hidden from queries, and pruned from the store head. Events more than 1 h in the
  future are rejected. Query results are oldest first, limit default 500, max 2000; the
  rejected query is newest first.
- audit drops the `BUILDER_FLASHBLOCK_*` event types (rule 10): they are rejected per item
  with reason `flashblock event types are not supported`.
- audit bounds `event_id` to 256 bytes and only indexes bundle ids/hashes up to 256 bytes;
  base/base leaves them unbounded. The retired write RPCs answer -32601.
- load-test key stream: key i of seed s is keccak256("needlefish/load-test/key-stream/v1" || s ||
  i || attempt) as a secp256k1 scalar (reject zero/>= n, next attempt). Random access, unlike
  base/base's seeded `StdRng` stream; `--senders N` uses `--seed` for both keys and payloads.
- load-test contracts are hand-assembled (a tiny comptime assembler with labels) instead of
  base/base's solc artifacts: a minimal ERC-20 (transfer/balanceOf, open `mint` faucet, balance
  at slot = address, `Transfer` logs), a storage writer (`[first_slot, count, value]`, no
  selector), and a looper (`[iterations]`, 40 gas each). Deployed with CREATE from the funder
  (base/base uses CREATE2 via a deployer); addresses come from `create_address(funder,
  completion.nonce)` and are checked with `eth_getCode` against the expected runtime.
- load-test prep: deploy (only when the mix needs contracts) -> verify code -> fund
  (`--fund-wei`, key-stream senders only) and mint to each sender, one funder driver with a
  sliding window of 16 unconfirmed txs. Senders are funded every run (no balance check, unlike
  base/base). Any failed or reverted prep tx, or a 300 s timeout, fails the run without load.
- load-test payloads: `precompile` calls ecrecover (a real signature by a seed-derived key),
  sha256, identity, and modexp directly from the EOA (base/base can route through a looper
  contract); `storage` writes fresh slots from a random 64-bit start. Gas limits are the
  EIP-7623 calldata floor plus the exact execution cost (asserted against needlefish's EVM);
  modexp uses a fixed 10000 bound. `erc20_transfer` now requires the deployed token (the
  fixed-address placeholder is gone). `--json` prints one JSON line on stdout.
- tx_manager `Candidate.to` and `txdata.Request.to` are optional: null sends a contract
  creation (estimateGas omits `to`; blob candidates must have a recipient).
- load-test senders_max is 64 (each sender owns a driver: about 140 KB of buffers).

## Log
- 2026-11-05: tx_manager core (fees, error classification, nonce tracker, send state,
  sans-IO manager) with unit tests, seeded + std.testing fuzz, and a faulty-L1 sim.
- 2026-11-05: tx_manager JSON-RPC driver (sign, publish, canonical receipts, gas estimate)
  with fake-L1 tests for ordering, drop + bump, reorged receipts, and rejections.
- 2026-11-05: `base balance-monitor` (exporter + sim tests); smoke-tested against
  `base node --dev-l1` (needs a fresh `devnet init --force` genesis; a stale genesis
  timestamp makes the dev miner fail every block, as `etc/devnet/devnet.sh` notes).
- 2026-11-05: load_test (pacer, workload, metrics, runner + fake-chain sim) and
  `base load-test`; against `base node --dev-l1` (1 s blocks, 5 tx/s): 49/49 confirmed,
  p50 1085 ms.
- 2026-11-05: `infra/roxy` + `base roxy`: deferred http responses, allowlist, method
  extractor, upstream pool (all fuzzed), proxy with retries/ejection; SimIo tests with 3 fake
  upstreams; smoke-tested against a local HTTP upstream (incl. a 200 KB response).
- 2026-11-05: tx_manager blob mode (EIP-4844 sidecars v0/v1, `eth_blobBaseFee`, blob fee
  bumps) with fake-L1 tests that decode the network form.
- 2026-11-05: snapshotter (manifest codec + fuzz, tip check) and `base snapshotter
  create|restore|verify`; smoke: 100 MB node.db round-trips byte-identical, re-create reuses
  all chunks, a corrupted chunk fails verify, a stale node is skipped.
- 2026-11-05: basectl core and `base basectl` (sync-status, block, txpool, batcher, p2p,
  sequencer, conductor, proofs, upgrade-readiness, doctor) with canned-response tests,
  seeded + std.testing fuzz of every decoder, and doctor pass/warn/fail tests; smoke-tested
  against a running devnet (doctor caught a stopped L1 and a 1148-block safe lag).
- 2026-11-05: smoke step 5 (`base load-test` 20 tx/s for 5 s from dev accounts 2-4 against the
  sequencer); full `just devnet smoke` passes, 99/99 confirmed, p50 690 ms. load-test gains
  `--receipt-poll-ms` (default 200, matching 200 ms L2 blocks).
- 2026-11-05: sidecrush (`HeadState` classifier + fuzz, `Checker(IO)` with metrics/readiness,
  SimIo tests at 200 ms slots) and `base sidecrush`; on the devnet: healthy/200, then error/503
  after the sequencer EL was killed.
- 2026-11-05: roxy per-client rate limits (`rate_limit.zig` + fuzz, trusted-proxy client IPs,
  SimIo test) and `--rate-limit-rps/--rate-limit-burst/--trusted-proxies`; live: 429 on the
  third request with burst 2.
- 2026-11-05: tx_manager `Metrics` (caller-driven, registry entries `tx_manager_*`).
- 2026-11-05: fee-jobs disburse/process/sweep; live on dev-l1: sweep confirmed at depth 2,
  process skipped on a 0 balance, missing key exits 2.
- 2026-11-05: roxy method routing (`routes.zig` + fuzz, SimIo test, `--routes`); live: pinned
  method served by its upstream, a dead pinned upstream returns 502 without failover.
- 2026-11-05: roxy block-lag exclusion (SimIo test, `--lag-max-blocks/--lag-poll-ms`,
  `roxy_upstream_head`); live: two dev-l1 nodes, all traffic to the leading one.
- 2026-11-05: `base audit` archiver: Vector NDJSON ingest (idempotent by event_id), the five
  `base_getTransactionEvents*`/`getRejected*` queries, metrics/health, segment durability;
  live: duplicate batch answered `duplicate`, restart replayed events, torn tail truncated.
- 2026-11-05: load-test key stream, chain prep (deploy + verify + fund + mint through the tx
  manager), hand-assembled ERC-20/storage/looper contracts executed in the EVM in tests,
  `storage`/`precompile`/`looper`/real `erc20_transfer` payloads, `--senders`, `--json`;
  tx_manager contract creation. Devnet: smoke passes (step 5 now deploys and runs the contract
  mix, 99/99, 0 reverted); `--senders 50` at 100 tx/s for 20 s with all six payloads: 50
  funded + 50 minted, 1996/1996 confirmed, 0 reverted, p50 399 ms, p99 669 ms.
