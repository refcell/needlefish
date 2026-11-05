# Lane: infra-tools

Owns `src/infra/*` (submodules `websocket_proxy`, `roxy`, `load_test`, `withdrawer`,
`basectl`, `audit`, `snapshotter`, `tx_manager`) and the matching `bin/base`
subcommands (`basectl`, `websocket-proxy`, `roxy`, `load-test`, `withdrawer`,
`balance-monitor`). Reference: base/base `crates/infra/{basectl,websocket-proxy,roxy,
load-tests,withdrawer,audit,snapshotter,telemetry}` and `crates/utilities/{tx-manager,
balance-monitor,health,optimism-rpc}`. Out of scope for now: `zk-*`, `snark-e2e`,
`challenger-e2e`, `fee-jobs`, `sidecrush`, `shadow-metrics` (add later if valuable).

Reuse, do not duplicate: HTTP/WS/JSON-RPC/metrics/health/retry/balance_monitor from
`src/utilities`, tx types and signing from `src/common`, flashblocks types from
`src/common/flashblocks`. Small additive edits in those modules are fine (a `pub`, a
hook); larger changes go through the owning lane. All IO through `src/utilities/io` so
every tool runs in the simulator. Bounded queues, static allocation after startup.

## Backlog
- [x] `infra/tx_manager` core: nonce tracking, fee bumping (EIP-1559 + blob fee), resubmit on
  timeout, receipt confirmation depth, bounded pending set (port
  `utilities/tx-manager`). Sim tests with a fake L1 that drops/reorders txs; fuzz the
  fee-bump state machine. Coordinate with batcher-devnet: it may switch to this later.
- [x] `infra/tx_manager` driver: JSON-RPC driver over the sans-IO core (fee suggestion,
  local EIP-1559 signing, `eth_sendRawTransaction`, receipt + canonical-block check, gas
  estimation). The devnet exercise is part of `load-test` below.
- [ ] `infra/tx_manager` blob driver: EIP-4844 sends with sidecars (reuse `batcher/blobs`).
- [ ] `infra/websocket_proxy`: fan out an upstream flashblocks websocket to many
  subscribers with per-IP/API-key rate limits, auth by key, method/filter support,
  bounded per-client send queues that drop slow clients (port `websocket-proxy/src/*`).
  Sim test: 1 upstream, N clients, one slow client is dropped, others see every message
  in order. Fuzz the filter/auth parsers.
- [ ] `infra/roxy`: HTTP JSON-RPC server scaffold with health endpoint, then a
  load-balancing RPC proxy over N upstreams with health checks, retry, and method
  allowlist (port `roxy`, extend toward base/base's intent). Sim test with a failing
  upstream.
- [ ] `infra/load_test`: seeded workload generator (funded dev accounts from the
  public test-junk mnemonic, transfer/ERC-20/calldata payload mixes, key stream),
  open-loop rate runner, latency/inclusion metrics, report (port `load-tests/src/*`).
  `bin/base load-test` against the devnet; deterministic in sim with a fixed seed.
- [ ] `infra/withdrawer`: L2→L1 withdrawal flow: initiate on L2, prove against an
  output root/dispute game, finalize after the challenge window; journal so a restart
  resumes (port `withdrawer/src/*`). Sim/devnet test over the proof lane's contracts.
- [ ] `bin/base balance-monitor`: wire `src/utilities/balance_monitor` into a
  subcommand with metrics + health endpoints.
- [ ] `infra/basectl` core: `sync-status`, `block`, `txpool`, `batcher`, `p2p`,
  `sequencer`, `conductor`, `proofs`, `upgrade-readiness`, `doctor` as plain-text CLI
  commands over the node/consensus/batcher RPCs (port `basectl/src/{commands,rpc}`).
  TUI is out of scope until the CLI commands are complete.
- [ ] `infra/audit`: transaction-event audit stream (port `audit/src/*`) over the node's
  RPC, metrics exported.
- [ ] `infra/snapshotter`: datadir snapshot create/restore for the node (port
  `snapshotter/src/*`), coordinate with trie-db for a consistent DB checkpoint.
- [ ] Devnet smoke: add load-test + websocket-proxy + withdrawer steps to
  `just devnet smoke` (coordinate with batcher-devnet, who owns `etc/devnet`).

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
- Deviation from base/base: "nonce too low" before any publish also resets the nonce cache
  so the next send refetches the chain nonce instead of failing the same way.

## Log
- 2026-11-05: tx_manager core (fees, error classification, nonce tracker, send state,
  sans-IO manager) with unit tests, seeded + std.testing fuzz, and a faulty-L1 sim.
- 2026-11-05: tx_manager JSON-RPC driver (sign, publish, canonical receipts, gas estimate)
  with fake-L1 tests for ordering, drop + bump, reorged receipts, and rejections.
