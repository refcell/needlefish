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
- [ ] `infra/tx_manager`: nonce tracking, fee bumping (EIP-1559 + blob fee), resubmit on
  timeout, receipt confirmation depth, bounded pending set (port
  `utilities/tx-manager`). Sim tests with a fake L1 that drops/reorders txs; fuzz the
  fee-bump state machine. Coordinate with batcher-devnet: it may switch to this later.
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

## Log
