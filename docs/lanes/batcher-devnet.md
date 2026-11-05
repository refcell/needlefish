# Lane: batcher-devnet

Owns `src/batcher/*`, `bin/batcher`, `etc/devnet/`, `docs/DEVNET.md`, and the
`just devnet` recipes. Goal: **`just devnet up` brings up a working all-Zig devnet.**

## Backlog
- [ ] `docs/DEVNET.md`: topology, ports, process contract (see draft below), smoke test definition.
- [ ] `base devnet init` (in `bin/base`, may live in `src/batcher/devnet` or `etc`): generate L1 + L2 genesis, rollup config, JWT secret into `.devnet/` (git-ignored), fund the public dev mnemonic accounts, predeploys (L1Block, GasPriceOracle, fee vaults...) using public bytecode/allocs from base/base, a minimal L1 portal (deposit event emitter) and system config.
- [ ] `batcher`: L2 block source (RPC), channel builder, frame encoding, compression (zlib/brotli own impl or std), span batches, calldata + blob (EIP-4844) submission via tx manager (nonce, fee bumping, resubmission), throttling.
- [ ] `etc/devnet/devnet.just`: `up`, `down`, `status`, `logs`, `smoke`, `reset` — native processes (no Docker required), pids/logs under `.devnet/`.
- [ ] Smoke test: L2 tx included by sequencer, batch posted to L1, verifier derives the same safe head; L1 deposit appears on L2.
- [ ] Optional Docker compose mirroring base/base's `etc/docker` using our binaries.

## Draft devnet contract
- L1: `node --dev-l1` (auto-mine, 2s blocks?), HTTP :8545, beacon API :5052.
- L2 sequencer: `node` HTTP :9545, engine :9551; `consensus --sequencer` RPC :7545.
- Batcher: `batcher` → posts to batch inbox on L1, metrics :7300.
- L2 verifier: `node` HTTP :10545, engine :10551; `consensus` RPC :8547 (derives from L1 only).

## Decisions

## Log
