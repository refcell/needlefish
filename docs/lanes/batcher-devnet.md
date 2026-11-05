# Lane: batcher-devnet

Owns `src/batcher/*`, `bin/batcher`, `etc/devnet/`, `docs/DEVNET.md`, and the
`just devnet` recipes. Goal: **`just devnet up` brings up a working all-Zig devnet.**

## Backlog
- [x] `docs/DEVNET.md`: topology, ports, process contract (see draft below), smoke test definition.
- [x] `base devnet init` (first cut: funded accounts, portal stub, rollup.json; genesis hashes
  patched by `base devnet rollup` after ELs start; predeploys still TODO)
- [ ] devnet genesis: predeploys (L1Block, GasPriceOracle, fee vaults, proxies) from public
  allocs; compute genesis hashes in-process once trie lands.
- [ ] (orig) `base devnet init` (in `bin/base`, may live in `src/batcher/devnet` or `etc`): generate L1 + L2 genesis, rollup config, JWT secret into `.devnet/` (git-ignored), fund the public dev mnemonic accounts, predeploys (L1Block, GasPriceOracle, fee vaults...) using public bytecode/allocs from base/base, a minimal L1 portal (deposit event emitter) and system config.
- [x] `batcher/frame`: frame encode/decode, tx data parse (fuzzed).
- [x] `batcher/blobs`: EIP-4844 blob codec (fuzzed).
- [x] `batcher/comp`: zlib (std flate) channel compressor; stored-block brotli encoder.
- [ ] `batcher/comp`: real brotli compressor (LZ77 + prefix codes), checked with `brotli -d`.
- [ ] `batcher/batch`: singular batch RLP, span batch encoding.
- [x] `batcher/channel`: channel out (ratio estimate, compress on close, frames).
- [x] `batcher/channel`: channel manager (double-buffered channels, backpressure, reorg detect,
  duration close); batches decode back via consensus SingleBatch.
- [x] `batcher/txdata`: EIP-1559 calldata tx building + signing, gas, fee bumps.
- [ ] `batcher/txdata`: EIP-4844 blob txs (KZG commitments/proofs, sidecar network form).
- [x] `batcher/txmgr`: nonce tracking, send, receipt polling, resubmission with bumps.
- [x] `batcher/source`: L2 block JSON -> raw txs (legacy/2930/1559, hash-checked) + L1 origin.
- [ ] `batcher/source`: EIP-7702 (type 4) transactions.
- [x] `batcher/service` + `base batcher`: step loop (heads, load, frames, txmgr), calldata DA.
- [x] `batcher/service`: safe-head stall watchdog (resubmit from safe+1; covers timed-out channels).
- [ ] `base batcher`: metrics endpoint, blob DA.
- [ ] `batcher`: L2 block source (RPC), channel builder, frame encoding, compression (zlib/brotli own impl or std), span batches, calldata + blob (EIP-4844) submission via tx manager (nonce, fee bumping, resubmission), throttling.
- [x] `etc/devnet/devnet.just`: `up`, `down`, `status`, `logs`, `smoke`, `reset` — native processes (no Docker required), pids/logs under `.devnet/`; skips components not built yet.
- [x] Smoke script `etc/devnet/smoke.sh` (needs `base devnet transfer`).
- [x] `base devnet transfer`: sign + send EIP-1559 tx (used by smoke for L2 tx and L1 deposit).
- [x] `batcher/rpc`: JSON-RPC client over an injected transport (HTTP in bin, canned in tests).
- [ ] Smoke test passing: L2 tx included by sequencer, batch posted to L1, verifier derives the same safe head; L1 deposit appears on L2.
- [ ] Optional Docker compose mirroring base/base's `etc/docker` using our binaries.

## Draft devnet contract
- L1: `node --dev-l1` (auto-mine, 2s blocks?), HTTP :8545, beacon API :5052.
- L2 sequencer: `node` HTTP :9545, engine :9551; `consensus --sequencer` RPC :7545.
- Batcher: `batcher` → posts to batch inbox on L1, metrics :7300.
- L2 verifier: `node` HTTP :10545, engine :10551; `consensus` RPC :8547 (derives from L1 only).

## Decisions
- 2026-11-05: batcher carries a minimal JSON-RPC client (`batcher/rpc`) behind a
  `Transport` interface until `utilities/rpc` lands; binaries use std.http.Client.
- 2026-11-05: no L1 deployment step. A hand-assembled portal stub at 0x..de90 emits
  `TransactionDeposited` (receive()-style deposit to msg.sender); system config has no code.
- 2026-11-05: L2 activates every OP upgrade through Jovian at genesis; Base-only upgrades
  (azul+) stay off until node/consensus support them. L2 genesis extraData is Jovian format.
- 2026-11-05: ChannelOut uses a ratio size estimate and compresses once on close
  (deterministic, no shadow compressor); misestimates only change the frame count.
- 2026-11-05: singular/span batch types are the consensus lane's (base/base keeps them
  in `base-protocol`); the batcher adds encoders there or locally once they land.
- 2026-11-05: devnet chain ids L1 900 / L2 901, batch inbox `0xff00..0901`, batcher =
  dev mnemonic index 6, sequencer = index 5 (matches base/base devnet-env roles).
- 2026-11-05: default channel compression is zlib via std.compress.flate (still valid
  after Fjord, decoder in std for the consensus lane); brotli (version byte 0x01) follows.

## Decisions addendum

- 2026-11-05: Channel timeouts are handled by a safe-head stall watchdog: if the rollup node's
  safe head does not advance for 30 L1 blocks while the batcher holds later blocks, it drops its
  channels and reloads from safe+1. Simpler than op-batcher's per-channel inclusion tracking and
  also recovers from dropped txs and rollup-node restarts; duplicate batches are dropped by
  derivation.

## Log
- 2026-11-05: DEVNET.md contract; batcher frame + blob codecs with fuzz tests.
- 2026-11-05: batcher/frame reuses consensus Frame; comp: zlib + stored brotli (verified
  against the brotli CLI).
- 2026-11-05: ChannelOut with fuzzed reassembly through the consensus Channel.
- 2026-11-05: dev accounts (BIP39/32), portal stub, genesis/rollup writers, `base devnet init`.
- 2026-11-05: devnet.sh supervisor (bash 3.2 compatible) + smoke.sh.
- 2026-11-05: rpc client, `base devnet transfer`; signing + portal deposit log verified
  against a local dev node; portal log decodes with consensus `decode_deposit_log`.
- 2026-11-05: L2 block source decoding with hash check and mutation fuzz.
- 2026-11-05: channel manager emitting singular batches; round trip through consensus decode.
- 2026-11-05: txmgr (nonce slots, same-nonce fee-bump resubmission) and batcher service step
  loop; end-to-end test decodes the L1 txs back into the L2 blocks' batches.
- 2026-11-05: `base batcher` binary (calldata DA). Live: 20 fake L2 blocks -> 1 batch tx mined on
  anvil L1. Blobs DA rejected with a clear error until EIP-4844 signing lands.
- 2026-11-05: safe-head stall watchdog instead of per-channel inclusion tracking (decision below).
