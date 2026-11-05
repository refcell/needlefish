# Lane: batcher-devnet

Owns `src/batcher/*`, `bin/batcher`, `etc/devnet/`, `docs/DEVNET.md`, and the
`just devnet` recipes. Goal: **`just devnet up` brings up a working all-Zig devnet.**

## Backlog
- [ ] (from crypto lane) Osaka blob txs carry EIP-7594 cell proofs (sidecar version 1):
  use `common.crypto.kzg.cells.compute_cells_and_kzg_proofs` with `Settings.init` and
  `settings.attach_prover_tables(&tables)` (one static ~25 MiB `fk20.Tables`): 93 ms per blob
  instead of 202 ms; proofs are identical with or without tables.
- [x] (from crypto lane, done: `blobs/kzg.zig` now wraps it) `common.crypto.kzg.blob` now provides `blob_to_kzg_commitment`,
  `compute_blob_kzg_proof`, `verify_blob_kzg_proof[_batch]` (c-kzg vector tested); consider
  replacing `src/batcher/blobs/kzg.zig` with it. EIP-7594 cell proofs are on main too:
  `crypto.kzg.cells.compute_cells_and_kzg_proofs` (189 ms/blob; `Settings.init` builds FK20
  tables once, 0.83 s).
- [x] `docs/DEVNET.md`: topology, ports, process contract (see draft below), smoke test definition.
- [x] `base devnet init` (first cut: funded accounts, portal stub, rollup.json; genesis hashes
  patched by `base devnet rollup` after ELs start; predeploys still TODO)
- [x] devnet genesis: genesis hashes computed in-process (common/genesis state root + header);
  `base devnet init` writes a correct rollup.json up front (devnet.sh still re-patches from ELs).
- [~] devnet genesis: predeploys skipped for now (decision 2026-11-05: base-ref only ships mainnet/
  sepolia genesis whose L1Block predates Ecotone and cannot take Jovian L1-info calls; without code
  the L1-info system call is a no-op and L1 fees are zero, fine for the devnet).
- [x] (orig, superseded by the items above) `base devnet init` (in `bin/base`, may live in `src/batcher/devnet` or `etc`): generate L1 + L2 genesis, rollup config, JWT secret into `.devnet/` (git-ignored), fund the public dev mnemonic accounts, predeploys (L1Block, GasPriceOracle, fee vaults...) using public bytecode/allocs from base/base, a minimal L1 portal (deposit event emitter) and system config.
- [x] `batcher/frame`: frame encode/decode, tx data parse (fuzzed).
- [x] `batcher/blobs`: EIP-4844 blob codec (fuzzed).
- [x] `batcher/comp`: zlib (std flate) channel compressor; stored-block brotli encoder.
- [x] `batcher/comp`: brotli encoder (greedy LZ77, one compressed meta-block, Huffman codes;
  stored fallback when incompressible). `base batcher` defaults to brotli like base/base;
  `--compression zlib` remains. Verified with the reference `brotli -d` and live on anvil.
- [x] `batcher/batch`: singular batches (channel manager). Span batch encoding skipped: Base's
  Denim upgrade makes derivation singular-only (see consensus span_batch.zig).
- [x] `base devnet batches`: L1 batch inspector (channels -> batches via derivation code); smoke
  check 2 now requires a decoded batch for the transfer's L2 block.
- [x] `batcher/channel`: channel out (ratio estimate, compress on close, frames).
- [x] `batcher/channel`: channel manager (double-buffered channels, backpressure, reorg detect,
  duration close); batches decode back via consensus SingleBatch.
- [x] `batcher/txdata`: EIP-1559 calldata tx building + signing, gas, fee bumps.
- [x] `batcher/blobs/kzg`: KZG prover (blob commitment + blob proof), verified by the pairing check.
- [x] `batcher/txdata`: EIP-4844 blob txs (sign, sidecar network form, blob fees); txmgr blob mode;
  `base batcher --data-availability blobs` (one frame per blob, one blob per tx).
- [x] `batcher`: multiple blobs per tx (up to 6 frames per tx, `FrameSource` pull; nonce and
  fees read before frames are pulled so RPC errors never drop frames).
- [x] `batcher/txmgr`: nonce tracking, send, receipt polling, resubmission with bumps.
- [x] `batcher/source`: L2 block JSON -> raw txs (legacy/2930/1559, hash-checked) + L1 origin.
- [x] `batcher/source`: EIP-7702 (type 4) transactions.
- [x] `batcher/service` + `base batcher`: step loop (heads, load, frames, txmgr), calldata DA.
- [x] `batcher/service`: safe-head stall watchdog (resubmit from safe+1; covers timed-out channels).
- [x] `base batcher`: metrics endpoint (`batcher/metrics`, utilities http server + metrics
  registry; served while waiting between steps; bind failure only disables metrics).
- [x] `batcher`: L2 block source (RPC), channel builder, frame encoding, compression (zlib/brotli own impl or std), span batches (skipped, see above), calldata + blob (EIP-4844) submission via tx manager (nonce, fee bumping, resubmission), throttling (`batcher/throttle`).
- [x] `etc/devnet/devnet.just`: `up`, `down`, `status`, `logs`, `smoke`, `reset` — native processes (no Docker required), pids/logs under `.devnet/`; skips components not built yet.
- [x] Smoke script `etc/devnet/smoke.sh` (needs `base devnet transfer`).
- [x] `base devnet transfer`: sign + send EIP-1559 tx (used by smoke for L2 tx and L1 deposit).
- [x] `batcher/rpc`: JSON-RPC client over an injected transport (HTTP in bin, canned in tests).
- [x] Smoke test passing: L2 tx included by sequencer, batch posted to L1, verifier derives the same safe head; L1 deposit appears on L2.
- [ ] Optional Docker compose mirroring base/base's `etc/docker` using our binaries.
- [x] `batcher/admin`: base/base admin JSON-RPC (start/stop/flush/status/throttle info) and
  `--stopped`, `--admin-port`, `--admin-addr`; one event loop serves admin + metrics.
- [x] `batcher`: `--num-confirmations` (free a slot only N blocks after inclusion), `--min-tip-cap`,
  `--min-basefee`, `--max-pending-transactions` (base/base txmgr flags).
- [x] `batcher`: `--sub-safety-margin`: close channels before `max_channel_duration` would let
  the channel time out on L1 (base/base `sub_safety_margin`).
- [x] `batcher`: `admin_setThrottleController` (replace strategy/config at runtime).
- [x] `batcher`: `--sequencer-urls`: pick the active sequencer among several L2/rollup endpoints
  (base/base `sequencers.rs`).
- [x] `batcher`: startup recent-tx check (`--check-recent-txs-depth`): skip resubmitting data
  already on L1 after a restart (base/base `recent_txs.rs`).
- [x] `batcher`: `--wait-node-sync` (wait until the rollup node's L1 head catches up).
- [x] DST: a sim scenario driving admin stop/start/flush on the real batcher.
- [x] `batcher`: base/base flag names as aliases (`--l1-rpc-url`, `--poll-interval` seconds,
  `--data-availability-type`, `--resubmission-timeout`, `--max-blobs-per-tx`,
  `--max-calldata-size-bytes`).
- [x] `batcher`: `--network-timeout` (needs a request timeout in the HTTP transport).
- [x] `batcher`: `--compressed-size-target` (close the channel once compressed output passes
  the target, keeping the batch that reached it).
- [x] `batcher`: throttle threshold/limit flags (`--throttle-{start,full}-threshold`,
  `--throttle-{block,tx}-size-{upper,lower}-limit`).
- [x] `batcher`: `--brotli-quality` (encoder effort levels; lazy matching at high quality).
- [x] `batcher`: force blobs while throttling (`--no-force-blobs-when-throttling` opts out).
- [x] `batcher`: `--publish-max-retries` / `--publish-retry-delay` for send failures.
- [x] `batcher`: shadow mode (`--shadow.*`): post to a shadow inbox and compare a parity
  validator's derived hashes with the leader's.
- [x] `batcher`: batcher balance metric (base/base `BalanceMonitorLayer`).

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

- 2026-11-05: Push procedure: after a green `zig build test` + tidy, if main moved and the new
  upstream commits touch none of our files (nor build.zig / src/base.zig), rebase and push without
  a second full test run. Main moves faster than one test run, so strict re-testing never lands.

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
- 2026-11-05: in-process genesis hashes for rollup.json (anvil is no reference: it skips the
  genesis state root).
- 2026-11-05: block source handles EIP-7702 txs (authorization list rebuilt, hash-checked).
- 2026-11-05: KZG prover for blobs; setup Lagrange points permuted to bit-reversed order like
  c-kzg's loader (the file is in natural order).
- 2026-11-05: blob DA end to end; anvil (c-kzg) accepted and mined our type-3 tx with sidecar.
- 2026-11-05: `base devnet batches` inspector; live: 20 batches decoded from an anvil L1.
- 2026-11-05: multi-blob transactions (default 6 per tx in blob mode).
- 2026-11-05: brotli compressor; text compresses to ~31% (reference q5: ~23%).
- 2026-11-05: batcher Prometheus metrics on `--metrics.port`; verified with curl live.
- 2026-11-05: batcher KZG prover now wraps `common.crypto.kzg.blob`; anvil (c-kzg) accepts.
- 2026-11-05: DA throttling (`miner_setMaxDASize`, base/base controller math in integer ppm).
  Decision: a builder answering method-not-found disables throttling with a log line instead
  of exiting (base/base bails unless `--no-throttle`), so the devnet runs before the EL lane
  serves the miner API. Backlog = (unsafe - safe) x EMA of per-block FastLZ DA estimates.
- 2026-11-05: txmgr liveness fix (dst-fuzz finding): a nonce gap (no slot holds `latest`
  while later slots wait) that outlives `resubmit_after_ms` makes the service reset channels and
  txmgr; the stall watchdog resets txmgr too. After a reset the nonce comes from `latest` and
  dropped nonces are refilled with fees bumped over the dropped txs (replace pooled copies).
  Frames are requeued by reloading blocks from safe + 1.
- 2026-11-05: txmgr takes its first nonce from `latest` (was `pending`), like base/base: a
  restarted batcher replaces untracked pooled txs instead of adopting them (an adopted tx that
  L1 evicts left a gap nothing re-sent). An underpriced same-nonce send bumps and resends on
  the next poll. Test: restart with pooled txs, then eviction (mutation-checked).
- 2026-11-05: batcher admin API; backlog extended with remaining base/base batcher features.
- 2026-11-05: txmgr confirmations (no resubmission of mined-but-unconfirmed txs), min tip /
  base fee floors, `--max-pending-transactions` (default stays 8, base/base uses 1).
- 2026-11-05: admin_setThrottleController (missing fields keep current values; switching to
  off after a push keeps pushing the unthrottled limits).
- 2026-11-05: `--wait-node-sync`, `--check-recent-txs-depth` (binary search over the batcher
  nonce, base/base `recent_txs.rs`), `--wait-node-sync-timeout`.
- 2026-11-05: smoke repro: all 6 components start, L2 head stays 0 because `Node.tick` does not
  run the driver yet (consensus lane "service node stage 2"). Devnet side: cold `up` now writes
  a fresh genesis (stale genesis made dev L1 backfill hours); smoke step 0 fails fast on a stuck
  sequencer.
- 2026-11-05: `just devnet smoke` passes end to end (after consensus d2a7b30).
- 2026-11-05: `--sequencer-urls` (entries `URL` or `L2_URL=ROLLUP_URL`, because our EL and CL are
  separate processes); leader = first `admin_sequencerActive` true, kept when none is active;
  a new leader gets DA limits re-pushed. The devnet batcher uses it.
- 2026-11-05: sim: `admin_ops_per_minute` fault class (real batcher stop/start/flush during the
  fault phase; heal starts it), swarm-enabled with the real batcher; scenario test is
  mutation-checked (no start on heal -> liveness failure).

- 2026-11-05: smoke re-run on 77c9635: all checks pass. Live check: with
  `--sequencer-urls verifier,sequencer` the batcher picks #1 via `admin_sequencerActive` and
  batches; "no sequencer active" is now logged on change only.
- 2026-11-05: base/base flag aliases; flag parsing seeded-fuzzed against its invariants.
- 2026-11-05: smoke on 3dae167 (incl. consensus p2p + sealing 43a8665): all checks pass.
- 2026-11-05: force blobs while throttling (default on in calldata mode; KZG prover loaded only
  when it can apply). Pending txs keep their type (geth never replaces across blob/non-blob).
  Live: forced blob batches stalled the verifier with BlobsUnavailable because the dev L1
  beacon served only `blob_sidecars` while consensus requests `/eth/v1/beacon/blobs/{slot}`;
  added that endpoint (versioned-hash filter) to `execution/node/beacon.zig` as an
  integration fix. Verifier then derived from blobs (safe head 40).
- 2026-11-05: `--network-timeout S` (default 10, 0 disables): std.http.Client has no timeout,
  so HttpTransport races the fetch against a sleep with `std.Io.Select`, cancels a late fetch
  (fails as TransportFailed, retried next step) and replaces the client so no cancelled
  connection is reused. Without Io concurrency it falls back to no timeout. Smoke passes.
- 2026-11-05: `--compressed-size-target B`: replaces `target_frames` full frames as the
  channel's compressed target; met through the ratio estimate (we compress once at close),
  so a channel rejects the batch that would cross it instead of keeping it like base/base.
- 2026-11-05: `--brotli-quality 0-11` (default 9 like base/base). Quality buys match search:
  1/2/4/8/16-way hash buckets, lazy matching from 5, all covered positions inserted from 10.
  Text sample: q0 16599 B, q9 12248 B, q11 10262 B. Smoke and sim seed 42 pass.
- 2026-11-05: `--publish-max-retries N` (10) / `--publish-retry-delay D` (1s; `500ms`, `2s`,
  `1m`, bare seconds): "nonce too high" schedules a re-send of the same signed tx from
  `poll` (step machine, no sleeping); once exhausted the error surfaces and the slot falls
  back to normal resubmission. Previously such a tx waited a full resubmission period.
- 2026-11-05: devnet `up` started while another lane's devnet held :8545; our components
  died with AddressInUse, `up` still said "up" and `smoke` passed against the other devnet.
  `up` now refuses a cold start while any devnet port is taken and fails when a component
  exits during startup. Re-ran smoke on our own devnet (a2d588d): all checks pass.
- 2026-11-05: shadow mode (`--shadow.enabled`, `--shadow.inbox`,
  `--shadow.validator-rollup-rpc`, `--shadow.validator-l2-rpc`; all four or none, requires
  `--no-throttle`; the rollup config file's inbox must be the shadow inbox). Safe head from
  the validator, unsafe from the leader (`Clients.unsafe_from_l2`): reading both from the
  validator stalled, since it only learns blocks once batched. `batcher.parity.Monitor`
  compares derived block hashes (<= 25 per step, from validator safe + 1); logs a summary
  per 100 blocks and every mismatch. Live on the devnet: 101/101 blocks match.
- 2026-11-05: `base_batcher_balance_gwei` gauge (eth_getBalance every 12 s like base/base;
  gwei because our gauges are integers; a failed read keeps the last value). Live: 10^13
  gwei (the 10,000 ETH dev allocation). Smoke passes.
