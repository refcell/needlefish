# Lane: builder

Owns `src/builder/*`, the payload-building path of `src/execution/payload`, and the
`builder` subcommand of `bin/base`. Also owns removing flashblocks (see below).

## Direction (2026-11-05, from the project owner)

**No flashblocks.** needlefish uses a regular block builder that produces full blocks at
Base's **native 200 ms subsecond cadence** (base/base `BaseFeature::SubsecondBlocks`,
`RollupConfig::NATIVE_SUBSECOND_BLOCK_INTERVAL_MILLIS = 200`, active from Denim; seal
target `DEFAULT_SEAL_OFFSET = 150 ms` into each slot, `crates/consensus/protocol/src/timing.rs`).
There is no flashblock stream, no websocket feed, no pending-flashblock RPC overrides.

Reference: base/base `crates/consensus/protocol/src/timing.rs`, `crates/common/genesis`
(subsecond feature, rollup config), `crates/consensus/service/src/standalone.rs`
(sequencer cadence, `BaseTimeUpdateTx`), `crates/execution/payload`, `crates/builder/core`
(only the non-flashblocks parts).

## Backlog
- [x] Remove flashblocks: delete `src/execution/flashblocks`, `src/common/flashblocks`,
  `src/builder/publish`, flashblock fuzz targets, sim wiring, and flashblock gossip/RPC
  hooks elsewhere (small edits in other lanes' files are allowed for this). Keep only code
  that a regular builder uses (best-txs view, rejection cache, timing, metering if used).
  Main must stay green at every push; do it in a few steps.
- [x] `builder/core`: turn the flashblock generator into a single-shot block builder:
  forced txs (deposits incl. L1 info + `BaseTimeUpdateTx`) then best pool txs until the
  gas/DA budget or the wall-clock tx cutoff (seal offset, default 150 ms into the 200 ms
  slot), seal once. Deterministic over injected time.
- [x] `builder/core` service core: `forkchoiceUpdated` (attributes) starts a job,
  `tick` builds until the cutoff and seals, `resolve` (getPayload) returns the sealed block
  (sealing at once when early); one job at a time; cancellation on new FCU.
- [ ] Wire `builder/core` `Service` into the node's Engine API handlers
  (`engine_forkchoiceUpdated` with attributes, `engine_getPayload`) behind a flag, with the
  node's IO clock as the builder `Clock` (coordinate with nf-node via small edits).
- [ ] 200 ms cadence end to end with nf-consensus and nf-batcher-devnet: sequencer
  requests a payload every 200 ms slot, seals at the offset, inserts; devnet genesis
  activates Denim/subsecond blocks at genesis; `just devnet smoke` passes at 200 ms.
- [ ] `bin/base builder` subcommand + flags (non-flashblocks subset of base/base
  `builder/cli/args.rs`), or fold into `base node` if base/base does not need a separate
  process without flashblocks — decide, record, implement.
- [ ] DST: builder in the cluster simulator at 200 ms blocks; invariants: every slot gets
  exactly one block (or an explained skip), sealed blocks replay identically on the
  verifier, no getPayload ever waits past the slot end.
- [ ] Benchmarks: build+seal latency per 200 ms slot at full gas limit; target well under
  the 150 ms cutoff. Record in docs/PERF.md.

## Decisions
- 2026-11-05: Flashblocks dropped by the project owner; superseded flashblocks
  decisions are in git history (`git log -- docs/lanes/flashblocks-builder.md`).
- 2026-11-05: `compact_flashblock_metadata` dropped from both feature enums (genesis and
  rollup config): base/base reads it only in the flashblocks payload path.
- 2026-11-05: single-shot builder runs in one synchronous `build` call (begin block,
  attribute txs, pool txs, finish, seal, roll back) instead of holding an open block across
  ticks, so the chain's executor and state are never left mid-block between IO events (RPC
  or imports may use them). Time passing during the build comes from an injected `Clock`
  read between pool transactions; `tick(now_ns)` triggers the build. This matches base/base
  one-shot building: the pool iterator is walked once and the payload is frozen.
- 2026-11-05: a job's slot starts at the FCU's time (the last `tick`); cutoff =
  start + `seal_offset_ms` (150), slot end = start + 200 ms, expiry = end + 500 ms leeway.
  An early `resolve` seals with the cutoff moved to now and never waits.
- 2026-11-05: the attribute transactions are copied at `start` so the caller's FCU buffers
  need not outlive the call; `Service` is no longer generic over a publish sink.

## Log
- 2026-11-05: `common/flashblocks` `encode_json`/`encode_brotli`, byte-exact random round-trip
  seeded + `std.testing.fuzz` tests.
- 2026-11-05: own `src/common/flashblocks`; `FlashblockId.parse` now matches Rust
  `u64::from_str` (leading '+', no '_'), dst-fuzz skip removed.
- 2026-11-05: builder/core timing schedule (deadline.rs, config.rs) with exhaustive + fuzz tests.
- 2026-11-05: `builder/publish` replay ring + `Publisher(IO)` over the ws server with resume
  replay, base/base metrics, and a SimIo DST (resets, partitions, floods, reconnects).
- 2026-11-05: `builder/core` best-transactions view and rejection cache, model-checked fuzz.
- 2026-11-05: `builder/multiplex` router (Denim one-shot selection, shadow builds, health).
- 2026-11-05: builder/core flashblock generator (index 0 + cumulative-budget deltas with
  per-delta roots and block hash; final block equals a `Chain` build), seeded + fuzz tests.
- 2026-11-05: `builder/metering` store (LRU/TTL, late arrivals) and execution metering mode.
- 2026-11-05: `execution/flashblocks` consumer: validation, pending blocks, cache, processor,
  state builder interface, resuming ws subscriber with backoff and keepalive; SimIo DST
  against `builder/publish` (resets, partitions, floods) checks exactly-once assembly.
- 2026-11-05: `builder/core` payload service (FCU starts/cancels a job, deadline ticks build and
  publish flashblocks, getPayload resolves the last sealed block), multiplex `Builder` interface,
  seeded + fuzz model check of FCU/resolve/tick interleavings.
- 2026-11-05: `execution/flashblocks` `ExecutorState`: pending re-execution on the node executor
  over a canonical overlay; receipts, balances, nonces, storage, code, pending `eth_call`;
  differential seeded + fuzz tests against the builder generator and imported blocks.
- 2026-11-05: `execution/flashblocks` RPC: pending-tag overrides (block, receipt, balance, nonce,
  call) and `newFlashblocks`/`pendingLogs`/`newFlashblockTransactions` pubsub; byte-equal to
  the producer's canonical JSON; seeded + fuzz request shapes.
- 2026-11-05: lane repointed from flashblocks-builder to builder (no flashblocks, native
  200 ms blocks).
- 2026-11-05: removed flashblocks, step 1: `execution/flashblocks` (consumer, RPC, pubsub),
  `builder/publish`, flashblock fuzz targets, and `BaseFeature.compact_flashblock_metadata`.
- 2026-11-05: removed flashblocks, step 2: `common/flashblocks`, `builder/multiplex`, and the
  flashblock generator; `BestFlashblocksTxs` renamed `BestTxs`.
- 2026-11-05: `builder/core` single-shot `BlockBuilder` (attribute txs, then best pool txs
  until gas/DA budget, pool end, or the injected-clock cutoff; sealed block hash-equals a
  `Chain` build), `timing` reworked to 200 ms slots + 150 ms seal offset (ports base/base
  `block_seal_target` tests), `Service` FCU/tick/resolve; seeded + `std.testing.fuzz` tests.
