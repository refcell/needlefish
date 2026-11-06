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
- [x] Wire `builder/core` `Service` into the node's Engine API handlers
  (`engine_forkchoiceUpdated` with attributes, `engine_getPayload`) behind a flag, with the
  node's IO clock as the builder `Clock` (coordinate with nf-node via small edits).
- [x] 200 ms cadence end to end with nf-consensus and nf-batcher-devnet: sequencer
  requests a payload every 200 ms slot, seals at the offset, inserts; devnet genesis
  activates Denim/subsecond blocks at genesis; `just devnet smoke` passes at 200 ms.
- [x] `bin/base builder` subcommand + flags (non-flashblocks subset of base/base
  `builder/cli/args.rs`), or fold into `base node` if base/base does not need a separate
  process without flashblocks — decide, record, implement.
- [ ] DST: builder in the cluster simulator at 200 ms blocks; invariants: every slot gets
  exactly one block (or an explained skip), sealed blocks replay identically on the
  verifier, no getPayload ever waits past the slot end.
  - [x] Builder-side hooks: `Service.observer` job events (started, sealed with cutoff,
    resolved with arrival time, ended with reason: cancelled/expired/failed, start_failed)
    and `slot_audit.SlotAudit`, which checks the three invariants from those events plus the
    verifier's replay hashes; cadence DST uses it with cancelled and expired (skipped) slots.
  - [ ] Cluster: blocked on dst-fuzz "Sim at native 200 ms blocks" (the sim's real execution
    is Granite at 2 s and builds through `Chain`, not `builder/core`). When it lands: install
    `NodeBuilder(SimIo)` on the real sequencer engine, set
    `node_builder.service.observer = Observer.of(SlotAudit, &audit)`, call
    `audit.on_replay(number, hash)` on each verifier import, `audit.reset(head)` on reorgs,
    and fail the seed on `audit.violation`, `resolves_late` without an injected delay, or
    `unreplayed()` at settle.
- [x] Benchmarks: build+seal latency per 200 ms slot at full gas limit; target well under
  the 150 ms cutoff. Record in docs/PERF.md.
- [x] `miner_setGasLimit` in pool selection: `BlockBuilder` fills pool transactions only up
  to `min(Chain.gas_limit_target, block gas limit)` (base/base `GasLimitConfig` in
  `execute_best_transactions`); the synchronous `Chain` build already did, the builder did not.
- [ ] Resource metering in tx selection: wire `builder/metering` into `BlockBuilder.apply_best`
  as base/base `execute_best_transactions` does (`check_simulated_usage` before execution,
  `check_executed_usage` after, `apply_accounted_usage` on commit, throttled count per build),
  plus the `resource_metering_*` and `metering_late_arrival_*` metrics of
  `crates/builder/core/src/metrics.rs`. Off by default, like `enable_resource_metering`.
- [ ] Sequencer self-import cost (from the `builder:` bench: build 20 ms CPU, self-import 55 ms
  wall at 2610 txs): the node re-recovers every sender and re-executes the sealed block. Hand
  the builder's known senders (it already skips ecrecover via `known_sender`) to the import, or
  commit the builder's state directly; needs the nf-node lane (`Chain.insert`).

## Decisions
- 2026-11-05: Flashblocks dropped by the project owner; superseded flashblocks
  decisions are in git history (`git log -- docs/lanes/flashblocks-builder.md`).
- 2026-11-05: Engine API wiring: `Chain.payload_builder` (an optional vtable) sits in front of
  the synchronous `Chain` build; `builder/core` `NodeBuilder(IO)` implements it. FCU with
  attributes starts a job and returns; a zero-delay IO timer ticks the service (build + seal
  at the 150 ms cutoff), a second timer drops expired jobs. getPayload resolves (sealing at
  once if unbuilt) and the chain imports the sealed block through its regular `insert`, which
  re-executes it once (doubles block execution on the sequencer, but verifies the builder's
  roots and keeps one import path; a direct commit of the builder's state is a later
  optimisation). A failed build makes getPayload answer `UnknownPayload`; a failed job start
  answers `InvalidPayloadAttributes`. The old `Chain` build stays the default; the service is
  opt-in (`--builder.enabled`), L2 only (L1 Prague requests are not carried by the builder).
- 2026-11-05: No separate `base builder` binary. base/base ships `bin/builder` only to add
  flashblocks and its extensions on top of the execution node; without flashblocks the
  builder folds into `base node` behind `--builder.enabled` with the non-flashblocks flags
  `--builder.rejection-cache-max-capacity` and `--builder.rejection-cache-ttl-secs`.
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
- 2026-11-05: 200 ms end to end: Denim at L2 genesis, the BaseTime proxy and
  `engine_getPayloadV5` landed from the batcher-devnet/node lanes (d7f44e5f) while this lane
  did the same work; theirs is kept. This lane's part: the devnet sequencer EL runs
  `--builder.enabled` (verifier EL only imports), so the devnet builds every 200 ms block
  through the `builder/core` service. `just devnet smoke` passed locally on that setup (51
  blocks in 10 s, all checks, BaseTime slot 0 updating), so the DST item below stays for the
  simulator rather than replacing the smoke.
- 2026-11-05: Engine API -> builder interface: node calls Service.send_new_payload(id, parent,
  attrs) on FCU+attrs, arms an IO timer at next_deadline_ns -> tick(now_ns), resolve(id) on
  getPayload (never blocks; Payload borrows builder buffers until next job). Builder reads
  Chain/StateDb, never commits. nf-node owns the handler wiring. (The first wiring, 210c4843:
  `Chain.payload_builder` + `builder/core` `NodeBuilder(IO)`, landed before this ownership
  change; nf-node maintains it from here, the builder lane keeps only `src/builder` helpers.)

- 2026-11-05: DST slot invariants live on the builder side as an event auditor
  (`SlotAudit` over `Service.observer`) rather than inside the cluster simulator, because the
  cluster's 200 ms mode is the dst-fuzz lane's backlog item; the cluster only has to forward
  events and replay hashes. A getPayload arriving after the slot end is counted
  (`resolves_late`), not a violation: under injected network delay it is the consensus side's
  lateness, and the service still answers without waiting.

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
- 2026-11-05: `builder/core` `NodeBuilder(IO)` wires the payload service into the node's Engine
  API (`Chain.payload_builder`, IO timers, `--builder.enabled` on `base node`); engine-level
  tests (equals a `Chain` build, early getPayload, expiry) and seeded + fuzz interleavings.
- 2026-11-05: devnet sequencer EL on `--builder.enabled`; `just devnet smoke` passes at 200 ms.
- 2026-11-05: `builder/core` cadence DST (`cadence_test.zig`): `Service` driven directly over
  injected time on a Denim-at-genesis chain; one block per 200 ms slot at the schedule's
  timestamp, no resolve past the slot end, verifier replays every block to the same hash and
  state root; seeded + `std.testing.fuzz`. The cluster-simulator item stays open.
- 2026-11-05: removed flashblocks, step 1: `execution/flashblocks` (consumer, RPC, pubsub),
  `builder/publish`, flashblock fuzz targets, and `BaseFeature.compact_flashblock_metadata`.
- 2026-11-05: removed flashblocks, step 2: `common/flashblocks`, `builder/multiplex`, and the
  flashblock generator; `BestFlashblocksTxs` renamed `BestTxs`.
- 2026-11-05: `builder/core` single-shot `BlockBuilder` (attribute txs, then best pool txs
  until gas/DA budget, pool end, or the injected-clock cutoff; sealed block hash-equals a
  `Chain` build), `timing` reworked to 200 ms slots + 150 ms seal offset (ports base/base
  `block_seal_target` tests), `Service` FCU/tick/resolve; seeded + `std.testing.fuzz` tests.
- 2026-11-05: builder slot bench (`builder:`): FCU+build+seal+getPayload at a full 60 M gas
  block (3000 transfers + 64 storage-heavy calls pooled), 2610 txs/block, 19.8 ms p50 / 26.6 ms
  p99 thread CPU; recorded in docs/PERF.md.
- 2026-11-05: `builder/core` `Service.observer` job events and `SlotAudit` (one block per
  slot or explained skip, seal cutoff inside the slot, verifier replay hashes); model fuzz with
  injected faults; cadence DST now skips slots (cancel, expiry) and runs through the audit.
- 2026-11-05: `BlockBuilder` honours the `miner_setGasLimit` target (`Chain.gas_limit_target`)
  for pool transactions; unit test plus the seeded/fuzz builder job draws a target.
