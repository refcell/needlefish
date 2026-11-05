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
- [ ] Remove flashblocks: delete `src/execution/flashblocks`, `src/common/flashblocks`,
  `src/builder/publish`, flashblock fuzz targets, sim wiring, and flashblock gossip/RPC
  hooks elsewhere (small edits in other lanes' files are allowed for this). Keep only code
  that a regular builder uses (best-txs view, rejection cache, timing, metering if used).
  Main must stay green at every push; do it in a few steps.
- [ ] `builder/core`: turn the flashblock generator into a single-shot block builder:
  forced txs (deposits incl. L1 info + `BaseTimeUpdateTx`) then best pool txs until the
  gas/DA budget or the wall-clock tx cutoff (seal offset, default 150 ms into the 200 ms
  slot), seal once. Deterministic over injected time.
- [ ] `builder/core` service: Engine API `forkchoiceUpdated` (attributes) starts a job,
  `getPayload` returns the sealed block; one job at a time; cancellation on new FCU.
  Wired into the node's Engine API handlers (coordinate with nf-node via small edits).
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
