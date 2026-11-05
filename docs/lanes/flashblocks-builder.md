# Lane: flashblocks-builder

Owns `src/builder/*` (submodules `core`, `publish`, `multiplex`, `metering`),
`src/execution/flashblocks/*`, `src/common/flashblocks` (taken over from primitives), and the `builder` subcommand of `bin/base`. Reference:
base/base `crates/builder/{core,publish,multiplex,metering,cli}` (~20k lines),
`crates/execution/{flashblocks,flashblocks-node}` (~12k lines) and
`crates/common/flashblocks`.

The primitives lane already landed the wire types and decoder in
`src/common/flashblocks` (payload/base/delta/metadata, JSON or brotli message). Extend
them there with small additive edits (an encoder, helpers) rather than duplicating.
WebSocket server/client come from `src/utilities/ws`; block execution, payload building
and the txpool come from the node lane (`src/execution/{payload,txpool,node}`) and the
EVM lane. All sockets and timers go through `src/utilities/io` so the cluster simulator
can drive the builder and the flashblocks consumer.

## Backlog
- [x] `common/flashblocks` encoder: JSON (and brotli, if the compressor exists, else
  plain JSON) encode of `FlashblocksPayloadV1`, byte-exact round trip with the decoder;
  seeded + `std.testing.fuzz` round-trip tests.
- [x] `builder/publish`: bounded broadcast ring of encoded flashblocks, WebSocket
  publisher with per-subscriber send queues and slow-subscriber eviction, listener
  accept loop, metrics (port `broadcast.rs`, `publisher.rs`, `listener.rs`). DST test
  with N simulated subscribers, loss and slow readers.
- [x] `builder/core` flashblocks timing: per-block deadline schedule (interval,
  leeway, first-flashblock offset; port `deadline.rs`, `config.rs`), pure state machine
  over injected time, exhaustive + fuzz tests of schedule invariants.
- [x] `builder/core` best-transactions iterator: priority-ordered txpool view that
  skips already-included and invalid txs across flashblocks (port `best_txs.rs`).
- [x] `builder/core` flashblock generator: build index 0 (deposits + system txs) then
  incremental flashblocks from the pending state, each producing a delta (txs,
  receipts root, state root, gas used, withdrawals, logs bloom, block hash) and
  metadata (receipts, new balances); final sealed block identical to a non-flashblocks
  build of the same txs (port `generator.rs`, `payload.rs`, `context.rs`, `handler.rs`).
- [ ] `builder/core` generator: flashblock metadata `receipts` and `new_account_balances`
  (base/base non-compact `FlashblocksMetadata`; extend `common/flashblocks.Metadata`).
- [ ] `builder/core` generator: Jovian per-flashblock DA footprint target
  (`da_footprint_per_batch`, cumulative DA bytes x scalar); the executor's block-level
  footprint limit is enforced today.
- [ ] `builder/core` generator: incremental intermediate roots (executor "continue block"
  after a commit) instead of re-executing the block prefix per flashblock.
- [x] `builder/core` service: Engine API integration (`forkchoiceUpdated` with
  attributes starts a job, `getPayload` returns the best sealed payload), resting /
  cancellation on new FCU (port `service.rs`, `resting.rs`).
- [ ] `builder/core` service wiring: Engine API `forkchoiceUpdated`/`getPayload` handlers that
  route through `multiplex.Router(Service)` and turn a resolved `service.Payload` into an
  execution payload envelope; an IO timer that calls `tick` at `next_deadline_ns`.
- [x] `builder/metering`: per-tx execution metering store and extension hooks
  (port `crates/builder/metering`, `execution_metering_mode.rs`).
- [x] `builder/multiplex`: router between the canonical EL and the builder for Engine
  API calls (port `crates/builder/multiplex`).
- [x] `execution/flashblocks` consumer: WebSocket subscription to a flashblocks feed
  with reconnect/backoff, ordering/validation (index, parent hash, payload id), pending
  block assembly and state builder, bounded cache keyed by block (port `processor.rs`,
  `validation.rs`, `pending_blocks.rs`, `state_builder.rs`, `cache.rs`).
- [x] `execution/flashblocks` executor-backed state builder: implement the `state.zig`
  interface over the node lane's executor (re-execute pending txs on the canonical state;
  receipts, balances, nonces, `eth_call` overrides; port `state_builder.rs`,
  `receipt_builder.rs`).
- [ ] `execution/flashblocks` canonical feed: call `Processor.on_canonical` from the node's
  canonical chain (forkchoice head moves, with the block's transaction hashes).
- [ ] `execution/flashblocks` state builder: reuse the previous snapshot's per-transaction
  results instead of re-executing on every rebuild (base/base `execute_with_cached_data`).
- [ ] `execution/flashblocks` RPC: pending-tag overrides for `eth_getBlockByNumber`,
  `eth_getTransactionReceipt`, `eth_getBalance`, `eth_call`, `eth_getTransactionCount`,
  plus the `eth_subscribe` flashblocks pubsub (port `rpc/*`).
- [ ] `bin/base builder` subcommand + flags matching base/base `builder/cli/args.rs`;
  devnet hook (coordinate with batcher-devnet lane) so the devnet sequencer EL can run
  with flashblocks and `just devnet smoke` checks a pending-tag receipt.
- [ ] DST: builder + consumer in the cluster simulator; invariant: every flashblock
  sequence for a block replays to exactly the sealed block.

## Decisions
- Metering store keeps base/base semantics (LRU + TTL from insert, late-arrival
  accounting) with injected time; moka's background expiry is an explicit `expire(now)`
  tick. The `base_setMeteringInformation` RPC wiring lands with the builder binary.
- Multiplex is a synchronous router over a comptime `Builder` interface (both builders
  in-process); it ports routing, shadow `no_tx_pool` builds, 128-id route memory, health,
  and the event filter. Wiring it to the Engine API service comes with `builder/core`
  service.
- Best-txs walks one `Pool.select` snapshot per flashblock; committed hashes persist per
  block. Resting predicates/parking (base/base `RestingPredicateMode`, default off) are
  deferred. The rejection cache is FIFO with TTL (moka TinyLFU approximated).
- Publisher replays inside `on_open` on the event loop, so replay and live messages
  cannot interleave and base/base's dedup set is unnecessary. A subscriber whose replay
  backlog overflows its send buffer is closed (base/base: replay send timeout). Slow
  subscribers are disconnected on broadcast (`SlowConsumer`) instead of tokio's lag.
- The replay ring stores at most `ring_entries_max` messages and `ring_bytes_max` bytes;
  a position older than the newest (a restarted payload job) clears it.
- Wire format published is plain JSON text (base/base `publisher.rs` sends `Utf8Bytes`);
  `encode_brotli` exists for consumers/tests and emits a bare brotli stream (no channel
  version byte), reusing the batcher lane's encoder.
- `builder/core/timing`: flashblock indices follow base/base (0 = fallback built at job start,
  regular flashblocks `1..=count`, flashblock `j` closes at `first + (j-1)*interval`). The
  schedule uses one injected time base where base/base reads `SystemTime` then `Instant`.
  `Config.validate` rejects interval 0, flashblocks leeway > interval, block time < interval,
  and durations over one hour (bounds keep all u64 sums in range).

- `builder/core/generator`: intermediate roots come from re-executing the block's accepted
  prefix each flashblock, committing once, sealing with `Chain.seal`, and `StateDb.rollback`;
  no executor change (only `Chain.child_header`/`seal` made `pub`). One undo record per
  flashblock is pushed and popped; the database stays at the parent state between
  flashblocks, so the last delta is exactly `Chain`'s build of the same list. Cost is
  O(flashblocks x prefix) executions; incremental roots are a backlog item.
- Every delta carries the real state root and the hash of the block sealed there, where
  base/base leaves `state_root` zero in flashblock deltas (it computes the root only in the
  final payload); a consumer can therefore verify each delta.
- Budgets follow base/base: `gas_per_batch = gas_limit / count`, `da_per_batch =
  block_bytes_max / count`, flashblock `j` fills up to `j * per_batch` (cumulative, deposits
  included in gas); over-budget or failing pool txs skip their sender's later nonces
  (`mark_invalid`). Accepted transactions are copied into a generator-owned buffer so pool
  eviction cannot dangle them.
- `builder/core/service`: a synchronous state machine over injected time. `send_new_payload`
  (FCU with attributes) cancels the previous job (base/base `ensure_only_one_payload`), builds
  and publishes flashblock 0; `tick(now)` builds every flashblock whose deadline passed (burst
  on late ticks) and drops the job at its `PayloadJobDeadline`; `resolve` returns the last
  sealed block and ends the job. Resolved, cancelled and expired ids answer null, as in reth's
  `PayloadBuilderService`. `best_payload` answers `BuildFailed` for the active id (base/base
  marks it unsupported). `send_new_payload` uses the last tick's time (the multiplex interface
  carries no clock). Resting carry is 0 (base/base `RestingPayloadTransactions` defaults hold
  nothing back). A failed flashblock build stops the job but its last sealed block stays
  resolvable (base/base's watch channel keeps the last value).

- `execution/flashblocks` consumer: the pending view stores what flashblocks carry (txs,
  hashes, withdrawals, latest delta roots/gas/hash, base) in a fixed ring of `blocks_max`
  block slots; a new block with every slot used evicts the earliest (base/base grows until
  a canonical block trims it). Capacity errors leave the view unchanged (base/base logs and
  keeps the previous snapshot). Execution sits behind the `state.zig` interface (`Noop` for
  now); reorg/depth rebuilds reset it and re-execute the retained blocks.
- The processor's canonical chain is what `on_canonical` reports; with none seen every
  parent counts as known. Added beyond base/base: a payload id change mid-block clears the
  pending blocks like a gap; a next block whose parent hash differs from the latest delta
  hash restarts the pending blocks from it (reorg).
- The cache stores re-encoded JSON in a fixed arena (`entries_max`, `bytes_max`); a full
  cache refuses inserts like an uncacheable block.
- The subscriber resumes with `?block_number=N&flashblock_index=I` of the last decoded
  flashblock (base/base reconnects to the plain URL), waits one backoff delay after every
  close (base/base reconnects at once after an upstream close), and detects stalls with a
  ws ping per interval (`ws.Client.ping`/`pongs_received`, added to `utilities/ws`).

- `execution/flashblocks` executor-backed state: `ExecutorState` owns an `Executor` whose
  backend reads a `db.Overlay` over the canonical `db.State` and folds each flashblock's evm
  state into it (never committed), so the canonical `StateDb` and its undo ring are never
  touched (no commit/rollback window during which the node could import on pending state).
  Pending contract code lives in a builder-owned store so the canonical code table and the
  durable journal see only canonical code. Flashblocks of a block resume the open block
  (`Executor.set_block_env` made `pub`); withdrawals/requests run via `finish_block` when the
  next block starts. The pending trie root is not computed (deltas carry it); receipts are
  copied out of the executor arena after every transaction. `has_storage` for create
  collisions reads the canonical trie (unless wiped); BLOCKHASH of an earlier pending block
  answers its latest delta hash. Any failure resets (base/base drops the pending state).

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
