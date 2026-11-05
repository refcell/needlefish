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
- [ ] `builder/publish`: bounded broadcast ring of encoded flashblocks, WebSocket
  publisher with per-subscriber send queues and slow-subscriber eviction, listener
  accept loop, metrics (port `broadcast.rs`, `publisher.rs`, `listener.rs`). DST test
  with N simulated subscribers, loss and slow readers.
- [ ] `builder/core` flashblocks timing: per-block deadline schedule (interval,
  leeway, first-flashblock offset; port `deadline.rs`, `config.rs`), pure state machine
  over injected time, exhaustive + fuzz tests of schedule invariants.
- [ ] `builder/core` best-transactions iterator: priority-ordered txpool view that
  skips already-included and invalid txs across flashblocks (port `best_txs.rs`).
- [ ] `builder/core` flashblock generator: build index 0 (deposits + system txs) then
  incremental flashblocks from the pending state, each producing a delta (txs,
  receipts root, state root, gas used, withdrawals, logs bloom, block hash) and
  metadata (receipts, new balances); final sealed block identical to a non-flashblocks
  build of the same txs (port `generator.rs`, `payload.rs`, `context.rs`, `handler.rs`).
- [ ] `builder/core` service: Engine API integration (`forkchoiceUpdated` with
  attributes starts a job, `getPayload` returns the best sealed payload), resting /
  cancellation on new FCU (port `service.rs`, `resting.rs`).
- [ ] `builder/metering`: per-tx execution metering store and extension hooks
  (port `crates/builder/metering`, `execution_metering_mode.rs`).
- [ ] `builder/multiplex`: router between the canonical EL and the builder for Engine
  API calls (port `crates/builder/multiplex`).
- [ ] `execution/flashblocks` consumer: WebSocket subscription to a flashblocks feed
  with reconnect/backoff, ordering/validation (index, parent hash, payload id), pending
  block assembly and state builder, bounded cache keyed by block (port `processor.rs`,
  `validation.rs`, `pending_blocks.rs`, `state_builder.rs`, `cache.rs`).
- [ ] `execution/flashblocks` RPC: pending-tag overrides for `eth_getBlockByNumber`,
  `eth_getTransactionReceipt`, `eth_getBalance`, `eth_call`, `eth_getTransactionCount`,
  plus the `eth_subscribe` flashblocks pubsub (port `rpc/*`).
- [ ] `bin/base builder` subcommand + flags matching base/base `builder/cli/args.rs`;
  devnet hook (coordinate with batcher-devnet lane) so the devnet sequencer EL can run
  with flashblocks and `just devnet smoke` checks a pending-tag receipt.
- [ ] DST: builder + consumer in the cluster simulator; invariant: every flashblock
  sequence for a block replays to exactly the sealed block.

## Decisions
- Wire format published is plain JSON text (base/base `publisher.rs` sends `Utf8Bytes`);
  `encode_brotli` exists for consumers/tests and emits a bare brotli stream (no channel
  version byte), reusing the batcher lane's encoder.

## Log
- 2026-11-05: `common/flashblocks` `encode_json`/`encode_brotli`, byte-exact random round-trip
  seeded + `std.testing.fuzz` tests.
- 2026-11-05: own `src/common/flashblocks`; `FlashblockId.parse` now matches Rust
  `u64::from_str` (leading '+', no '_'), dst-fuzz skip removed.
