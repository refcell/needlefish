# Lane: consensus

Owns `src/consensus/*` and `bin/consensus`. Reference: base/base `crates/consensus/*`
(kona-derived), OP Stack derivation spec.

## Backlog
- [x] `protocol`: (split below) rollup config, system config (+ updates from L1 logs), L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian formats), user deposits from TransactionDeposited logs, frames, channels, singular + span batches, batch validity rules (Holocene strict ordering), block info.
  - [x] frames (zero-copy codec, payload parser), channels, `BlockInfo`/`L2BlockInfo`
  - [x] singular batches (codec + validity rules), batch drop reasons (uses `common/rlp`)
  - [x] span batches (bitlists, tx data decoding) + batch reader (zlib, brotli)
  - [ ] span batch EIP-8130 tx data: `common/consensus/eip8130.zig` now decodes/encodes 0x79
    (`TxEip8130`, `Signed`), so `error.Eip8130Unsupported` can be replaced.
  - [x] rollup config + hardfork activation, system config + L1 log updates
  - [x] user deposits (TransactionDeposited logs), deposit tx encoding, source hashes
  - [x] L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian), blob base fee schedule
  - [x] batch validity rules (singular, span, Holocene)
- [x] `sources`: L1 RPC client (blocks, receipts, by number/hash), beacon blob client, L2 engine client (JWT) — all over `utilities.rpc`/`http`.
  - [x] L2 chain provider (`l2_block_info_by_number`/`_by_hash`, `system_config_by_l2_hash`)
  - [ ] engine `getPayloadBodies`/`exchangeCapabilities` if needed
- [x] `derive`: (split below) pipeline stages (L1 traversal, retrieval calldata/blobs, frame queue, channel bank/assembler, channel reader with zlib+brotli decompression (own implementations or std.compress), batch stream/queue, attributes queue), resets, Holocene semantics. Fuzz all decoders.
  - [x] blob codec, error kinds, provider contracts, L1 traversal
  - [x] data sources (calldata, blobs), L1 retrieval, frame queue (Holocene pruning)
  - [x] channel bank / assembler / provider (Holocene switch)
  - [x] channel reader (decode owned batches)
  - [x] batch stream, batch queue, batch validator, batch provider
  - [x] stateful attributes builder, network upgrade txs (Ecotone/Fjord/Isthmus/Jovian)
  - [x] attributes queue, pipeline core (step, reset, signals)
- [ ] `engine`: (split below) engine task queue (insert unsafe, consolidate, build, finalize), forkchoice state tracking, safe/finalized promotion.
  - [x] sync state (heads, forkchoice state, ordering invariant), L2 finalizer
  - [x] engine task queue: insert unsafe, consolidate (AttributesMatch), build/seal (Holocene
    deposits-only fallback), finalize, synchronize; deterministic mock engine, fuzzed
  - [x] polling adapter over `sources.EngineClient` (callback-based) implementing the task
    client contract in `engine/task.zig`, plus a full L2 block fetch (header fields + raw
    EIP-2718 txs incl. deposits + withdrawals) for consolidation
  - [x] starting forkchoice discovery (resumable find_starting_forkchoice)
  - [ ] EL sync mode, checkpoint reader / pruned-block recovery
- [ ] `sequencer`: build L2 blocks at block time, sequencer drift, L1 origin selection, conductor-free single sequencer.
  - [x] L1 origin selector (non-blocking, drift, subsecond, reorg detection)
  - [x] build ticker + attributes for sequenced blocks, seal, admin start/stop
- [ ] `rpc`: optimism_* (outputAtBlock, syncStatus, rollupConfig), admin_*.
  - [x] optimism_outputAtBlock, safeHeadAtL1Block, syncStatus, version
  - [x] rollup.json codec (protocol) + optimism_rollupConfig
  - [x] admin_* sequencer control (active/start/stop), recover mode, resetDerivationPipeline,
    conductorEnabled, healthz
  - [x] admin_postUnsafePayload: `engine_json.decode_unsafe_envelope` → `Driver.insert_unsafe` (same rules as gossip); RPC body limit raised to 1 MiB
  - [ ] base_* RPC
- [x] `safedb`: L1→safe head mapping (in-memory sorted, bounded; 80-byte records for persistence).
- [x] `p2p`: `Node` embeds `p2p.Network(IO)` (`--p2p.*` flags, on by default, `--p2p.disabled`): gossiped blocks go to `Driver.insert_unsafe`, the sequencer publishes each sealed block; devnet verifier follows the sequencer's unsafe head over gossip.
  - [x] unsafe payload buffer: gossiped blocks ahead of the unsafe head wait (64 slots, highest evicted) until their parent is inserted
  - [ ] EL sync from gossip (forkchoice to the gossiped tip when the gap exceeds the buffer; needs EL-side p2p sync)
  - [ ] unsafe block signer from the L1 SystemConfig instead of `--p2p.unsafe.block.signer`
  - [ ] `--p2p.bootnodes-file` / `--p2p.bootstore` file IO in the binary
- [ ] `bin/consensus`: sequencer + verifier modes, flags like base/base.
  - [x] service: L1 head watcher (latest/safe/finalized polling, verified headers)
  - [x] service node stage 1: L1 watcher + engine label heads → optimism_* RPC server;
    `base consensus` subcommand with the docs/DEVNET.md flags
  - [x] sequencer: next-block attributes on the unsafe head (origin selection, consistency
    check, pool gating; resets reported to the caller)
  - [x] service driver: startup forkchoice → synchronize + pipeline reset, derivation →
    consolidate, safedb + finalizer, sequencer build → seal (one loop, client-generic)
  - [x] service node stage 2: run the driver in `Node` over real providers (L1Provider,
    BlobProvider + KZG, L2Provider, polling engine client); logs phase/unsafe/safe heads
  - [x] L2Provider `l2_block_by_number` (full safe blocks via `l2_block_full`) so span
    batches overlapping the safe chain decide instead of waiting
  - [x] devnet smoke green (sequencer produces blocks, verifier safe head follows)
  - [x] optimism_outputAtBlock from Isthmus headers (`withdrawalsRoot` = message passer
    storage root)
  - [ ] optimism_outputAtBlock before Isthmus via eth_getProof of the L2ToL1MessagePasser

## Decisions
- Deviation from base/base `batch_queue.rs`: `next_batch` advances the epoch list a second time, after `update_origin` appends the new origin (the Holocene `BatchValidator` order). Otherwise a reset point one L1 block behind the safe head's origin (always the case near genesis) leaves [reset origin, parent origin], every step fails `L1OriginMismatch`, and the reset repeats forever.
- p2p in `base consensus` is on by default (base/base); without `--p2p.unsafe.block.signer` a verifier runs with p2p off and warns, a sequencer signs with its own key. The node key is random unless `--p2p.priv.*`. The devnet verifier dials the sequencer's enode, scraped from its startup log.
- Gossiped unsafe blocks: the block right after the unsafe head is queued, later ones wait in a 64-slot buffer (evicting the highest number when full), stale ones are dropped. Gaps the buffer cannot bridge are filled by derivation until EL sync exists. An active sequencer ignores gossip.
- Devnet: the dev L1 JSON-RPC server allowed only 4 connections; each consensus node holds
  two (watcher + provider) and the batcher more, so the verifier's L1 provider was reset
  forever (RecvFailed). Raised to 16 (beacon 8) in `execution/node/service.zig`.
- Driver: one tick-driven loop instead of base/base's actors; the engine queue owns the
  heads. Sequencer builds at the block's timestamp and seals right after the payload id
  (base/base seals on the next tick at block time); good enough until gossip lands.
- Frame `is_last` byte other than 0/1 is rejected (OP Stack spec / op-node), stricter
  than base/base's `== 1`.
- Decoded frames borrow the input (zero-copy); channels copy frame data into allocator-owned
  memory because L1 payloads are transient. Total bytes are bounded by the channel bank.
- `RollupConfig`, `SystemConfig` live in `src/consensus/protocol` (upstream: `common/genesis`)
  because this lane's backlog owns them; JSON (serde) parsing comes with `bin/consensus`.
  Execution-only Base features (Beryl/Cobalt/Everest/Zenith precompiles) are omitted from
  `Feature`; the runtime upgrade override registry is not ported yet.
- `DepositTx` lives in `protocol/deposits.zig` until the primitives lane lands OP deposit
  tx types; switch to theirs then.
- Invalid system config logs are skipped (base/base collects them as non-fatal errors).
- Zig 0.17 has no array `**` operator: use `@splat`.

- Derivation stages are plain structs whose methods take the previous stage and the
  providers as `anytype`; providers never block and return `error.NotAvailable`
  (temporary) while a fetch is in flight. Error kind (temporary/reset/critical) is a pure
  function of the Zig error (`derive/errors.zig`).
- L1 transactions reach the data sources with a recovered `from`; providers over an
  untrusted RPC must recover the sender themselves.
- Span batches: EIP-8130 txs decode but cannot be expanded yet (`error.Eip8130Unsupported`)
  until `common/consensus` has 8130 decoding. Overflow returns errors where base/base wraps.
- Brotli: own RFC 7932 decoder, static dictionary committed (CRC checked vs RFC).
- Attributes builder errors: `BlockMismatch` → `L1OriginMismatch`, `BlockMismatchEpochReset`
  → `EpochParentMismatch`, `BrokenTimeInvariant` → `BadTimestamp` (all reset); deposit decode
  failures → `BadEncoding` (critical); BaseTime/overflow → `AttributesBuilder` (critical).
  Upgrade deployment bytecode is embedded hex copied verbatim from base/base and decoded
  when an activation block is built. `PayloadAttributes` reuses the execution lane's
  `Withdrawal` and converts to its engine type with `engine()`.
- Sources verify instead of trusting the RPC: every header must hash to its block hash;
  senders of txs to the batch inbox are recovered from the rebuilt EIP-2718 envelope
  (mismatch with the RPC `from` rejects the block); the envelope must hash to the tx
  `hash`. Unless `trust_rpc` (base/base default true, ours false), transactions and
  receipts roots must match the header, so unknown L1 tx types are rejected in strict mode.
- `L1Provider`: one request in flight, bounded de-duplicated queue (overflow drops; the
  caller's retry re-enqueues), fixed LRU caches with one arena per slot. By-number results
  live for a short TTL (2 s) because numbers move on reorgs (base/base never caches them);
  `null` results surface once as `NotFound`; failed/unverifiable fetches are dropped.
- `BlobProvider`: base/base's `/eth/v1/beacon/blobs/{slot}?versioned_hashes=` endpoint by
  default (blob_sidecars optional); blobs matched by recomputed KZG commitment (sidecars:
  commitment hash + `verify_blob_kzg_proof`). The verifier is a type parameter so tests use
  a cheap fake; production passes `KzgVerifier` with caller-owned setup/workspace. 404 →
  `BlobsUnavailable` once.
- `EngineClient`: FCU V2/V3, newPayload V2-V4, getPayload V2-V5 (base/base versions), one
  request in flight, callback-based `Response` union, fresh JWT per request from IO time.
  Reuses execution-lane `ExecutionPayload`/`PayloadAttributes`/`ForkchoiceState` types.

- Decoded batches own an arena (`OwnedBatch`) holding a copy of their bytes, so they outlive
  the channel's decompressed buffer.

- Batch stages do not own their upstream: the pipeline resets each stage upstream-first.
  L2 fetch errors during span checks make the span undecided (as base/base). `l1_blocks`
  and the queue's batch list are allocator-bounded only, as in base/base.

- RPC handlers never block: `optimism_outputAtBlock` returns -32000 "output not available
  yet" until the backend has the EL proof. rollup.json reading is lenient
  (unknown fields such as `chain_op_config` skipped; integers as numbers or hex quantities).

- Pipeline: `derive.pipeline.Pipeline` owns every stage and binds them per call with
  providers `chain` (L1), `blobs`, `l2` (safe chain + `system_config_by_l2_hash`). Prepared
  attributes sit in a bounded ring (`prepared_max` = 16, base/base: unbounded); a full ring
  fails `step` with temporary `PreparedAttributesFull`. The driver answers
  `HoloceneActivation` with an activation signal and other reset errors with a reset.
  The attributes queue only checks the batch parent hash, as base/base.

- Engine task queue: tasks are resumable state machines over a polling client contract
  (`engine/task.zig`; `NotAvailable` while in flight, same arguments on retry). Zig errors
  carry no payload, so each base/base task error is a distinct error with a fixed severity
  (temporary/deferred/critical/reset/flush); nested errors keep their own. Priorities:
  build 5 > seal 4 > insert 3 > consolidate 2 > finalize 1 > synchronize 0 (base/base queues
  only seal/insert/consolidate/finalize; build and synchronize are direct calls there), FIFO
  within a priority. A task waiting on the client stays active (no preemption) so tasks stay
  atomic. Temporary failures restart the task and return to the caller (base/base retries in
  place); deferred/critical keep it; flush drops it; reset clears the queue. Fixed capacity
  (`QueueFull`), one arena per slot holding copies of payloads/attributes.
- Engine heads: applying an update that would break finalized <= safe <= local safe <= unsafe
  fails with critical `UnorderedHeads` instead of storing it; a SYNCING-filtered partial update
  that would break it is dropped. Seal results go to the caller through the queue's step
  result (no `result_tx`); `UnsafeHeadChangedSinceBuild` (direct `get_payload`) and Denim
  `BaseTimeUpdateTx` timestamp validation on insert are not ported yet. All-zero Holocene
  `eip1559Params` resolve to `Context.fee_params_canyon` (default 250/6, base/base
  `post_canyon_params`) because `RollupConfig` has no chain op config. Deposits-only
  fallback builds with the leading-deposits prefix of the attributes' transactions.
- Polling engine client (`engine/polling_client.zig`): each call names its request with a
  key (method, version, 64-bit Wyhash digest of the identifying arguments: forkchoice state
  + attributes, payload block hash + side-car, payload id, block number). A stored result is
  handed out once to the matching call; a different call discards it and starts its own
  request, so an abandoned task cannot leak its result into another. Errors: -38002 ->
  `InvalidForkchoiceState`; block decode/verify/genesis failures -> `InvalidBlock`;
  transport and other RPC errors (and arena OOM) -> `RpcFailed`; null block -> null; a block
  whose number differs from the requested one -> `InvalidBlock`.
- Full L2 blocks (`sources/l2_block_full.zig`): transactions are rebuilt from the JSON
  objects (types 0-4 and deposits 0x7e), each must hash to its `hash` and the list must
  match `transactionsRoot`; senders are not recovered (hash + root already bind them).
  Deposit `to` (absent = create), `mint`, and `isSystemTx` default like op-alloy serde.
  Withdrawals are decoded but not checked against `withdrawalsRoot` (post-Isthmus that root
  is the message passer storage root).

## Log
- 2026-11-05: rpc: admin_postUnsafePayload decodes the posted envelope and queues it like a gossiped block.
- 2026-11-05: derive: fix reset livelock (DST seed 48): `BatchQueue.next_batch` advances the epoch list again after appending the new origin; regression test in `batch_queue_test.zig`.
- 2026-11-05: service: `UnsafeBuffer` keeps out-of-order gossiped blocks until their parent is inserted; driver drains it every tick. Devnet verifier unsafe head equals the sequencer's.
- 2026-11-05: service: unsafe-block gossip wired into `base consensus` (p2p.Network in Node, publish on seal, insert on receive); devnet smoke green with the verifier's unsafe head tracking the sequencer over gossip.
- 2026-11-05: engine/service: seal tasks own their fetched payload once the insert starts (the polling client reuses result memory); queue keeps the last unsafe sealed payload (`take_sealed`); `Driver.insert_unsafe` queues the gossiped payload right after the unsafe head; `service/gossip_bridge.zig` converts engine <-> gossip payloads.
- 2026-11-05: rpc: admin_* sequencer control, recover mode, pipeline reset, healthz.
- 2026-11-05: rpc: optimism_outputAtBlock output roots from Isthmus L2 headers.
- 2026-11-05: sources: L2 provider full safe blocks (arena slots, TTL) for span checks.
- 2026-11-05: devnet smoke green; driver/L1 failure logging; L1 server connection limit.
- 2026-11-05: service: node runs the driver over real providers (`base consensus`).
- 2026-11-05: service: driver (startup, derivation, finalization, sequencing), fuzzed.
- 2026-11-05: sequencer: next-block attributes (build_on, pool gating), fuzzed.
- 2026-11-05: engine: polling client over `sources.EngineClient` (keyed results, error
  mapping), full L2 block fetch with deposits; e2e insert + consolidate over SimIo, fuzzed.
- 2026-11-05: service: node stage 1 (heads + RPC); bin: `base consensus` subcommand.
- 2026-11-05: sources: L2 provider label queries; service: L1 head watcher.
- 2026-11-05: sources: L2 chain provider; protocol: system config from L2 blocks.
- 2026-11-05: engine: task queue (insert, consolidate, build, seal, finalize, synchronize),
  AttributesMatch, mock engine, seeded + std fuzz.
- 2026-11-05: sources: L1 JSON decoders, caching L1 provider, beacon blob provider, engine
  client with L2 block info.
- 2026-11-05: sequencer: non-blocking L1 origin selector, fuzzed.
- 2026-11-05: derive: attributes queue, pipeline core (step, signals, reset walk-back), e2e + fuzz.
- 2026-11-05: protocol: rollup.json codec; rpc: optimism_rollupConfig.
- 2026-11-05: rpc: optimism_{outputAtBlock,safeHeadAtL1Block,syncStatus,version}.
- 2026-11-05: engine: resumable starting-forkchoice finder (reorg walk, safe walk), fuzzed.
- 2026-11-05: derive: channel reader, batch stream/queue/validator/provider (ported tests, fuzz).
- 2026-11-05: engine: sync state + forkchoice state, L2 finalizer (bounded, fuzzed).
- 2026-11-05: safedb: safe head updates, reset semantics, lookup, record codec, fuzz.
- 2026-11-05: derive: channel bank (Granite ready selection, size prune), assembler, provider.
- 2026-11-05: derive: calldata/blob data source, L1 retrieval, frame queue + Holocene prune.
- 2026-11-05: stateful attributes builder (Denim BaseTime/gas scaling), upgrade txs.
- 2026-11-05: derive: blob codec, error kinds, provider contracts, L1 traversal.
- 2026-11-05: span batches (codec, tx data, derive, validity), brotli decoder, batch reader.
- 2026-11-05: singular batch codec + validity (Holocene, Denim same-second, Jovian).
- 2026-11-05: L1 info deposit (4 formats, base/base vectors), fork selection, blob fee.
- 2026-11-05: user deposits, deposit tx 2718 encoding (base/base vectors), source hashes.
- 2026-11-05: rollup config (upgrades, features, Denim schedule), system config updates.
- 2026-11-05: protocol frames, channels, block info with seeded + std fuzz tests.
