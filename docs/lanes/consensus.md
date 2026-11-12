# Lane: consensus

Owns `src/consensus/*` and `bin/consensus`. Reference: base/base `crates/consensus/*`
(kona-derived), OP Stack derivation spec.

## Backlog
- [x] `protocol`: (split below) rollup config, system config (+ updates from L1 logs), L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian formats), user deposits from TransactionDeposited logs, frames, channels, singular + span batches, batch validity rules (Holocene strict ordering), block info.
  - [x] frames (zero-copy codec, payload parser), channels, `BlockInfo`/`L2BlockInfo`
  - [x] singular batches (codec + validity rules), batch drop reasons (uses `common/rlp`)
  - [x] span batches (bitlists, tx data decoding) + batch reader (zlib, brotli)
  - [x] span batch EIP-8130 tx data (`span_batch_tx_data.Eip8130`): authenticators inline,
    proofs in the trailing auth column, zero signature + contract-creation bit; `full_txs`
    rebuilds and `build` splits 0x79 transactions (`Eip8130Unsupported` removed)
  - [x] rollup config + hardfork activation, system config + L1 log updates
  - [x] user deposits (TransactionDeposited logs), deposit tx encoding, source hashes
  - [x] L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian), blob base fee schedule
  - [x] batch validity rules (singular, span, Holocene)
- [x] `sources`: L1 RPC client (blocks, receipts, by number/hash), beacon blob client, L2 engine client (JWT) — all over `utilities.rpc`/`http`.
  - [x] L2 chain provider (`l2_block_info_by_number`/`_by_hash`, `system_config_by_l2_hash`)
  - [x] engine `getPayloadBodiesByHashV1`/`ByRangeV1` and `exchangeCapabilities` on `EngineClient` (client-only, like base/base; no node caller)
- [x] `derive`: (split below) pipeline stages (L1 traversal, retrieval calldata/blobs, frame queue, channel bank/assembler, channel reader with zlib+brotli decompression (own implementations or std.compress), batch stream/queue, attributes queue), resets, Holocene semantics. Fuzz all decoders.
  - [x] blob codec, error kinds, provider contracts, L1 traversal
  - [x] data sources (calldata, blobs), L1 retrieval, frame queue (Holocene pruning)
  - [x] channel bank / assembler / provider (Holocene switch)
  - [x] channel reader (decode owned batches)
  - [x] batch stream, batch queue, batch validator, batch provider
  - [x] stateful attributes builder, network upgrade txs (Ecotone/Fjord/Isthmus/Jovian)
  - [x] attributes queue, pipeline core (step, reset, signals)
- [ ] M5 derivation check on Base Sepolia (`base derive-check`, `src/consensus/derive_check`):
  derive real safe blocks from Sepolia L1 (blobs from the beacon API) and compare every
  payload attributes with the reference node through `AttributesMatch` (header plus derived
  transactions root; the full body only on a root mismatch).
  - [x] 2026-11-08 run: start l2 56077495 (L1 origin 12090294), reset walk-back to l2
    56074375 (L1 origin 12090244); derived l2 56077496..56083495 (6000 blocks) from L1
    12090244..12090414 (9 blob blocks, 55 blobs): 6000 matched, 0 mismatched, 0 resets.
  - [x] fix found by the run: Amsterdam L1 headers (`blockAccessListHash`, `slotNumber`)
    failed the header hash check in `sources/header_json.zig` (L1Provider too)
  - [ ] engine API integration with the stateful node (consolidate against our own EL)
    - [x] el-run serves the Engine API (`bin/base/el_engine.zig`, `--engine.addr`,
      `--engine.jwt`): newPayload judged against executed blocks, forkchoice labels,
      full blocks from an in-memory ring (`bin/base/el_ring.zig`); see "el-run engine" below
    - [x] live run: `base consensus` (verifier) against el-run on Base Sepolia (SYNC_PLAN M5)
    - [ ] execute head+1 payloads through the Runner (el-run then needs no devp2p at the tip)
    - [ ] reorgs: el-run follows one devp2p chain; a reorged-out block is a divergence today
  - [x] L1 reorg evidence: live Sepolia reorg at L1 12094705 survived (SYNC_PLAN M5)
  - [ ] mainnet
- [x] `engine`: (split below) engine task queue (insert unsafe, consolidate, build, finalize), forkchoice state tracking, safe/finalized promotion.
  - [x] sync state (heads, forkchoice state, ordering invariant), L2 finalizer
  - [x] engine task queue: insert unsafe, consolidate (AttributesMatch), build/seal (Holocene
    deposits-only fallback), finalize, synchronize; deterministic mock engine, fuzzed
  - [x] polling adapter over `sources.EngineClient` (callback-based) implementing the task
    client contract in `engine/task.zig`, plus a full L2 block fetch (header fields + raw
    EIP-2718 txs incl. deposits + withdrawals) for consolidation
  - [x] starting forkchoice discovery (resumable find_starting_forkchoice)
  - [x] EL sync mode: derivation and sequencing wait for `el_sync_finished`; the driver
    re-sends the forkchoice state every 2 s while the engine answers SYNCING (base/base
    `AwaitingELSyncCompletion` + `probe_el_sync`)
  - [x] checkpoint store (`service/checkpoint.zig`, `--checkpoint.path`): safe/finalized
    heads in base/base's 128-byte record layout, one crc-checked image via `StoreFile`
  - [x] pruned-block recovery: L2 provider reports a missing L1 info deposit (pruned body);
    the start finder then uses a matching checkpoint, else binary-searches the earliest
    unpruned block (base/base `find_earliest_unpruned_block`)
- [x] Native 200 ms blocks (AGENTS.md rule 10):
  - [x] driver ticks in ms; subsecond slots build at the parent timestamp and seal 150 ms in
  - [x] BaseTimeUpdateTx deposit in sequenced and derived attributes; singular-only and
    same-second batch rules; pipeline test of 200 ms derivation
  - [x] devnet smoke at 200 ms (nf-builder, 2026-11-05): devnet genesis activates Denim at
    genesis, EL serves `engine_getPayloadV5` (Azul/Osaka); `just devnet smoke` passes with
    ~5 L2 blocks/s.
  - [x] devnet smoke at 200 ms passes (25 blocks per 5 s; verifier derives; metrics check)
- [x] `sequencer`: build L2 blocks at block time, sequencer drift, L1 origin selection, conductor-free single sequencer.
  - [x] L1 origin selector (non-blocking, drift, subsecond, reorg detection)
  - [x] build ticker + attributes for sequenced blocks, seal, admin start/stop
- [ ] `rpc`: optimism_* (outputAtBlock, syncStatus, rollupConfig), admin_*.
  - [x] optimism_outputAtBlock, safeHeadAtL1Block, syncStatus, version
  - [x] rollup.json codec (protocol) + optimism_rollupConfig
  - [x] admin_* sequencer control (active/start/stop), recover mode, resetDerivationPipeline,
    conductorEnabled, healthz
  - [x] admin_postUnsafePayload: `engine_json.decode_unsafe_envelope` → `Driver.insert_unsafe` (same rules as gossip); RPC body limit raised to 1 MiB
  - [x] base_* RPC: `base_upgradeReadiness` (`rpc/base.zig`) over an upgrade-signal observer (`--upgrade-signal.contract` / `.l1-block-tag`, default contract per chain); metrics-only mode
  - [x] admin_overrideLeader (no conductor: InternalError like base/base),
    admin_refreshUpgradeSignal (-32004 outside runtime-admin mode), dev_taskQueueLength
  - [ ] admin_clearPendingP2pConnections (needs a dial-abort API in `p2p.Service`)
  - [x] `--l1.verifier-confs` (default 0) / `--sequencer.l1-confs` (default 4): derive and
    pick origins at the L1 head minus confirmations
  - [x] `--sequencer.recover` (initial recover mode)
  - [x] `--rpc.disabled`
  - [x] `--rpc.execution-forwarding-endpoint`: unserved HTTP RPC methods go to the EL
- [x] L1 reorg orphaning batch data: startup/reset caps the safe label at the newest safedb entry whose L1 block is still canonical (coordinator; dst seed 850)
  - [x] reset records (the reset head at its L1 origin) count only when no newer entry is orphaned (`SafeCheck.judge`); fixes ungated 1097, 1310
  - [ ] ungated swarm 2997/3000 still: 992, 2258, 2622 keep safe beyond L1 batch data with no reorg visible to the verifier (investigate traversal over by-number cache vs. reorg timing)
  - [x] `--safedb.path` persistence of the L1→safe-head mapping
  - [x] admin error parity with base/base: sequencer methods on a verifier -32001, start/stop
    idempotent, redacted -32603 start/stop failures, postUnsafePayload fire-and-forget
  - [x] `ws_subscribe_{unsafe,safe,finalized}_head` and `dev_subscribe_engine_queue_size`
    (needs websocket support in the RPC server)
- [x] `safedb`: L1→safe head mapping (in-memory sorted, bounded; 80-byte records for persistence).
- [x] `p2p`: `Node` embeds `p2p.Network(IO)` (`--p2p.*` flags, on by default, `--p2p.disabled`): gossiped blocks go to `Driver.insert_unsafe`, the sequencer publishes each sealed block; devnet verifier follows the sequencer's unsafe head over gossip.
  - [x] unsafe payload buffer: gossiped blocks ahead of the unsafe head wait (64 slots, highest evicted) until their parent is inserted
  - [ ] EL sync from gossip (forkchoice to the gossiped tip when the gap exceeds the buffer; needs EL-side p2p sync)
  - [x] unsafe block signer from the L1 SystemConfig (`service/signer_watcher.zig`, polled every 60 s, applied to gossip validation); startup fallback: chain config, then `--p2p.unsafe.block.signer`, then the sequencer's own key
  - [x] `--p2p.bootnodes-file` / `--p2p.bootstore` file IO in the binary (done in `p2p.Network`
    through the io layer; the binary forwards every `--p2p.*` flag)
- [ ] `bin/consensus`: sequencer + verifier modes, flags like base/base.
  - [x] Prometheus metrics endpoint (`--metrics.enabled/addr/port`) with base/base metric
    names (heads, derivation, engine queue, sequencer, p2p)
  - [x] follow mode (base/base `service/follow`): follow a remote CL's safe/finalized heads
    over RPC instead of deriving
  - [x] op-conductor client (`--conductor.rpc`): leader check before sequencing,
    commitUnsafePayload, overrideLeader
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
  - [x] optimism_outputAtBlock before Isthmus via eth_getProof of the L2ToL1MessagePasser
    (`sources/message_passer_roots.zig`)

## Decisions
- derive-check takes each verified block's hash from the reference (the block the engine
  already has in consolidation), since the hash needs execution; blocks below the start come
  from the reference (the reset walk-back window, preloaded in batches). Public endpoints:
  sepolia.base.org counts every batch element against 25 calls/s, so L2 calls are paced at
  55 ms per element in batches of 20.
- Amsterdam header fields follow alloy's order: `requests_hash`, `block_access_list_hash`,
  `slot_number` (all optional, appended).
- Safe head after L1 reorgs: base/base discovery trusts a safe label whose L1 origin is canonical even when the blocks that carried its batch data are gone. We also check the safedb (L1 block -> safe head) at every startup/reset and lower the safe label to what canonical L1 still supports, so the batcher re-posts. A safe head may therefore drop after a reorg (the sim allows it at resets).
- execution forwarding: single requests over HTTP only; batches and WebSocket stay local (unknown methods -32601), because the servers cannot defer one batch entry or a WS frame. base/base forwards per batch entry.
- safedb persistence: one rewritten image (like checkpoints) instead of redb; the in-memory safedb stays on without a path (base/base disables tracking), since the RPC is useful anyway.
- Subsecond (Denim) blocks follow base/base timing: build at the parent's timestamp, `getPayload` at T - 50 ms. Pre-Denim blocks keep build-at-T, seal-on-payload-id (base/base builds one slot early); the devnet runs Denim from genesis so this only affects legacy chains.
- Admin and dev RPC are off by default like base/base (unmerged modules answer -32601). The devnet sequencer passes `--rpc.enable-admin` because the batcher finds the leader with `admin_sequencerActive`.
- Admin errors follow base/base exactly (codes and redacted messages) even where ours were more descriptive; reasons go to the log instead.
- WebSocket RPC listens on its own port (default 7546) because the HTTP server cannot upgrade; ids are numbers and notifications use the subscribe method name, like jsonrpsee; only changes after subscribing are sent.
- Conductor: leadership is polled every 1 s and admin_startSequencer answers from the last poll (the admin API is synchronous; base/base asks per call). Commits are JSON-RPC only and retried every 100 ms until accepted; the deposits-only fallback payload is committed too.
- Follow mode: one block in flight, fetched only while the engine queue is idle (the unsafe head is current, no double insert); labels polled every 30 s; no prefetch window, proof gate, or L1 origin check yet. The driver skips derivation and L1 finalization.
- Metrics: base/base names where they map (`base_node_block_labels{label}`, `base_node_engine_task_queue_depth`, `base_node_engine_reset_count`); driver counters are `base_node_*_total`, sampled from monotonic driver stats each tick.
- `ProviderError.Pruned` is critical for derivation (it cannot go below a pruned body). The
  node holds the driver until the checkpoint file is read, so startup sees the checkpoints.
- Checkpoints: base/base stores them in redb under its data dir by default; we write one
  fixed 269-byte image (magic, mask, two records, crc32) through the io layer and only when
  `--checkpoint.path` is given. A torn image loads as "no checkpoints".
- Engine queue: an empty `synchronize` update is always a forced forkchoice update (startup
  sync and EL sync probes); unforced it was a no-op once the heads were known, so
  `el_sync_finished` could stay false.
- Pre-Isthmus output roots: the RPC router is synchronous, so the first query for a block
  starts an `eth_getProof` (keyed by block hash, 64-entry LRU) and answers "output not
  available yet"; retries answer from the cache. Like base/base, the proof is not verified.
- `base_upgradeReadiness` answers from the node's upgrade-signal observer (finalized reads every 15 min by default) instead of a fresh L1 read per query (base/base, 5 s cache), because the router is synchronous. The node only observes schedules (metrics-only), so without a target version it reports not ready, as base/base does in that mode.
- Unsafe block signer: base/base reads the L1 SystemConfig once at startup (blocking, with retries); we poll it every 60 s without blocking startup, and until it answers validate against the fallback (chain config, flag, own sequencer key; zero when only L1 can tell, which rejects gossip until it does).
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

- L1 blob schedule (L1 info deposits' blob base fee): the node takes its built-in L1's
  Prague, Osaka and BPO forks by `l1_chain_id` (`L1BlobSchedule.of_l1`, shared with the proof
  client and derive-check). An unknown L1 keeps Cancun's fraction and logs a warning; base/base
  needs an L1 chain config for such chains, which this node does not read yet.
- Post-Canyon EIP-1559 parameters for all-zero Holocene `eip1559Params` in consolidation: the
  built-in chain's by `l2_chain_id`, else Base mainnet's (the rollup JSON's `chain_op_config`
  is not read).

## el-run engine (M5 integration)

`base el-run --engine.addr IP:PORT --engine.jwt FILE` serves the Engine API to a verifier
`base consensus`, so derived safe attributes are consolidated against blocks el-run executed
from devp2p. Semantics (`bin/base/el_engine.zig`):
- `engine_newPayloadV1..V4`: version and shape checks as op-reth (`validate_new_payload`),
  then the payload must hash to its `blockHash` (else INVALID). At or below el-run's head:
  VALID when el-run's block at that number has that hash, else INVALID and a loud
  `ENGINE DIVERGENCE` line (derivation or gossip disagrees with the devp2p chain). Above the
  head: SYNCING (no execution). Older than the ring and the database's canonical index:
  SYNCING (cannot judge, counted as `unjudged`).
- `engine_forkchoiceUpdatedV1..V3`: VALID when the head is an executed block and safe and
  finalized (zero = unset) are executed blocks at or below it; the labels are recorded and
  printed in el-run's 10 s summary (`engine: head .. safe .. finalized ..`). SYNCING when one
  is unknown; -38002 when out of order; attributes on a VALID update: -38003 (verifier only).
- `eth_getBlockByNumber` (number, latest/pending, safe, finalized, earliest) and
  `eth_getBlockByHash`, hashes or full transactions, from the ring; `eth_chainId`,
  `eth_blockNumber`, `engine_exchangeCapabilities`, `engine_getClientVersionV1`. An executed
  block that left the ring is -32000 naming the ring range, never a wrong block; above the
  head or an unknown hash is `null`. Not served (-32601): `engine_getPayload*`,
  `engine_getPayloadBodies*`, `eth_getProof`, state reads. The verifier does not call them on
  Isthmus+ chains (output roots come from the header's `withdrawalsRoot`; `eth_getProof` is
  only for pre-Isthmus `optimism_outputAtBlock`). Do not run the consensus node with
  `--sequencer`.
- Ring: the database keeps 1024 headers and no bodies, while the Sepolia safe head trails
  the tip by 2,000-5,000 blocks and a pipeline reset walks back about 3,100 more. The ring
  keeps the last `--engine.ring-blocks` (default 16,384) executed blocks, header RLP and
  EIP-2718 transactions, in `--engine.ring-mb` (default 512) MiB, filled by the per-block hook
  `block_committed(run, *const el_source.Block)` in `el_run.zig`. Both bounds evict oldest
  first; a non-consecutive block restarts the ring. Memory is committed as it is written.
- Unset safe/finalized: until a forkchoice update names them, `safe` and `finalized` answer
  an anchor `min(8192, count / 2)` blocks below the newest ring block, pinned at first use, so
  the consensus node's startup walk and reset walk-back stay inside the ring. Until the ring
  holds 16,384 blocks (or has evicted by bytes) they answer a "warming up" error; the
  consensus node retries. So start `base consensus` once el-run's summary shows a full ring
  (about 55 min at the tip at 200 ms blocks). A forkchoice label whose block has left the ring
  is dropped and the tag answers the anchor again, so a consensus node restarted after a long
  stall starts without an el-run restart.
- Single-threaded: the HTTP server runs on its own completion IO, driven by el-run only
  between blocks (non-blocking `poll`) and during the idle wait at the tip (`wait` replaces
  the 100 ms sleep). Requests never run while the runner executes or commits, and the engine
  is a plain state machine tested over SimIo. At the tip el-run also serves for 30 ms after
  every block (`tip_serve_ms`): following one peer, the feed waits for the next block inside
  `next`, so the idle wait can go unused for hours, and one `poll` per block held a Base
  mainnet verifier's consolidation near 1 block/s (2026-11-11). Behind the tip, `poll` only.
- JWT: HS256 bearer token with `iat` within the window (`utilities.jwt`), 401 otherwise.

Run (paths are examples; the JWT secret is a runtime file, never committed):

    openssl rand -hex 32 > /tmp/el-engine.jwt
    base el-run --db DB --peers PEERS --chain base-sepolia \
        --engine.addr 127.0.0.1:8551 --engine.jwt /tmp/el-engine.jwt \
        --engine.rollup-out /tmp/base-sepolia-rollup.json
    # once the summary's engine line shows ring 16384 blocks:
    base consensus --rollup-config /tmp/base-sepolia-rollup.json \
        --l1 http://127.0.0.1:PORT --l1-beacon http://127.0.0.1:PORT \
        --l2 http://127.0.0.1:8551 --l2-jwt /tmp/el-engine.jwt \
        --p2p.disabled --rpc.port 7545

`--engine.rollup-out` writes the chain's built-in rollup config (the one `derive-check`
derives with) as rollup.json. `base rollup-config --chain base-sepolia|base-mainnet --out
FILE` writes the same file without a database, to prepare a consensus node before el-run's
first start. `--p2p.disabled` keeps the first run to derivation: with gossip
on, gossiped blocks above el-run's head answer SYNCING and the consensus unsafe head then
moves only by consolidation (the adopt-existing-block path), which also works.

## el-run JSON-RPC, archive, pool

`base el-run --rpc` (127.0.0.1:8545; `--rpc.addr IP:PORT` for another) serves the common
methods from what el-run itself executed, never proxied (`bin/base/el_rpc.zig`):
`web3_clientVersion`, `net_version`, `eth_chainId`, `eth_blockNumber`, `eth_gasPrice`,
`eth_maxPriorityFeePerGas`, `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
`eth_getStorageAt`, `eth_call`, `eth_getProof`, `eth_getBlockByNumber`/`ByHash`,
`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockReceipts`,
`eth_sendRawTransaction`, `txpool_status`. Decisions:
- State at the head reads the database; at an older block it reads through the archive
  (`--archive <file>`, `bin/base/el_archive.zig`, `execution.archive`). Outside the archive's
  window the answer is -32000 naming the window, never an answer from the wrong state.
  `eth_getProof` walks the branch records (`DiskState.prove`, `prove_at` for older roots;
  byte-identical to the in-memory trie's proofs in `disk_state_test`). `eth_call` gas is
  capped at 50M and runs in the target block's environment.
- Archive design: a bounded window, not a full archive. Per block it appends one unit:
  header, transaction hashes, the block's record, and the old value of every key the block
  wrote (accounts and branch records from `DiskState.capture_enable`, slots from the
  changeset). Units sit in a ring in one fixed-size file (`--archive.size-gb`, default 512,
  min 8), grouped in segments of 8,192 blocks; a sealed segment gets a sorted fingerprint
  index (4 KiB pages, fences, a Bloom filter), the open one an in-memory hash chain. The
  oldest segment is evicted when the file is full. A view (`DiskState.view_begin`) reads
  the trie from the old state root and each key from the first archived block after it that
  changed it, else the head. Numbers (Base mainnet, 23,754 blocks from 54528125): 343 KiB
  per block, 141 GiB a day, so 512 GiB holds about 1.5M blocks (3.6 days). A full archive
  of 56M blocks would be about 20 TB, ten times the 1.9 TB head database, and a snapshot
  node never executed the older blocks. Tip cost: the append is one sequential write per
  block (synced every 64) after the commit, timed in the `archive:` summary line; block
  execution with the capture on had the same p50 (20 ms) over the same blocks as the live
  node. The archive never stops the node: an unusable capture or an oversized block
  restarts the window at the next block; at startup it is cut back to the database head.
- Blocks, transactions and receipts come from an RPC ring filled by `block_committed` with
  the executed receipts (`import.run.Outcome.receipts`): one `node.chain.Record` per block
  (header, transactions, receipts), `--rpc.ring-blocks` 16,384 / `--rpc.ring-mb` 1024,
  committed as written, plus a lossy 4-way transaction hash index (`--rpc.tx-index`, 2^21
  entries, 48 MiB) whose hits are checked against the stored bytes; past the ring, from the
  archive's records. Blocks held by neither are -32000 naming the range; above the head or
  unknown: `null`. The ring starts empty at every start.
- Transactions: `eth_sendRawTransaction` checks (chain, signature, intrinsic gas, fees) and
  adds to `txpool.Pool` (by sender and nonce against the head; `txpool_status`, `pending`
  nonce, pending transactions by hash). After each block the pool drops included
  transactions and re-reads those senders, and every 64 blocks all senders. With
  `--rollup.sequencer-http <url>` (`bin/base/el_sequencer.zig`, base/base and op-geth's
  flag) it also forwards to the sequencer on one of 8 `std.Io` tasks and answers with the
  sequencer's answer (the parked HTTP response resumes in `Service.prepare`). Fee
  suggestions are op-geth's: tip 0.001 gwei, gas price = head base fee + tip (matches
  mainnet.base.org).
- `safe`/`finalized` are the Engine API's last valid forkchoice labels (needs
  `--engine.addr`); otherwise an error.
- Same model as the Engine API: own completion IO, polled between blocks and in the idle
  wait at the tip (10 ms slices alternating with the engine's IO when both run). No request
  runs while a block executes or commits, and the database stays single-threaded.
  Limitation: while a catch-up download waits for peers (`Pool.next`, up to 5 min) requests
  wait too; at the tip the feed does not block.
- Not yet: `optimism_syncStatus` (needs the consensus node's labels), logs/filters.

## Log
- 2026-11-12: el-run history and transactions: the archive window (`--archive`), state,
  proofs and `eth_call` at older blocks, blocks past the ring, the pool, and sequencer
  forwarding (`--rollup.sequencer-http`). Checked on a copy of the mainnet database over
  23,754 archived blocks against mainnet.base.org (1,734 state answers by number and hash;
  blocks, transactions, receipts from the archive) and base.drpc.org (20 proofs, exact). A
  signed transaction forwarded to mainnet-sequencer.base.org came back with its error.
- 2026-11-08: verifier on el-run (Base Sepolia): consolidation now warns with the first
  attributes mismatch per block. It showed `transaction_content` at index 0, the L1 info
  deposit: the node priced blob fees with Cancun's fraction (block 56166090: 11 instead of 2).
  Fixed with the L1's own blob schedule; chain fee params fixed alongside.
- 2026-11-08: el-run read-only JSON-RPC (`bin/base/el_rpc.zig`, `--rpc`): head state, head
  proofs over the disk records, and blocks/transactions/receipts from an RPC ring; compared
  against the public Base Sepolia RPC.
- 2026-11-08: el-run Engine API (`bin/base/el_engine.zig`, `el_ring.zig`): newPayload
  judged against executed blocks, forkchoice labels in the summary, full blocks from a
  16,384-block / 512 MiB ring, anchor for unset safe/finalized; a consensus `EngineClient`
  drives it over SimIo and the production IO in tests.
- 2026-11-05: paused for replay focus (owner decision). Next on resume: ungated swarm seeds 992, 2258, 2622.
- 2026-11-05: reorg: safedb reset records are flagged (in memory) and trusted only without a newer orphaned entry; a shadowed one is the cap before finalized. Gated 3000/3000; ungated 2997/3000 (992, 2258, 2622).
- 2026-11-05: reorg: `driver.SafeCheck` checks the safedb against canonical L1 before discovery and caps the safe label at the newest supported safe head (finalized when none; unknown blocks wait, 3000-tick budget). The sim real verifier keeps its safedb across restarts (`--safedb.path`); the cluster's safe-decrease check re-latches on driver resets. Seed 850 and 15/16/2562/2856/329 pass with the batcher gate removed; gated 3000-seed sweep clean, ungated 2997/3000.
- 2026-11-05: rpc: `service/forwarding.zig` forwards single HTTP JSON-RPC calls for methods the router does not serve to `--rpc.execution-forwarding-endpoint` (deferred responses, 4 keep-alive clients, -32603 on failure or when all are busy).
- 2026-11-05: rpc: `--rpc.disabled` starts no HTTP or WebSocket RPC server (`Options.rpc_address` is optional; `start` returns null and logs "rpc disabled").
- 2026-11-05: safedb: `service/safedb_store.zig` persists the L1->safe-head entries (`--safedb.path`) as one crc-checked image (`magic | count | 80-byte records | crc32`) through `store_file`; `SafeDB.version` drives writes; the driver waits for the load.
- 2026-11-05: devnet smoke passes at native 200 ms blocks on main (Denim at genesis from batcher-devnet, EL fixes from node): 25 blocks/5 s, verifier derives, load test 99/99.
- 2026-11-05: confs: `service/conf_depth.zig` hides L1 blocks within N of the head from derivation (`--l1.verifier-confs`, no head: no gate) and from sequencer origin selection (`--sequencer.l1-confs`, default 4, no head: nothing); `--sequencer.recover`.
- 2026-11-05: 200 ms devnet trial (local, uncommitted Denim genesis): EL rejects same-second FCU attrs and lacks Base upgrades from genesis; handed to the node and batcher-devnet lanes.
- 2026-11-05: derive: end-to-end pipeline test of native 200 ms Denim blocks (singular batches sharing a second, BaseTimeUpdateTx millis).
- 2026-11-05: sequencer: native 200 ms cadence: driver ticks in ms; subsecond blocks build from the parent's timestamp and seal 150 ms into the slot (base/base `block_seal_target`); stop discards a waiting payload.
- 2026-11-05: rpc: `admin_*` only with `--rpc.enable-admin`, `dev_*` (and the engine queue ws subscription) only with `--rpc.dev-enabled`, else -32601; devnet sequencer enables admin for the batcher's leader check.
- 2026-11-05: rpc: WebSocket requests use the node's merged router (opp2p_* included); devnet verifier serves metrics and smoke checks the safe-head metric (not run: ports held by another devnet).
- 2026-11-05: rpc: admin error codes and idempotent start/stop match base/base.
- 2026-11-05: rpc: WebSocket RPC (--rpc.ws-enabled/--rpc.ws-port): head and engine queue size subscriptions, router fallback.
- 2026-11-05: sequencer: op-conductor client: seals commit before insert, leader-gated admin_startSequencer (-32002), overrideLeader forwarded, --sequencer.stopped.
- 2026-11-05: service: follow mode (--source-l2-rpc): source blocks inserted in order, safe/finalized labels verified against local blocks and promoted.
- 2026-11-05: service: Prometheus /metrics (--metrics.enabled/addr/port): block labels, queue depth, driver counters.
- 2026-11-05: rpc: admin_overrideLeader, admin_refreshUpgradeSignal, dev_taskQueueLength; backlog extended.
- 2026-11-05: engine: startup recovers pruned safe/finalized heads from checkpoints or the earliest unpruned block.
- 2026-11-05: service: durable safe/finalized checkpoints behind `--checkpoint.path`.
- 2026-11-05: service: derivation and sequencing wait for EL sync, probing the engine every 2 s.
- 2026-11-05: rpc: pre-Isthmus optimism_outputAtBlock from cached eth_getProof storage roots.
- 2026-11-05: protocol: span batches carry EIP-8130 transactions (base/base `SpanBatchEip8130TransactionData`).
- 2026-11-05: engine: payload bodies by hash/range and capability exchange on the engine client, with codecs and fuzz.
- 2026-11-05: rpc: `base_upgradeReadiness` evaluates the L1 upgrade-signal schedule with base/base's readiness predicates.
- 2026-11-05: service: `SignerWatcher` reads the unsafe block signer from the L1 SystemConfig storage slot and updates gossip validation on change.
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
