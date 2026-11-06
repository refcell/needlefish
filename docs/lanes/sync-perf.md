# Lane: sync-perf

Owns `src/execution/sync/*` (new), the `sync` / `import` / `export` subcommands of
`bin/base`, and sync/throughput benchmarks under `src/execution/sync/bench*.zig`.
Perf changes inside other lanes' directories (evm, trie-db, node, io) go through small,
measured edits with a benchmark before/after, and a message to the owning lane.

Scope: get a fresh needlefish node from genesis (or a snapshot) to the Base tip fast,
then make block import as fast as the hardware allows. No flashblocks (AGENTS.md rule 10).

Reference (public base/base): `crates/execution/node` (reth staged pipeline via
`reth-stages-types`, `storage.rs`), `crates/execution/cli` (import/export, datadir),
`crates/consensus/engine/src/sync` (EL-sync vs consensus-sync, checkpoint/forkchoice
sync start), `crates/consensus/service` (engine request processor, EL sync handling),
`crates/infra/snapshotter` (snapshot layout, tip, progress). Public reth docs for stage
order (Headers, Bodies, SenderRecovery, Execution, MerkleExecute, AccountHashing,
StorageHashing, Merkle, TransactionLookup, IndexHistory, Finish).

## Backlog
- [ ] Design doc section below: stage order, checkpoint format in the existing db
  (`src/execution/db/storage`), and how `engine_forkchoiceUpdated` to an unknown head
  triggers EL sync (base/base returns `SYNCING` and backfills). Decide and record.
- [ ] `sync/stages`: staged-sync driver over an injected IO interface: bounded stage list,
  per-stage checkpoint, unwind on reorg, resumable after crash. DST test: random crash
  points, same seed same result, final state root equals straight-line execution.
- [ ] Headers + bodies stages fed by an L2 block source interface (trusted L2 RPC
  `eth_getBlockByNumber` with full txs first; reuse `src/consensus/sources`), bounded
  in-flight window, hash-chain validation backwards from the target head.
- [ ] Sender-recovery stage: batch secp256k1 recovery across a fixed worker pool, results
  written in block order; benchmark txs/s vs the inline path.
- [ ] Execution stage: execute in batches with one db commit per N blocks (configurable),
  defer trie hashing to the Merkle stage; benchmark blocks/s on a devnet-generated chain.
- [ ] Merkle stage: incremental state root from changesets for the whole batch, assert it
  equals the header state root at the batch end; precise repro on mismatch.
- [ ] EL sync wired into the node: FCU to an unknown head returns `SYNCING`, starts the
  pipeline toward it, then `VALID` once caught up; consensus driver handles it (small edit
  coordinated with nf-consensus). Sim + devnet test: a verifier started late catches up.
- [ ] `base import` / `base export`: RLP block file import (reth/geth format) through the
  pipeline; export a range. Round-trip test.
- [ ] Snapshot restore: datadir snapshot manifest (tip, block, state root) in the shape of
  base/base `snapshotter` (`tip.rs`, `progress.rs`); restore + verify, then sync on top.
- [ ] Perf: io_uring batched/linked writes and fsync coalescing for the commit path
  (Linux), kqueue fallback; measure commit latency p50/p99.
- [ ] Perf: optional huge pages (`MAP_HUGETLB` / madvise) for the large static arenas
  (state cache, trie node cache), behind a flag; measure TLB-miss-sensitive benches.
- [ ] Perf: prefetch state for the next block's txs (access-list + sender/recipient
  warmup) on a worker while the current block executes; then evaluate optimistic parallel
  execution with conflict detection (Block-STM style), deterministic fallback to serial.
- [ ] Sync throughput benchmark target `zig build bench-sync`: generate N blocks on the
  devnet profile, sync from scratch, report blocks/s, gas/s, and per-stage time.

## Decisions

## Log
