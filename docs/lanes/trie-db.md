# Lane: trie-db

Owns `src/execution/{trie,db}`. Reference: reth trie/db, base/base `crates/execution/trie`.

## Backlog
- [x] Witness header ancestry verification (DST-found soundness gap): `SparseState` trusted
  each witness header's number, so a hostile witness could forge BLOCKHASH. Now bound to the
  verified block's parent (`reset(pre_root, parent)`): headers strictly decoded, contiguous
  and ascending, parent-hash linked, ending at the parent with the pre-state root.
  (`db/witness.zig` `header_link` / `verify_headers`, `db/witness_header_test.zig`)
- [x] Merkle Patricia Trie: node encoding (RLP), in-memory trie, root computation, proofs (eth_getProof), ordered-trie root for tx/receipt/withdrawal roots. No recursion. Vectors from ethereum/tests TrieTests.
- [x] Fast incremental state root: sorted batch updates, parallel hashing of subtries, cached branch nodes.
- [x] Storage engine (own design, TigerBeetle-inspired): append-only data file + fixed-size block grid or LSM, checksummed blocks, crash-safe superblock, all disk I/O through `utilities.io` (io_uring on Linux), static memory budget. Flat account/storage tables + history for reorgs.
- [x] State provider implementing the evm `Host` backend: accounts, storage, code-by-hash, block hashes; overlay/journal for pending block execution; commit + state root.
- [x] Block/receipt/header storage and canonical chain indices; reorg (unwind) support.
- [x] Fault injection tests on the simulated disk (torn writes, corruption, crash at any point) — state must recover to last committed block.
- [x] Benchmarks: state root of N updates, random reads, commit latency. (`trie/bench.zig`;
  `db/bench.zig`: block apply+root, changeset codec, commit-until-durable p50/p99, checkpoint)
- [x] Durable database facade (`db/database.zig`): journal block/head entries, state moves
  only on head moves, checkpoints = State snapshot + chain blocks, crash-recovery tests.
- [x] Real storage backend over `utilities.io` (io_uring/kqueue): `db/storage/io_storage.zig`.
- [x] Checkpoint fallback / redundancy so one rotten checkpoint block is not data loss.
- [x] Batch keccak (crypto lane's SIMD batch, 74 vs 146 ns) for sibling nodes in
  `update_cache`.
- [x] Storage-heavy block root is slow: 1k accounts + 4k slots over 100k accounts = 13 ms
  (vs 2 ms for 1k accounts alone). Profile storage trie rehash/creation and fix.
  (10.3 -> 7.9 ms; the rest is real trie work, docs/PERF.md)
- [x] Parallel storage-trie rehash: in a storage-heavy block, hashing dirty storage tries
  (~2.4 ms) and the account trie (~1.8 ms) is now over half the block. Split the dirty storage
  roots across worker threads (one pool, disjoint subtries).
  (`rehash_threads`, default 0; db/block 8.05 -> 6.87 ms at 4 threads, docs/PERF.md)
- [x] One fsync per `execute_and_commit`: journal block + head as one entry (was 2 fsyncs,
  ~7.5 ms durability cost per block).
- [x] Compact node layout (packed paths, per-kind body, cached refs out of line).
- [x] Historical proofs store (base/base `crates/execution/trie`, `BaseProofsStore`): per-block
  versioned account/storage leaves + trie node preimages for a retention window, so
  `eth_getProof` works at any block in the fault-proof window without re-execution.
  (`db/history.zig`; in memory, rebuilt from retained changesets on open, see Decisions)
- [x] Window pruner: bounded work per tick, removes history older than the window; crash-safe
  by rebuild (history is in memory; rebuilt on open from retained changesets, see Decisions).
  (`Store.prune_step(budget)`, tombstones free deleted paths, atomic `commit_block`)
- [x] Execution witness (`debug_executionWitness`): touched trie nodes + codes + headers for a
  block, verified by re-executing statelessly against a sparse trie built from the witness.
  (`db/witness.zig`, `trie/sparse.zig`; verification replays reads + the block's changeset,
  `SparseState.database()` is the evm backend for real stateless re-execution)
- [x] Differential tests: historical proof at block N == proof from a State unwound to N;
  witness-only re-execution root == stored root (base/base `witness_differential`).
  (historical half: `db/history_test.zig`; witness half: changeset replay in
  `db/witness_test.zig`, real evm re-execution over `SparseState` in
  `db/witness_evm_test.zig`)
- [x] Witness entry point for the node: move the durable database to the block's parent
  (`set_head`, no re-journal), wrap the evm Database with `witness.Recorder`, run the caller's
  executor (`node.Executor.execute_block` over the recorded database), build the witness,
  restore the head. Bounded scratch; refuses blocks outside retention.
  (`db/witness_block.zig`: `Generator.generate` / `database_witness`; in-memory unwind of
  stored changesets instead of `set_head`, see Decisions)
- [x] `debug_executionWitness(block)` handler in `rpc/debug.zig` (small additive integration
  edit in the rpc lane) returning `{state, codes, keys, headers}` as hex arrays.
  (`node/witness.zig` + `Journal.witness` hook, `Executor.execute_uncommitted`,
  `StateDb.recent_changesets`, `Api.witness`, `Limits.witness`)
- [x] Feed the history store from the durable database: every head move (apply/unwind) updates
  `history.Store`; rebuilt with `reset` at open; `Database.proof_at(block, address, slots)`
  for `eth_getProof` with a block tag inside the window.
  (`Config.history`, `history_drops`/`history_off`; `Journal.proof` + `eth_getProof` at older
  canonical blocks of the window on durable nodes, small additive node/rpc edit)
- [x] Node canonical index after a reorg back (node lane, found here): `Chain.mark_canonical`
  stops at the first matching entry, so after head A6 -> side B5 -> A6 the number index still
  maps 5 to B5 (number-tagged RPCs resolve the side block). Clear entries above a lower head.
  (fixed by the node lane: `BlockStore.clear_canonical_above` + regression test + chain fuzz)
- [x] Witness codec for the proof lane: canonical binary encoding of a `Witness` (strict
  decoder, encode(decode(x)) == x) plus a keccak256 preimage view (iterator + lookup by digest).
  (`db/witness_codec.zig`)
- [x] Witness size + build-time benchmarks (nodes, bytes, us per block) for 1k-account and
  storage-heavy blocks; record in docs/PERF.md. (`db/witness_bench.zig`, `-- db/witness`;
  plus a 200-call evm block; docs/PERF.md "db witness")
- [x] `SparseState.reset` / `SparseTrie.clear` is O(pool capacity): ~370 us per reset for a
  104k-node pool, paid by every `Builder.build` and verifier load. Clear only used nodes
  (or track a high-water mark). (high-water mark + free list in `trie/sparse.zig`, landed
  with the witness memory change: `clear` is O(1))
- [x] `Builder.build` is 4-5x a full-state block apply (30.7 vs 8.2 ms storage-heavy): proves
  every key separately, then replays on a sparse trie. Share proof walks (sorted keys, one
  descent) or build the witness from the full trie's dirty-path walk.
  (sorted multi-key walk: see "Faster `witness.Builder.build`")
- [ ] (blocked: base/base commits no reth witness fixtures and running reth is out of scope)
  Byte-compare our `debug_executionWitness` against reth's output for public fixture blocks;
  revisit when public fixtures exist. Meanwhile: the `witness-diff` port below.
- [x] `witness-diff` tool (port of base/base `etc/tools/witness-diff`): compare two witness
  JSON files (or one file vs a node's `debug_executionWitness`), report differing trie nodes,
  codes, keys, and the accounts/slots whose leaves diverge.
  (`db/witness_diff.zig` + `db/witness_diff_test.zig`, binary `bin/witness-diff/main.zig`:
  `witness-diff --local FILE (--remote FILE | --rpc-url URL --block N)`)
- [x] Witness generator memory: default limits allocate ~40-60 MB at node start even if
  `debug_executionWitness` is never called; size from limits more tightly or allocate through
  `utilities.lazy_alloc` (node lane pattern). Large witnesses can exceed the 1 MiB HTTP buffer.
  (lazy buffers in `db/witness.zig`, `db/changeset.zig`, `trie/sparse.zig`; derived config in
  `Limits.witness_config`; "witness too large" in `rpc/debug.zig`; measured by
  `node/witness_memory_test.zig`)
- [x] Witness generation blocks the state for one unwind + re-apply per block between target
  and head; consider generating from the history store instead (no state disturbance).
  (`witness_block.Generator.generate_history` / `database_witness_history`, preferred by
  `database_witness`; `witness.HistorySource`; history walks in `history.Store`)
- [x] Faster `witness.Builder.build`: 4-5x the cost of applying the block (30.7 vs 8.2 ms on
  the storage-heavy block); collect proof nodes in one sorted multi-key trie walk instead of
  one proof per key, and skip the sparse replay when the caller does not need the root.
  (`trie/path_targets.zig`, `TrieType.visit_paths_in`, `history.Store.walk_paths`,
  `Builder.build_with` + `BuildOptions.verify_root`; storage-heavy build 36.9 -> 15.8-16.0 ms
  verified, 4.6-4.7 ms unverified; byte-identical witnesses checked against the old
  collection by `db/witness_differential_test.zig`; docs/PERF.md "db witness")
- [x] Witness build with `verify_root` is now dominated by the sparse apply (~9 ms of 16 on
  the storage-heavy block: node resolution + RLP decode + per-write keccak of slot and
  address keys) and the post-root (~2.6 ms). Pass the hashed keys the walk already computed
  into the apply, and batch-hash keys with `keccak256_batch`.
  (`SparseState.apply_hashed` + `ChangesetHashes` from `Builder.hash_keys`; batched
  `SparseTrie.update_root_refs`; one account lookup per storage run; storage-heavy build
  15.7 -> 12.5 ms, verifier replay 9.9 -> 8.2-9.4 ms; docs/PERF.md "db witness: hashed keys")
- [x] The verified witness build is still ~8 ms of sparse apply on the storage-heavy block,
  split between node keccak, RLP decode (~15k pool nodes resolved, `decode_node` again for
  dirty branches' unloaded children at rehash) and pool-node copies. Cache decoded child refs
  or decode lazily per item.
  (unloaded child slots hold item offsets into the parent preimage, one-pass branch decode,
  direct dirty-branch encoding, digest-keyed maps; storage-heavy build 16.1 -> 10.8 ms,
  replay 9.6 -> 6.4 ms under load; docs/PERF.md "db witness: sparse apply without
  re-decoding")
- [ ] The sparse apply is now keccak-bound: ~32% of the storage-heavy verified build is the
  rehash of ~15k dirty nodes (two lanes per `keccak256_batch` on NEON) and ~13% is `resolve`
  (branch scan + first touch of each preimage). Options: a wider software batch on aarch64
  (4 lanes over two NEON registers), or skip the post-root rehash where a caller only needs
  the witness (`verify_root = false` already does).
- [x] Witness responses over 1 MiB: the storage-heavy witness is 1.28 MB binary (2.6 MB hex);
  size the rpc response buffer for witnesses or stream the JSON.
  (shared lazy large send buffers in `http.server` (`Options.large_send_buffers_max/size`,
  grown on a body-writer rebase); `debug_executionWitness` sizes with `ensureUnusedCapacity`;
  node default 2 x 16 MiB, `witness_response_bytes_max` 16 MiB - 2 KiB;
  `rpc/debug_http_test.zig`, `http/large_test.zig`, `node/witness_memory_test.zig`)
- [x] End-to-end rpc test with a real witness over 1 MiB (storage-heavy fixture block) through
  the large send buffers; today only a 3 MiB generic response covers that path.
  (`rpc/debug_large_test.zig`: code-heavy block instead of storage-heavy, see Log)
- [x] Persist the history window across restarts: today `open` resets history at the head,
  so `eth_getProof` / witnesses for older blocks are unavailable until the window refills.
  Rebuild the window on open by replaying retained blocks' changesets from the checkpoint
  (or checkpoint the history store), bounded by the window.
  (`Database.history_rebuild_window`, `Config.history_rebuild_on_open`; rebuild from
  retained changesets, see Decisions; `db/database_history_test.zig`)
- [x] Linux io_uring run of the storage engine: run `IoStorage` engine/database tests under
  `just test-linux` (Docker) and fix any backend differences (fsync vs fdatasync, short
  writes); record results. (all green on io_uring, no fixes needed; see Decisions and Log)
- [x] Read-path benchmark for the EVM backend: `State.basic` / `storage` / `code_by_hash`
  hit/miss latency on 100k accounts and the overlay read path; compare with trie `get`.
  (`db/read_bench.zig`, `-- db/read`; docs/PERF.md "db reads")
- [x] evm backend `basic` hit costs ~330 ns (vs 17 ns for `State.basic`): it keccaks the
  address on every hit only to answer `has_storage` from `StateTrie`. Keep a has-storage
  flag (or slot count) per account in `State` so the vtable read stays a table lookup.
  (`State.AccountEntry.storage_slots`, see Decisions; `db/has_storage_test.zig`; docs/PERF.md
  "evm backend `basic` without keccak")
- [x] Enable parallel rehash in the node: set `rehash_threads` from the CPU count (as the
  sender-recovery threads do), keep 0 under DST/sim; measure the commit path end to end.
  (`--rehash-threads`, auto min(cores - 1, 4); db/commit sim cpu p50 7.81 -> 6.79 ms, PERF.md)
- [x] History memory budget at 200 ms blocks: measure bytes per retained block in
  `history.Store` (storage-heavy and typical blocks), express the window as wall-clock span
  at 5 blocks/s, add a byte budget (`Config.history_bytes_max`) that shrinks the window
  (pruning oldest) instead of dropping history on overflow; record in docs/PERF.md.
  (`history.Config.bytes_max`, `Store.fit_budget`/`bytes_used`/`window_shrinks`,
  `db/history_bench.zig`; typical 2.82 MiB/block, heavy 4.68 MiB/block; node default
  window 300 = 60 s, `Limits.history_bytes_max` 1 GiB; see Decisions, PERF.md)
- [x] Multi-key historical proofs sharing one walk (base/base `cursor_cache.rs` analogue):
  `eth_getProof` with many storage keys at an older block walks the history trie once per
  key; reuse `path_targets` + `history.Store.walk_paths` for one sorted walk per trie.
  (`db/proof_set.zig`, `history.Store.get_proofs`/`walk_frames`, `Database.proofs_at`,
  `Chain.proofs_at` + `Journal.proofs`, historical `rpc/eth_proof.zig`; 1 account + 64 keys
  344-384 -> 48-56 µs, + 256 keys 1307-1314 -> 96-98 µs; docs/PERF.md "db history:
  multi-key"; see Decisions)
- [x] History commit is the largest step of a 200 ms slot on heavy blocks (34 ms p50,
  117 ms max for 1k acct + 4k slots; ~12 ms typical): profile `history.Store.commit_block`
  (version allocation, path index probes, node re-encoding) and cut it, or move it off the
  block's critical path (commit history after the head commit is durable, bounded queue of
  one block, proofs at the newest block wait or fall back to live state).
  (`TrieType.clear_changes` replaces the drain walk; version kind/mask/fingerprint;
  `db/path_index.zig`; interleaved medians heavy 17.0 -> 5.7 ms p50, typical 10.0 -> 3.8 ms;
  stays on the critical path, see Decisions and PERF.md)
- [ ] Checkpoint stalls at 200 ms blocks: measure the durable commit latency distribution
  (p50/p99/max) over thousands of blocks on a real file (`IoStorage` over the os backend),
  including the blocks that trigger a checkpoint; if a checkpoint's state write exceeds the
  slot budget, spread it over commits (incremental checkpoint chunks per commit) so no
  single commit stalls. Crash tests must still pass.

## Decisions
- Local minimal RLP in `trie/rlp.zig` (strict, canonical-only decoder) until `common/rlp` lands;
  switch over then.
- Two trie engines: `HashBuilder` (alloy-trie algorithm, streaming, sorted input, accepts
  subtrie hashes) for ordered roots and DB-driven state roots; `TrieType` (fixed node pool,
  cached `RlpNode` per node, dirty-path rehash) for in-memory incremental roots and proofs.
  They are fuzzed against each other.
- `HashBuilder` borrows the latest leaf value (no copy) until the next call.
- Proof format matches geth `eth_getProof`: root plus hashed nodes; embedded nodes stay inline.
- Public TrieTests JSON vectors committed under `trie/testdata/` (small, public).
- One trie pool hosts many roots (`*_in` APIs): all storage tries share a pool sized at init.
- `StateTrie` takes hashed keys; writes mark accounts dirty, `root()` rehashes dirty storage
  tries and applies dirty accounts sorted.
- Node rehash workers: `state_db.Config.trie.rehash_threads` reaches `db.State` through
  `StateDb.state_config` (in-memory and durable nodes alike). `base node` sets it to
  `state_db.rehash_threads_auto(cores)` = min(cores - 1, 4), like the sender-recovery threads
  (min(cores - 1, 7)) but capped at 4 because 8 threads gained nothing over 4 (PERF.md); the
  two pools run in different block phases, so they do not compete. `--rehash-threads N`
  overrides (0 disables, > 16 rejected). `Service(SimIo).init` asserts 0, so DST cannot
  start threads; tests and benches default to 0. The pool joins in `State.deinit`, which
  `Service.deinit` reaches through `StateDb.deinit` or the durable database.
- Parallel storage rehash (`StateTrie.Config.rehash_threads`, `db.state.Config`): default 0,
  so DST, the simulator and tests not asking for it stay single-threaded. With N > 0 a static
  pool (`trie/rehash_pool.zig`) is spawned at init and sleeps on a futex (`std.Io.Threaded`'s
  OS futex, synchronization rather than I/O). `flush` collects dirty nodes serially (per-trie
  end offsets, change marks), splits them at trie boundaries into <= 4 chunks per thread
  (cap 64, the bounded queue), and caller + workers claim chunks from a
  `generation << 32 | index` counter, then join before applying accounts and hashing the
  account trie. A chunk holds whole storage tries, so a worker writes only its chunk's
  `order` slice and its nodes' caches, with batch buffers on its own stack; results are
  bit-identical for any split. Fewer than 1024 dirty nodes hash on the caller. Claimed
  chunks, not one static range per thread: on a loaded machine workers lagged 3-4x behind
  the caller's share. The account trie and the collect walk stay serial.
- State provider (`db/state.zig`, `db/overlay.zig`): committed state is flat hash tables
  (EVM reads) mirrored into `StateTrie` (roots). Reads follow revm `Database`: `basic`,
  `storage`, `code_by_hash`, `block_hash` (256-entry ring). The EVM lane can adapt its Host
  to `Overlay` directly. Tx-level journaling/reverts stay in the EVM; the overlay is
  block-level.
- `Changeset` (`db/changeset.zig`) is the unit of commit, unwind, and journaling: old+new
  values, wipes spelled out per slot, sorted, canonical binary encoding (fuzzed).
- Code is content-addressed and never deleted on unwind.
- `ChainStore` keeps block contents as opaque bytes (header/body/receipts/changeset) in a
  fixed FIFO byte ring (bounded memory; older blocks are the storage engine's job), with
  hash/tx indices and a canonical ring. Reorgs: `plan_reorg` -> caller unwinds/applies
  state from stored changesets -> `set_head`. Side branches are executed by unwinding to the
  fork point (no historical-state overlay yet).
- EVM integration (`db/evm_backend.zig`): `database(&state)` is the evm vtable `Database`;
  `commit_evm` folds the evm's journaled block State into an Overlay with the same rules as
  `node/state_db.zig`, so the node can move to `db.State` and get changesets/unwind/snapshots.
- Storage engine (`db/storage/`): duck-typed sector Storage (callbacks only from `tick`),
  deterministic `SimStorage` (latency, reorder, crash with lost/kept/torn sectors, bit rot,
  read faults). Layout: 4 superblock copies (sectors 0-3, written one at a time with a sync
  each, highest valid sequence wins, repaired on open), checkpoint zones A/B, journal ring.
  AEGIS-128L MAC checksums. `format(format_id)` seeds all checksums/chain so stale data from a
  previous format never validates. Journal: hash-chained entries, logical positions, clean
  end vs corrupt classification, valid prefix accepted after torn tail. Checkpoints: pulled
  producer, per-block checksums. Journal space freed only after all superblock copies durable.
- `DatabaseType(Storage)`: one operation per journal entry (block insert, head move, or both);
  apply in memory first, journal only on success; state moves only on head moves; the
  database (not ChainStore) drives block retention so live and checkpoint-rebuilt stores
  match; checkpoints = header + State snapshot + retained blocks, started when the journal is
  half full and the queue is empty. Genesis = first `execute_and_commit` after format.
- `IoStorageType(IO)` (`db/storage/io_storage.zig`): Storage over `utilities.io` on a
  caller-owned fd (the binary opens/creates the file via `io.open_file`). Bounded IO completion
  pool (`operations_max`), overflow waits in an intrusive FIFO; short reads/writes resubmit
  the rest; EOF reads zero-fill (sparse/short file); read errors retry then zero-fill (engine
  checksums catch it); write errors retry then panic; fsync errors panic (fsyncgate). IO
  callbacks only queue; storage callbacks run from `tick()`, which calls non-blocking
  `io.tick()`. With `SimIo` the caller advances time (`io.run_for_ns`) before `tick()`.
- `IoStorageType(IO)`: caller opens/owns the fd (sparse files ok); bounded completions with
  FIFO overflow; short transfers resubmitted; read errors retried then zero-filled (checksums
  catch it); write errors retried then panic; fsync failure panics (no retry after fsync
  error); full fsync (F_FULLFSYNC on Darwin); callbacks only from `tick`.
- Publishing under contention: after a green `zig build test` on base B, a rejected push is
  retried without re-testing only when B..origin/main touches none of trie/db/evm/common/
  build.zig/base.zig (tidy still runs); anything else re-tests.
- `db/bench.zig`: commit latency is a closed loop (wait durable, then next block) with its
  own runner for percentiles (`run_commit`, takes `std.Io` for the clock); the OS case uses a
  scratch file under `.zig-cache/tmp/needlefish-db-bench`, deleted afterwards. Journal sized
  so rounds never trigger automatic checkpoints; checkpoints are timed separately.
- Compact trie node (`TrieType`): an `extern union` body per kind (leaf: packed path + inline
  value; extension: packed path + child; branch: 17 `u32` children), so a node is
  `4 + max(key_bytes + 1 + value_size_max, 68)` bytes; the cached `RlpNode` lives in a parallel
  `cache` array. Paths are stored packed in hex-prefix layout without the flag, so encoding is a
  copy plus the flag nibble and `get` compares leaf paths against the packed key bytes. A
  branch value is a leaf with an empty path in child slot 16, so branches carry no value
  buffer; a value branch now costs two pool nodes (only with prefix keys; fixed-length state
  keys never have branch values). Out-of-line values in a byte arena were not done: without a
  caller-given byte budget the arena must be sized for every node holding a maximal value
  (no saving over inline), and freeing variable-size values needs compaction or a general
  allocator. Account node 284 -> 186 B, storage node 204 -> 106 B (docs/PERF.md).
- Batched rehash: `TrieType` collects dirty nodes with their depth (explicit stack), hashes
  deepest level first, sorts each level by encoding length, and feeds equal-length encodings of
  32+ bytes to `keccak256_batch` (leftovers hash singly). Scratch is one `u64` per pool node,
  allocated at init. `update_caches(roots)` batches across tries of one pool; `StateTrie.flush`
  uses it for all dirty storage tries. `Config.hash_batched = false` keeps the old post-order
  walk as the fuzz reference. Kept because block roots got 19-24% faster (docs/PERF.md).
- One durable round trip per `execute_and_commit`: a third entry kind, `block_and_head` (block
  layout, own tag), replayed as `chain_insert` then `move_head`. Chosen over engine group
  commit (several entries per journal write + sync) because it keeps one operation = one
  entry = one sequence (TigerBeetle: one prepare per request), needs no engine change, and
  keeps Busy accounting at one entry. `block`/`head` stay for standalone `insert_block` and
  `set_head`. `Commit` now carries one `sequence`. If the head move fails after the in-memory
  insert (only a planning error can, and not for a child of the head), a plain `block` entry
  is journaled so replay stays in step. A block already stored only journals a `head` entry.
  Group commit stays an option if standalone insert+set_head pairs ever become hot.
- Checkpoint fallback (superblock version 2): the superblock also names the previous
  checkpoint (`checkpoint_previous`, `journal_start_previous`, `commit_metadata_previous`),
  and the journal tail is the previous checkpoint's start, so live entries span two
  checkpoints. A checkpoint's superblock demotes the replaced newest to the fallback and only
  then releases entries before the old fallback's start. Open streams the newest checkpoint;
  if it fails to verify, `Consumer.on_checkpoint_reset` drops the chunks already delivered,
  the fallback streams, and replay starts at the fallback's start. The fallback must replay
  at least up to the newest checkpoint's coverage (else `CheckpointCorrupt`); then the
  superblock is rewritten naming the fallback as newest (no distinct fallback), so the next
  checkpoint overwrites the rotten zone. Right after format, and after the first checkpoint,
  the fallback is the empty state with the journal from entry 1. Chosen over per-block parity
  (option b) because it is TigerBeetle's approach (the WAL covers the previous checkpoint),
  needs no new on-disk structure beyond superblock fields, and also covers a checkpoint lost
  to a misdirected write. Stream-then-reset instead of verify-then-stream keeps open at one
  read of the checkpoint. A first-to-verify transient read fault (4 retries) also falls back;
  harmless, the result is the same state. Two zones only: while a checkpoint writes into the
  fallback zone, only the newest checkpoint is recoverable (a third zone would close that
  window; not worth it for a double fault). The journal trigger is unchanged (`used` from the
  tail > half the journal), which now counts two checkpoints of entries, so checkpoints run
  about twice as often (each covers ~1/4 of the journal) and Busy/JournalFull clears after at
  most two back-to-back checkpoints.
- Witness evm differential (`db/witness_evm_test.zig`) drives the evm directly
  (`transaction.transact` over a `TxEnv` list), not the node executor: the executor takes
  signed RLP transactions over `node.StateDb` and adds system calls, so it has no entry over
  an arbitrary evm `Database`. `SparseState.apply_evm` folds the evm block state with the
  `commit_evm` + `Overlay.build_changeset` rules (old values from the witness, no-op changes
  dropped) and applies that changeset, so it touches the same trie nodes in the same order as
  the builder's replay; a wiped account that survives drops its storage trie whole.

- History window pruner (`db/history.zig`): `commit_block` only moves the window; the block
  that becomes the oldest appends its versions to a FIFO prune queue (versions linked through
  `block_next`, block order kept). `prune_step(budget)` examines up to `budget` queued
  versions; each frees the one older version it shadows (FIFO order leaves at most one), and
  a queued tombstone is freed too, with its path when nothing newer exists (a newer version
  just loses its `prev`; lookups below it return null, which no parent of a window block asks
  for). Versions got a `newer` link for that. Removed nodes get tombstones (empty versions):
  after a block's nodes are written, every rewritten node is diffed against its previous
  version; dropped children (branch slots, a changed extension path, all children of a
  collapsed branch) are walked in the old trie (lookups at N-1, explicit bounded stack) and
  tombstoned unless the new trie still reaches the path (walk at N); an account leaf whose
  account had storage and has none now buries its whole storage trie, and an empty state
  buries the account trie. Chosen over mark-and-sweep (O(state) per cycle, and reachability
  must hold for every block of the window, not one root) and matches base/base, which keeps
  `removed_nodes` tombstones and drops them once they reach the earliest block. Sizing
  invariant (documented on `Store`): N = most trie nodes of a state, B = most versions one
  block writes including tombstones; with `prune_per_commit >= B` the queue is empty whenever
  a block is written, so the store never holds more than N + window_blocks * B versions or
  paths, and `HistoryFull` never happens at that size. Fallback when a block does not fit:
  drain the whole queue (bounded by version capacity) and retry once.
- History commit is atomic: the block is written with the non-clearing `count` walk, then
  tombstoned; any `HistoryFull` pops the half-written block (frees its versions and the
  paths it created) and the window is unchanged; the trie's change marks are cleared by a
  second `drain` walk only on success, so the commit can be retried. Replaces the old
  `count`-then-write sizing walk (still two walks per block). The oldest block only moves
  after the write succeeds.
- History commit cost (`db/history.zig`, `db/path_index.zig`): the change marks are cleared
  with `StateTrie.clear_changes` (bitset memset) after a successful write instead of a second
  `drain` walk that re-encoded every changed node; marks of unreachable nodes go too, which is
  safe because a reused node is marked again when rehashed and a trie with the same contents
  has the same encodings. Versions carry the node kind, branch child mask, and a 14-bit
  fingerprint of the node's reference (from the trie's `Visit`, in the record's padding, still
  32 bytes): the removed-node diff reads masks instead of decoding both encodings, and the
  unchanged check compares bytes only when length and fingerprint match. `Store.check_metadata`
  (run by every history test sweep) re-derives them from the encodings. The path index is our
  own open-addressing table of (key hash, path id) slots with keys compared in the path records
  (linear probing, backward-shift deletion, load <= 2/3, no rehash): `path_bytes` 147 -> 84,
  but the slot array is filled at init and `reset` (~37 MiB for the node's ~3.1M paths, vs ~4
  MiB of std hash map metadata). Proof bytes are unchanged (the existing seeded tests compare
  every proof against the unwound live state). Not moved off the critical path: heavy commit
  is ~6 ms of the 200 ms slot, below the cost of a second history head (proofs at the newest
  block waiting or falling back) and the extra ordering under DST. Remaining cost: the trie
  re-encodes each visited node and its encoding is copied into a pool slot; taking encodings
  from a trie-side cache would need the trie to keep full encodings.
- Multi-key historical proofs (`db/proof_set.zig`, `history.Store.get_proofs`): one account
  walk, then the slots are hashed, sorted and deduplicated into a caller-owned `ProofSet`
  and the storage trie is walked once (`Store.walk_frames`, the depth-first core now shared
  with the witness `walk_paths` through a frame visitor). Each node is looked up,
  keccak-checked and decoded once; every key entering it appends a slice into the store (no
  copy), and leaves give the values with `walk_path`'s rules, so each key's proof and value
  are byte for byte `get_proof`'s (seeded differential at every window block, plus fuzz).
  Duplicate keys share one walk entry (binary search back from the input order). The slices
  are valid until the store changes, which the single-threaded RPC handler satisfies (walk,
  then write the response). base/base memoizes cursor results per request
  (`cursor_cache.rs`, concurrent proof jobs over one snapshot); we have no cursors or
  concurrent jobs, so the sorted walk gives the sharing structurally. Not memoized across
  requests. `Database.proofs_at` needs history (no live fallback at the head: the RPC serves
  the head from the live trie and only sends older blocks here). The RPC carves the set from
  the API scratch after its proof buffers, sized by the request's key count (~1.1 KiB per
  key: 256 keys ~ 290 KiB of the node's 16 MiB scratch).
- History is not journaled: it is derived data. After a restart the durable database
  rebuilds the window from the retained blocks' changesets (see "History rebuild on open").
  Journaling every node version would multiply the journal volume per block for data the
  node can regenerate.
- History rebuild on open (`Database.history_rebuild_window`, `Config.history_rebuild_on_open`,
  default true; only with `Config.history`): after checkpoint load and journal replay, State
  is unwound in memory through the retained canonical blocks' stored changesets down to
  `max(head - window + 1, the state below the oldest contiguous canonical block whose
  changeset is retained)` (genesis is never unwound), `reset` there, then each block is
  re-applied with `commit_block`; the state ends at the recovered head (root asserted).
  Nothing is journaled and the chain index never moves; it runs once, synchronously, before
  the first operation. Cost at open: O(window) unwinds + applies + state roots + history
  commits, plus one O(state) `reset` (the old cost). Proofs equal the pre-crash ones because
  the trie is canonical for a state. If retention holds fewer blocks than the window, the
  window starts at the oldest state retention reaches. An unwind that does not fit
  (`State.unwind` fails before any change) starts the window at the block it reached; a
  history failure (`HistoryFull`) falls back to `reset` at the head (`history_drops`); a
  failed re-apply fails the open (`ReplayFailed`), recoverable by opening with
  `history_rebuild_on_open = false`. Chosen over checkpointing the history store: the store
  is up to N + window * B versions, would bloat every checkpoint and need its own format,
  versioning, and validation, while the changesets are already durable in the retained
  blocks.
- Witness of a stored block (`db/witness_block.zig`): the state is unwound in memory with the
  stored changesets (head down to the block) and re-applied afterwards, instead of
  `set_head(parent)`, so nothing is journaled, the chain index and head never move, and the
  block-hash ring is untouched. Chosen over a state copy (too much memory for a full state)
  and over a historical-state overlay (none exists). It requires the state's users (the
  node executor) to be idle for the call; the node is single-threaded and runs RPC handlers
  between blocks. The root after unwinding the descendants is the block's stored root, and
  the witness-only post root must equal it (`WitnessMismatch`); the head root is checked
  after the re-apply (`StateCorrupted` fails the database). The caller's executor returns
  its uncommitted evm block `State`, folded with `commit_evm` + `build_changeset` (the
  node's commit rules, nothing applied). BLOCKHASH during the run answers from the
  caller's canonical chain view (the ring slots for numbers above the block were
  overwritten by descendants). Headers: contiguous ancestors from the lowest BLOCKHASH
  number read up to the parent (reth), so a verifier can link each hash to the parent.
  `Generator` is bound to one `State` and owns all scratch (allocated at init); depth is
  bounded by `Config.depth_max` and by retention (`BlockUnavailable`).
- Witness from history (`db/witness_block.zig`, `generate_history`): when the database keeps
  history and the block's parent is in the window, the recorder wraps an evm `Database` over
  `history.Store` at the parent (`account_at`/`storage_at` walk the versioned trie from that
  block's root, every node checked against its parent's reference; codes from the live
  state's code store, which never deletes; BLOCKHASH from the chain as before). The builder
  takes a duck-typed node source (`Builder.build_from`): `StateSource` (live trie proofs and
  `visit_siblings_in`, the old behavior) or `HistorySource` (`Store.visit_account_proof`,
  `visit_storage_proof`, `visit_account_siblings`, `visit_storage_siblings`: the same nodes
  in the same order, from history), so the replay, minimality, and output order are shared.
  The changeset is folded with the `Overlay.build_changeset` rules but old values from
  history (the overlay's base is the head state). A wiped account whose parent storage is
  not empty would need its old slots spelled out, which the hashed history trie cannot
  enumerate (no slot preimages): `HistoryWipeUnsupported`, and `database_witness` unwinds
  instead (post-Cancun the evm cannot wipe an account with storage that survives, as
  creation over storage collides). Expected post root = history root of the block. Nothing
  of the state, head, journal, or trie change marks moves, so commits may interleave; the
  history reference is valid only until the next head move. Chosen over an overlay on a
  historical state: no new state provider, one generic builder. Cost per read is a
  history walk (O(depth) lookups); fine for one block's reads.
- Node integration of the witness (`node/witness.zig`): durable nodes use the database's
  stored changesets through an optional `Journal.witness` hook (`Durable` calls
  `Generator.database_witness`); in-memory nodes peek the newest changesets of `StateDb`'s
  undo ring (`recent_changesets`, ring unchanged). The block executor is the node's own
  `Executor`: its evm `State` is `reset` to the recorded parent database,
  `execute_uncommitted` runs the block (system calls, txs, withdrawals, requests) without
  committing, and afterwards `abort_block` + `reset` back to `StateDb.database()`. No
  second executor, so no extra executor memory. The RPC writes the generator's witness
  (one bounded buffer set, `Limits.witness`, default on; null disables the method).

- Witness codec (`db/witness_codec.zig`): own format, not RLP or JSON: `"NFWT"`, u32 version,
  then state, codes, keys, headers, each `count | payload_bytes | (u32 len | bytes)*`, all
  little-endian u32. One canonical form so a witness has one byte string (hashable, cacheable,
  comparable): state and codes strictly ascending by keccak256 (dedup), keys 20 or 32 bytes
  strictly ascending bytewise, headers strictly ascending block number (two different headers
  with one number are rejected at encode). The decoder accepts only that form and is bounded by
  the output `Witness` capacities (`WitnessFull`); seeded and coverage-guided fuzz check that
  every accepted input re-encodes to itself. Encoding sorts index arrays in an `Encoder`
  allocated from the witness config (no allocation per encode). Sorting by digest makes the
  sections binary-searchable: `lookup(digest)` costs one keccak per probe and needs no index.
- Preimage view: base/base `crates/proof/preimage/src/key.rs` (`PreimageKeyType::Keccak256 =
  2`, oracle key = type byte + low 31 digest bytes) and `crates/proof/host/src/handler.rs`
  (`execution_witness_preimages` hashes every `state`, `codes`, and `keys` item).
  `PreimageIterator` yields that same set (digest, bytes) and `preimage_key` renders the oracle
  key; keys are searched linearly since they sort by bytes, not digest. No lookup by oracle
  key: it drops the digest's high byte, so hosts load their key-value store from the iterator.
- Witness generator memory: every large generator buffer (byte lists, key-set items, node
  stores, the sparse node pool, changesets, proof buffers) is reserved at init through
  `utilities.lazy_alloc` and committed on first touch, so static allocation holds (nothing
  allocates per call) while an idle node pays only for hash-map indexes, which std writes at
  init (metadata always; keys and values too in safe builds, where `Allocator.alloc` fills
  with 0xAA). `SparseTrie` hands out nodes from a high-water mark plus a LIFO free list, so
  `clear` is O(1) instead of rewriting the whole pool on every witness (same allocation order
  as the old fully threaded free list). The output `Witness` byte lists are derived from
  `Limits.witness_response_bytes_max` (default 1 MiB - 2 KiB: the HTTP send buffer less the
  head reserve and the JSON-RPC envelope): hex doubles every byte, so no list can usefully
  hold more than half of it. Key bounds stay 4096 accounts + 16384 slots: each key is at least
  45 JSON bytes, so the default response cannot carry more than ~23k keys anyway. The RPC
  computes the exact JSON length first and replies -32000 "witness too large" when it exceeds
  the configured bound or the space left in the response buffer, or when the build overflowed
  the output lists (`WitnessFull`); before, the router's generic -32603 "response too large".
  The bound rides on `witness_block.Config.response_bytes_max` (default unbounded) so
  `eth.Api` stays unchanged. Not done: the generator's `Overlay` (18 MiB of hash maps for one
  block's writes) could borrow the `StateDb` overlay, idle between blocks.

- Witness responses over the 1 MiB send buffer: a small pool of shared large send buffers in
  `http.server`, not a streamed body. Streaming would need a body-producer API in the server
  (a response spanning several sends), the router's rewind-on-failure and batch envelope to
  work without a buffer, and the generator's single `Witness` pinned until the last chunk is
  sent (another connection's witness call would otherwise overwrite it mid-stream). The pool
  keeps the existing one-buffer-per-response model: `Options.large_send_buffers_max` x
  `large_send_buffer_size`, reserved at init through `lazy_alloc` (committed only as written,
  so an idle node's resident memory is unchanged). The body writer is fixed as before, but its
  `rebase` moves the body written so far (envelope, batch prefix) into a free large buffer and
  the connection holds it until the response is sent or the connection closes. Only a rebase
  grows (`ensureUnusedCapacity`, i.e. a handler that sized its output up front); plain writes
  past the end still overflow, so other methods keep their bounds and cannot hog the pool.
  No free buffer, or one too small, fails the rebase like a full buffer: the witness RPC
  replies -32000 "witness too large", as it does over the configured bound (checked first,
  before any buffer is taken). Node default: 2 x 16 MiB (32 MiB reserved, 0 resident when
  idle) and `witness_response_bytes_max` 16 MiB - 2 KiB, so the derived `Witness` lists grow
  to 4 MiB state / 8 MiB codes / 8 MiB headers (reserved, lazily committed). APIs are
  additive (`ResponseBuilder.grow` defaults to null; `ResponseBuilder.init` unchanged).

- Database-owned history (`DatabaseType`, `Config.history`, null = off): the database owns a
  `history.Store` and enables `StateTrie.track_changes` only when it is configured. Live head
  moves update it inside `move_state`: unwinds, then `unwind_to(fork point)`, then
  `commit_block` after each applied block (a state root per applied block, so a multi-block
  reorg costs one extra root per block); `commit_applied` commits its one block. Replay at
  open never touches history; `open` ends by rebuilding the window from retained changesets
  (see "History rebuild on open"; `reset` at the head when disabled). Any history failure
  (`HistoryFull`, a reorg below the window, `NotNextBlock`) never fails the operation and never touches state: the
  move finishes, history is rebuilt with `reset` at the new head, and `history_drops` counts
  it. If that rebuild fails too (the store cannot hold one state), history stays off
  (`history_off`) until the next open instead of retrying O(state) per block.
  `proof_at(number, ...)` serves the window from history; without history only the head is
  served (live trie proof), else `HistoryUnavailable`.
- Historical `eth_getProof` (node/rpc integration): `Journal.proof` (set by `Durable` only when
  history is configured) takes the block hash and number; the database's canonical index (not
  the node's) decides whether the hash is the block at that number, so side blocks get the
  existing "historical state unavailable" error, as do blocks outside the window. The handler
  moves the state to the chain head first (`ensure_head_state`) so the database head and the
  window match the chain. Storage proofs are fetched one slot per call into the existing
  scratch (no scratch growth); the account proof is recomputed per slot (a few lookups).

- Witness header ancestry (reth stateless validation): `SparseState.reset(pre_state_root,
  parent)` binds the verifier to the parent of the block it checks (number + hash, trusted by
  the caller). `add_header` decodes each header strictly (`header_link`: 32-byte parent hash
  and state root, canonical number) and requires it to be the child of the previous one
  (number + 1, parent hash = keccak256 of the previous header); `verify_headers` (called by
  `load`) requires the last header to be the parent (number and hash) and to hold the
  pre-state root. `block_hash` serves nothing before verification and only numbers the chain
  covers (O(1) by offset). An empty header list is allowed (a block that reads no BLOCKHASH);
  every BLOCKHASH read is then `WitnessIncomplete`, and the pre-state root is the caller's
  claim alone, as before. A chain may start anywhere below the parent (a suffix: fewer
  ancestors is not a forgery). Failures are `error.InvalidHeaderChain` (`witness.Error`). The
  builder's scratch is unbound (private `clear`), since it never serves BLOCKHASH.

- witness-diff (base/base `etc/tools/witness-diff`): library `db/witness_diff.zig` is pure
  (parse, diff, render to a `std.Io.Writer`); the binary does file/HTTP IO. Parser accepts
  the `result` object or a whole JSON-RPC response (`error` -> `RpcError`), each list as an
  array, a hash-keyed object (older reth maps; keys recomputed), null, or absent. Keys are
  normalized: reth's RLP `0x94 ++ address` / `0xa0 ++ slot` become raw 20/32 bytes, so ours
  and reth's compare equal; other keys over 32 bytes are rejected. Sets compare by keccak256
  of distinct items, as the reference. Leaf attribution walks each witness's account trie
  from its own pre-state root (last header's state root if present, else the only
  decodable unreferenced node; ambiguous -> walk skipped and reported) and descends into
  reachable storage tries, so leaves carry full hashed keys (account, slot) instead of the
  reference's partial-path matching; preimages from both witnesses name addresses/slots.
  Sections, wording, and exit codes mirror the reference (0 when the diff ran, identical or
  not; 1 error; 2 usage), labels "local"/"remote", plus listing of one-sided codes/keys and
  per-walk stats. `--rpc-url` uses `std.http.Client` in the binary (std only, like
  `bin/base/http_transport.zig`; `utilities.http.client` needs an event loop and caps
  bodies at 1 MiB). Bounds: tool limits 512Ki nodes/keys, 16Ki codes, 1 GiB input, 1 MiB
  per item, lazily committed; walk bounded by `leaves_max`, `walk_steps_max`, and a
  fixed DFS stack (`stack_frames_max`), truncation reported.
- Witness builder collection (`Builder.build_with`): one depth-first walk per trie over the
  touched keys sorted by hashed path (`path_targets.sort_unique`, flags OR-ed: `mark` = read,
  `siblings` = deleted). Each proof node and each hashed sibling of a deleted key's branch is
  visited once with its hash (live trie: the cached `RlpNode`; history: the parent reference
  `checked_node` verified), so nothing is re-encoded or re-hashed per key; the node store
  still deduplicates by hash (identical nodes across storage tries). Read keys' proof nodes
  are pre-marked "decoded" instead of replaying the reads, because a sparse `get` resolves
  exactly its key's proof nodes. `BuildOptions.verify_root` (default on; `build`/
  `build_from` and the node/rpc paths use it) applies the changeset on the scratch sparse
  trie and returns its root; off returns null, and a changeset with no deleted account or
  slot then skips the sparse apply (a put resolves its whole proof path, so the witness is
  exactly the touched keys' proof nodes); deletions still run the apply, since only it knows
  which collapsing branch needs which sibling. The witness is the same set either way;
  `Witness.state` order is now walk order (codec encoding sorts by hash, so encoded bytes
  are unchanged). The old per-key collection lives on as the reference in
  `db/witness_differential_test.zig`.
- Witness key hashing: the builder hashes every touched key once, batched in `touched` order,
  and derives the changeset's hashes (`ChangesetHashes`, changeset order) by insertion-index
  lookup (`SetList.index` maps item -> index), so the walks and `SparseState.apply_hashed` share
  them. The verifier's `apply` hashes slots and account addresses in batches of 64
  (`KeyCursor`); one keccak per storage run address. `apply` runs in three phases: every storage
  run (recording the run's address hash, pre-state account leaf and root in per-state scratch
  bounded by `storage_tries_max`), one batched rehash of all written storage roots, then the
  account leaves in address order reusing the run records. The account trie still sees reads
  before writes, so the decoded node set (the witness) is unchanged: 72 builds of the
  differential test encode to the same bytes as before the change.
- `SparseTrie` root: dirty nodes are collected with their depth across any number of roots,
  counting-sorted deepest first, and each level hashed with equal-length encodings paired
  through `keccak256_batch` (one waiting slot per length and batch lane, flushed one by one at
  the end of the level) instead of sorting by length. The serial post-order rehash stays as
  `root_hash_serial`, fuzzed against it ("seeded differential of the batched root").
- `SparseTrie` unloaded children: a child slot of a witness-decoded node is a pool index, `none`,
  or `unloaded_first + offset` where `offset` (< 1024; preimages are at most 532 bytes) is
  the byte offset of the child's RLP item in the parent's preimage. A valid child item (32-byte
  hash string or short list) is its own reference, so materializing or rehashing reads it in
  place. Chosen over caching decoded `RlpNode`s per branch (544 B per node) because the
  offset fits in the existing slot. `decode_layout` (offsets) is the strict decoder;
  `decode_node` copies the references out of it. Branches go through a one-pass scan first
  (`decode_branch_fast`), fuzzed to accept exactly what the item decoder accepts.
- Witness hash maps (`NodeStore.index`, `SparseState.storage_roots`) use `DigestContext`:
  keys are keccak digests, so the map hash is their first eight bytes. As deterministic as
  the unseeded `AutoContext` it replaces, and digests are equally grindable under both.

## Known limitations (storage)
- Bit rot in an acknowledged journal entry truncates replay at that entry (reported as
  `journal_stop` corruption; acknowledged entries after it are lost). Not fixed: needs
  journal redundancy (TigerBeetle repairs from replicas; we have one copy).
- One rotten checkpoint zone is survived; it is data loss (`CheckpointCorrupt`) only with a
  second fault: rot in the fallback zone, rot in a journal entry between the two checkpoint
  starts, or a crash during a checkpoint write combined with rot in the newest zone.
- A transient read fault while streaming the fallback after it was chosen fails open (no third
  option); reopening retries.
- A cleanly closed journal can report `journal_stop = header_corrupt`: the sector after the
  last entry may hold a body sector from an older lap, which the scan cannot tell from a torn
  header. Recovery is still the full valid prefix; only the stop reason is pessimistic.

- Storage-heavy block (profiled with phase timers, not committed): the cost was changeset
  sorting (~2 ms: block sort copying 128+ byte entries, byte-wise compare) and `State.apply`
  hashing each storage slot's address again. Fixed with an index sort (pdqsort over
  `address prefix << 32 | index`, in-place cycle permutation; keys are unique, so the order is
  unchanged), one address hash and one `entries` lookup per run of slots
  (`StateTrie.set_storage_slots`, marks the account dirty before writing so a mid-run
  `TrieFull` still rehashes earlier slots), and batched slot/account key hashing. Changesets
  take 8 more bytes per entry. Storage tries were never created or destroyed per block, so
  nothing to fix there.

- Historical proofs (`db/history.zig`, `HistoryStore`): versioned trie node preimages keyed
  by (trie owner, path), newest-first version chain per path; a proof at block N walks from
  N's state root and takes at each path the newest version at or before N, checking every
  node against its parent's reference (hash or inline bytes). Paths, not hashes: one node per
  path per block, so the lookup is exact whenever N's parent points there, and pruning is per
  path (a version is freed once a newer one is at or before the window start). No tombstones:
  removed nodes are never pointed at by a parent of N. No separate leaf history or reverse
  changesets: account and slot values decode from the leaf nodes, and unwinding drops the
  versions of the removed blocks. Feed: `TrieType.track_changes` adds one bit per pool node,
  set when the node is rehashed (both hash paths) and drained by `visit_nodes` (path +
  encoding, skipping clean subtries since a rehash also rehashes all ancestors);
  `StateTrie.visit_nodes` descends into the storage trie of each changed account leaf (a
  changed storage trie always changes its leaf). Untracked tries pay one branch per rehashed
  node. Versions equal to the path's newest one are skipped (after an unwind, rehashed-back
  nodes repeat). Two version size classes (160 B: leaves, extensions, sparse branches; 646 B:
  dense branches). Lookup is O(versions at the path newer than N): at most the window length
  plus the unpruned queue; fine for windows in the thousands, a jump-pointer chain (or a
  per-path newest-at-or-before index) is the upgrade if long windows need it (not done).
  Tombstones cost one diff per rewritten node plus, per removed node, a reachability walk
  from the new root (O(depth) lookups); a wiped storage trie tombstones every node in one
  block, so B (versions per block, see sizing) must cover the largest storage trie wiped.
  `path_index` removals leave hash map tombstones; `prune_step` rehashes it once per
  `paths_max / 2` removals (an O(paths) spike, amortized O(1) per removal).

- Execution witness (`db/witness.zig`): alloy `ExecutionWitness` shape (`state`, `codes`,
  `keys`, `headers` as byte lists). `Recorder` wraps the evm `Database` and records reads in
  insertion order (bounded sets; full -> `StateFull`). `Builder.build` gathers a superset
  (eth_getProof nodes of every read or written key, plus hashed siblings along deleted keys'
  paths via `TrieType.visit_siblings_in`), replays reads + changeset on a `SparseState` over
  it, and emits only the nodes the replay decoded: minimal for that replay, so dropping any
  node is `WitnessIncomplete` (tested for every node). Chosen over computing exact collapse
  siblings up front, which needs the post-order of deletes. Keys: addresses (20 B) then slot
  keys (32 B), touched order. Headers are opaque caller bytes; `SparseState` maps them to
  block hashes by decoding field 8 (number). A destroyed account's storage trie is dropped
  whole, not slot by slot; a wipe without destroy deletes slot by slot (the changeset spells
  them out), so its witness holds that storage trie.
- Sparse trie (`trie/sparse.zig`): own pool (not `TrieType`): nodes are unresolved refs,
  leaves, extensions, or branches; a node decoded from the witness keeps its preimage slice and
  materializes children lazily (one pool node per untouched branch, not 17). Fixed 32-byte
  keys only: branch values and off-length leaves are `InvalidWitness`. A delete resolves and
  shape-checks the surviving sibling before changing anything, so `WitnessIncomplete` leaves
  the trie unchanged.

- Linux io_uring storage run: no backend fix was needed. `IORING_OP_FSYNC` is issued with
  flags 0 (full fsync, not `IORING_FSYNC_DATASYNC`), so file-size growth from appending
  writes is durable, matching `F_FULLFSYNC` on Darwin. The file is opened buffered (no
  `O_DIRECT`), so there is no alignment requirement beyond the 4 KiB sector contract, and no
  preallocation: reads past end of file zero-fill. Short reads/writes are resubmitted by
  `IoStorage` and covered by the flaky-IO test. The real-file test ("engine over the os
  backend on a real file") already runs on both io_uring and kqueue, so no new test.
- `has_storage` for the evm backend (EIP-7610) is a per-account nonzero slot count stored
  with the account in `State.account_table` (`AccountEntry.storage_slots`), not a cached
  storage root: `StateTrie` storage roots are only hashed at flush, so a root compare is
  stale mid-block, and a separate presence map costs a second probe. The count is updated in
  the same `storage_table` probe by every slot writer (`apply`/`unwind` via `set_slot`,
  `put_account`/`put_storage` for genesis, snapshot load); wipes and selfdestructs reach
  `State` only as per-slot changeset entries, and removing an account asserts its count is
  zero. The evm backend reads committed `State` only (the evm keeps its own block cache and
  `Overlay` has no `has_storage`), so overlay reads need no count. Genesis writes in
  `node/state_db.zig` now go through `State.put_account`/`put_storage` (they wrote the tables
  directly and would have bypassed the count).
- Block time: needlefish runs Base's native 200 ms L2 blocks (AGENTS.md rule 10, no
  flashblocks). Trie/db budgets assume 5 blocks/s: commit latency must stay well under the
  200 ms slot (seal at 150 ms), and block-count windows (history, retention, pruning) cover
  5x fewer seconds than at 1 s blocks; size them in blocks from the desired wall-clock span.
- History byte budget (`history.Config.bytes_max`; the backlog's `Config.history_bytes_max`,
  kept on the store config the database already takes, plus `Limits.history_bytes_max` in
  the node): `Store.bytes_used` counts occupied paths and versions at fixed unit sizes
  (`small_version_bytes` 196, `large_version_bytes` 682, `path_bytes` 84, was 147: record, encoding
  slot, free-stack entry, index entry). After a commit writes its block and moves the window,
  `fit_budget` drains the prune queue (garbage first), then moves the oldest block forward one
  at a time and prunes what it shadowed until the store fits: the window stays contiguous
  and ends at the head, grows back one block per commit, and proofs below it return the
  existing `BlockOutOfWindow`. Only when the head block alone (its state's nodes) is above the
  budget does the commit return `HistoryFull` (window shrunk to that block), and `reset`
  refuses such a state too; the database then drops history as before (`history_drops`,
  `history_off`). Capacity exhaustion keeps its old atomic refusal (not turned into shrinking):
  the node sizes the version pools at the budget's worth of each class plus one block, so
  the budget binds first. Pools and path arrays are lazily committed (`lazy_alloc`) and hand
  out never-used slots from a bump index before recycling LIFO, so resident memory follows
  the peak occupancy (about the budget), not the capacity; the path hash index is still
  allocated eagerly, so node paths are capped at min(sizing rule, budget / (path + small
  version)). Rebuild on open needs nothing new: its `commit_block`s shrink the same way (it
  may replay blocks that are pruned again right away; bounded by the window).
- Node history defaults: base/base defaults to 15 days (6 480 000 blocks at 200 ms) because
  its proofs store is on disk (RocksDB/MDBX); needlefish's window is in memory, where 15 days
  of typical blocks is ~17 TiB (14.1 MiB/s measured). Default `--proofs-history.window` is
  300 blocks = 60 s at 200 ms (`service.proofs_history_span_s`, `block_time_ms`), enough for
  proving the recent head; the 1 GiB budget holds the devnet-scale 100k-account state
  (79 MiB) plus 300 typical blocks (~925 MiB) and shrinks to ~202 blocks (40 s) under
  sustained storage-heavy blocks. A longer window needs a disk-backed store (not done).

## Log
- 2026-11-05: MPT (rlp, nibbles, node, HashBuilder, mutable trie, proofs, ordered root);
  all ethereum/tests TrieTests vectors pass.
- 2026-11-05: StateTrie (account + shared-pool storage tries, dirty-set incremental root,
  account/storage proofs), differential-tested against HashBuilder.
- 2026-11-05: state provider: State + block Overlay (O(1) wipes via epochs), canonical
  Changeset codec, unwind; tested with replica replay and multi-block reorgs.
- 2026-11-05: ChainStore: block ring, canonical index, tx lookup, reorg plans; reorg test
  moves State purely from stored changesets.
- 2026-11-05: State snapshots (stream write/load, trie rebuilt and root-checked on load).
- 2026-11-05: evm backend adapter (Database vtable + commit_evm fold into Overlay).
- 2026-11-05: storage engine (superblock, journal, A/B checkpoints, engine) with seeded
  crash/torn-write/bit-rot fault injection over SimStorage; mutation-checked.
- 2026-11-05: durable database facade over the storage engine; crash-recovery tests
  (24 seeds x 4 crashes) recover a head/root between last acked and last submitted op.
- 2026-11-05: io-backed storage (sim + real OS file), engine end-to-end over both.
- 2026-11-05: trie benchmarks: 1k-account state block on 100k accounts in 2.0 ms.
- 2026-11-05: IoStorage over utilities.io; engine end to end over a short-IO double, SimIo
  (16 crash seeds), and kqueue/io_uring on a real temp file.
- 2026-11-05: batch keccak in the trie rehash: 1k-account state block 1.98 -> 1.60 ms.
- 2026-11-05: db benchmarks: 1k acct + 4k slot block on 100k accounts: 13 ms apply+root,
  21 ms commit until durable (kqueue + F_FULLFSYNC), 40 ms checkpoint of a 17 MB state.
- 2026-11-05: one fsync per `execute_and_commit` (`block_and_head` entry): 1.0 syncs/block,
  fsync wait per block ~9 -> ~4 ms (durable p50 24.1 -> 15.3-17.6 ms on a noisy laptop).
- 2026-11-05: compact trie node layout: 284 -> 186 B/node (accounts), 204 -> 106 B (storage);
  100k bench trie 393 -> 257 live B/entry; get 173 -> 166 ns, other benches within noise.
- 2026-11-05: storage-heavy block apply+root 10.3 -> 7.9 ms (changeset index sort, one
  address hash per slot run, batched key hashing); remaining gap is 2x dirty accounts plus
  storage rehash (docs/PERF.md).
- 2026-11-05: historical proofs store: `eth_getProof` at any block of the window from
  versioned node preimages; differential against a State unwound to each block (2 seeds,
  reorgs, window 10), proofs verified against each block's root.
- 2026-11-05: checkpoint fallback: journal keeps entries back to the previous checkpoint; a
  rotten newest checkpoint (any sector) reopens via the older zone plus the longer journal.
  Engine fault injection now also rots the newest checkpoint (fallbacks asserted), database
  crash test too; superblock fallback fields fuzzed.
- 2026-11-05: execution witness + stateless `SparseState`: witness-only replay root == full
  State root (8 seeds x 4 blocks with deletes/wipes/destroys), every witness node required,
  sparse trie differential against `TrieType` with shared prefixes, fuzzed node decoder.
- 2026-11-05: history window pruner: FIFO prune queue with `prune_step(budget)`, tombstones for
  removed nodes so deleted subtries free their paths, atomic `commit_block`; tests: 360-block
  run with reorgs within the N + window * B bound, budget-1 steps, freed storage trie paths,
  base versions == trie nodes of the oldest block after a drain.
- 2026-11-05: witness evm differential: random pre-state with hand-assembled contracts
  (SLOAD/SSTORE/LOG1/BALANCE/EXTCODEHASH/EXTCODESIZE/BLOCKHASH/CALL/SELFDESTRUCT/CREATE),
  6 seeds x 3 blocks of calls and transfers through the real evm; witness-only re-execution
  gives identical results and post root, and every witness node is required (~0.8 s Debug).
- 2026-11-05: `witness_block.Generator`: witness of a retained canonical block of the durable
  database (unwind in memory to the parent, run, build, verify root, restore); test runs 6
  evm blocks through `execute_and_commit`, witnesses the last 5, re-executes each over
  `SparseState.database()` to the stored root, head/root/journal unchanged, deeper/unknown/
  genesis refused.
- 2026-11-05: `debug_executionWitness` wired: rpc test decodes the JSON witness of 3 fixture
  blocks, rebuilds a `SparseState`, re-executes with the node executor statelessly to the
  header root, head and root unchanged; durable node test witnesses 3 blocks after a side
  branch with no journal entries, side block and genesis refused, node keeps building.
- 2026-11-05: witness codec: canonical encoding + strict decoder + keccak preimage view; builder
  witnesses (4 seeds x 3 blocks) round-trip byte for byte, a `SparseState` loaded from the
  decoded witness replays to the same root, every node/code/key found by digest; decoder fuzzed.
- 2026-11-05: database feeds history: seeded workload (2 seeds, side branches, reorgs, 3
  crash/reopen cycles) checks proofs at every block of the window against each block's root and
  the database's State unwound to it; reopen restarts the window at the head; a full store
  drops and rebuilds history with the database healthy; history-off serves the head live.
  `eth_getProof` at older blocks of a durable node's window returns the bytes it returned as
  the head (by number and hash, after a reorg back too); out-of-window and side blocks refused.
- 2026-11-05: witness generator memory, default node limits, measured by
  `node/witness_memory_test.zig` (bump allocator over a sentinel-filled region; a written
  4 KiB page counts as resident). Before: reserved 99.4 MiB, resident 99.4 MiB (Debug/
  ReleaseSafe) and 14.8 MiB (ReleaseFast: the sparse pool clear). After: reserved 88.4 MiB,
  resident 332 KiB (ReleaseFast) and 24.2 MiB (safe builds: overlay maps 18.3, key-set maps
  2.3, node-store maps 1.3). Per part (Debug before -> after, reserved/resident MiB): sparse
  29.0/29.0 -> 29.0/1.3, keys x2 3.3/3.3 -> 3.3/2.3, witness 13.3/13.3 -> 2.3/0, overlay
  18.3/18.3 unchanged, changesets x2 16.0/16.0 -> 16.0/0, proofs 0.15/0.15 -> 0.15/0.
  `debug_executionWitness` over the configured bound or the response buffer: -32000
  "witness too large", exact JSON length checked against the written response.
- 2026-11-05: witness benchmarks (`db/witness_bench.zig`, 100k-account state, 11 samples, median):
  1k account writes 3 004 nodes / 751 KB / build 7.1 ms; 1k acct + 4k slots 5 613 nodes /
  1.28 MB / build 30.7 ms / verifier replay 12.7 ms; 200 evm SLOAD+SSTORE calls 1 484 nodes /
  392 KB / build 4.4 ms / stateless re-exec 1.67 ms. Recorder ~30 ns per key, codec 0.45-0.75
  GB/s. Every sample checks the verifier's root against the builder's.
- 2026-11-05: witness from history: `debug_executionWitness` of a block whose parent is in the
  durable history window runs over history (state, head, journal untouched; commits continue
  between calls). Seeded workload (2 seeds, reorgs, window 4): every block's history witness
  encodes (`witness_codec`) to the unwind witness's bytes, head witness re-executes
  statelessly to the stored root; blocks below the window fall back to the unwind; durable
  node test checks the source per block across a new head.
- 2026-11-05: witness header ancestry verification (DST-found soundness gap: forged BLOCKHASH
  from unlinked witness headers). `SparseState` is bound to the parent; gap, duplicate,
  unsorted, broken middle link, wrong tail hash/number, missing parent, and pre-root mismatch
  are rejected; seeded + `std.testing.fuzz` chain mutations verify only suffixes of the valid
  chain. Witness tests now use real linked headers (`db/witness_header_chain.zig`).
- 2026-11-05: Witness responses over 1 MiB: shared lazily committed large send buffers in
  `http.server` (grown on a body-writer rebase, held until sent), `debug_executionWitness`
  requests its exact JSON length from the writer; node default 2 x 16 MiB, bound 16 MiB -
  2 KiB. Tests: a 3 MiB sized response over SimIo (500 for unsized overflow, 503 beyond the
  buffer, busy pool), the witness over real HTTP with a 2 KiB send buffer equals the router's
  output byte for byte, over-bound and over-buffer still -32000, the node's large buffers
  reserved but not resident at init.
- 2026-11-05: witness-diff port: `db/witness_diff.zig` (parser for our/reth JSON shapes,
  set diff of nodes/codes/keys, account + storage trie walk from the pre-state root naming
  diverging accounts and slots, stable text report) and `bin/witness-diff`. Tests: identical
  -> empty, changed storage leaf -> account + slot named, missing code / extra key, leaf only
  in one walk, parser shapes and errors, `std.testing.fuzz` + seeded mutated-JSON fuzz.
- 2026-11-05: end-to-end `debug_executionWitness` over 1 MiB (`rpc/debug_large_test.zig`). A real
  block (24 calls from distinct senders, each to its own 24 KiB contract doing `SSTORE(0, 1)`)
  has a 1.18 MB JSON witness, mostly codes: the cheapest way past 1 MiB in Debug (a
  storage-heavy block needs ~1k contracts x 4k slots of pre-state). Served over SimIo HTTP with
  the node's 1 MiB send buffer and one 2 MiB large buffer; the client decodes it, rebuilds a
  parent-bound `SparseState`, re-executes with the node executor, root == header. With the
  pool disabled (the old 1 MiB path), too small, or busy with a concurrent witness: -32000
  "witness too large"; the buffer is released and serves the next witness. ~0.1 s in Debug.
- 2026-11-05: witness builder: sorted multi-key proof walk for live and history sources,
  read paths pre-marked, `BuildOptions.verify_root`, cheaper sparse child materialization
  (skip to one RLP item). Storage-heavy build 36.9 -> 15.9 ms (4.6 ms unverified), 1k-account
  7.8 -> 3.2 ms (0.63-0.71 ms), evm block 4.0 -> 2.2 ms (0.40-0.45 ms); witnesses
  byte-identical (differential test vs the old collection on random states, both sources).
- 2026-11-05: witness apply with shared hashed keys: builder hashes touched keys once (batched)
  and passes the changeset's to `SparseState.apply_hashed`; verifier `apply` batch-hashes;
  storage applied per account run with one account lookup; batched level-ordered rehash in
  `SparseTrie.update_root_refs` across all storage tries. Storage-heavy verified build 15.7 ->
  12.5 ms, 1k-account 3.2 -> 2.5 ms, evm block 2.2 -> 1.8-2.0 ms; verifier replay 9.9 ->
  8.2-9.4 ms. Witness bytes identical to before (differential digests across 72 builds);
  new seeded differential of batched vs serial sparse roots over three tries per pool.
- 2026-11-05: sparse apply without re-decoding: unloaded child slots carry the child's item
  offset in the parent preimage (no `decode_node` at rehash or in `child_at`), one-pass
  branch decode in `resolve`, dirty branches encoded straight from cached refs, digest-keyed
  witness maps. Storage-heavy verified build 16.1 -> 10.8 ms, unverified 5.1 -> 4.2 ms,
  replay 9.6 -> 6.4 ms; 1k-account 2.59 -> 1.96 ms; evm block 2.11 -> 1.35 ms, stateless evm
  1.35 -> 0.98 ms (interleaved medians, load 50-75). Witness bytes unchanged (same node
  counts and sizes; differential, codec, rpc and proof tests pass); fast branch decode fuzzed
  against the item decoder.
- 2026-11-05: history window rebuilt on open: `open` unwinds State through the retained
  canonical changesets to the window start, `reset`s history there, and re-applies with
  `commit_block` (O(window) at open, configurable). Seeded workload (2 seeds + a retention-4
  run, reorgs, crash/reopen after a random number of steps x 3): the head and root survive,
  the window reaches `max(head - window + 1, retention floor)`, proofs at every block of it
  verify against the stored roots and equal the pre-crash proofs; rebuild off restarts at the
  head; history off serves only the head. ~0.9 s Debug for the history test group.
- 2026-11-05: parallel storage-trie rehash: `rehash_threads` (default 0) static pool, chunks
  of whole tries claimed by caller + workers, joined before the account trie. trie/storage 4k
  slots 3.40 -> 2.37 ms (4 threads), db/block 8.05 -> 6.87 ms, db/commit sim cpu p50
  ~8.2 -> ~6.9 ms (medians, load 25-60 on 14 cores). Seeded differential (caches, roots,
  change marks; threads 3-4 vs 0, incl. deletions, wipes, early flushes) and a fuzz.
- 2026-11-05: read-path bench (`db/read_bench.zig`): flat-table reads 14-41 ns, the
  vtable adds ~1-3 ns except `basic` hits (+~310 ns keccak for `has_storage`, backlog);
  `StateTrie` reads are dominated by keying keccak (300 / 450 ns vs 23 / 34 ns prehashed).
- 2026-11-05: Linux io_uring run of the storage engine (Docker, aarch64 kernel 6.8, Zig
  0.17.1, `-Drequire-io-uring=true`, so a missing ring fails instead of skipping). The
  `just test-linux` recipe with `-Dtest-filter=<f>` per filter and caches in the container
  (`ZIG_GLOBAL_CACHE_DIR=/tmp/zg ZIG_LOCAL_CACHE_DIR=/tmp/zc`): `zig build test
  -Drequire-io-uring=true -Dtest-filter=<f> --summary all` for f in io_storage, database,
  engine, journal, superblock, checkpoint, `io:`: all exit 0, 0 skipped (122, 130, 217, 126,
  123, 129, 126 tests; database 6 s, engine 4 s). Includes the real-file
  format/commit/checkpoint/reopen-on-a-fresh-fd test over io_uring. No code changes.
- 2026-11-05: evm backend `basic` without keccak: per-account slot count in
  `State.account_table` answers `has_storage`; vtable `basic` hit 294 -> 24 ns, db/block
  unchanged within noise (7.8-8.2 -> 7.4-7.8 ms, load ~25). Seeded differential vs
  `StateTrie.has_storage` (genesis puts, overlay blocks with destroys/wipes/discards,
  unwinds, snapshot reloads) and a fuzz.
- 2026-11-05: history byte budget: `history.Config.bytes_max` shrinks the window (oldest
  pruned first) instead of dropping history; lazily committed pools. Measured
  (`db/history_bench.zig`, 100k accounts): typical block 8 025 versions = 2.82 MiB, heavy
  15 309 = 4.68 MiB, state 78.7 MiB; history commit p50 12 / 34 ms. Node: window 300 (60 s),
  budget 1 GiB. Tests: seeded store workloads with reorgs under a budget (window contiguous at
  head, in-window proofs equal the unwound state, pruned blocks out of window), a state over
  the budget is refused, and a database workload with crash/reopen under a budget (no
  `history_drops`, rebuilt window within the budget).
- 2026-11-05: multi-key historical `eth_getProof`: `history.Store.get_proofs` walks the
  account path once and the storage trie once for all keys (sorted, deduplicated `ProofSet`
  of slices into the store), wired through `Database.proofs_at`, `Journal.proofs`,
  `Chain.proofs_at` into the historical RPC path. Bench (`db/history proof`, 16-block heavy
  window, oldest + 1): 1 acct + 64 keys 344-384 -> 48-56 µs, + 256 keys 1307-1314 -> 96-98
  µs vs the old per-key path. Tests: seeded store differential (random workloads with
  reorgs, random key sets with duplicates and absent keys, absent account, empty storage,
  every block of the window, before and after pruning) against per-key `get_proof`, a fuzz
  target, and `proofs_at` vs `proof_at` in the database history workload.
