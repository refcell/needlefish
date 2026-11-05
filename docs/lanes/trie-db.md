# Lane: trie-db

Owns `src/execution/{trie,db}`. Reference: reth trie/db, base/base `crates/execution/trie`.

## Backlog
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
- [ ] Parallel storage-trie rehash: in a storage-heavy block, hashing dirty storage tries
  (~2.4 ms) and the account trie (~1.8 ms) is now over half the block. Split the dirty storage
  roots across worker threads (one pool, disjoint subtries).
- [x] One fsync per `execute_and_commit`: journal block + head as one entry (was 2 fsyncs,
  ~7.5 ms durability cost per block).
- [x] Compact node layout (packed paths, per-kind body, cached refs out of line).
- [x] Historical proofs store (base/base `crates/execution/trie`, `BaseProofsStore`): per-block
  versioned account/storage leaves + trie node preimages for a retention window, so
  `eth_getProof` works at any block in the fault-proof window without re-execution.
  (`db/history.zig`; in memory only, not yet journaled or fed by `Database`)
- [ ] Window pruner: bounded work per tick, removes history older than the window; crash-safe
  through the storage engine journal.
- [ ] Execution witness (`debug_executionWitness`): touched trie nodes + codes + headers for a
  block, verified by re-executing statelessly against a sparse trie built from the witness.
- [ ] Differential tests: historical proof at block N == proof from a State unwound to N;
  witness-only re-execution root == stored root (base/base `witness_differential`).
  (historical half done in `db/history_test.zig`; witness half pending)

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
  tries and applies dirty accounts sorted. Single-threaded for now; parallel subtrie hashing
  only once benchmarks show hashing dominates block time.
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
  node. `commit_block` does a `count` walk first, so `HistoryFull` stores nothing; versions
  equal to the path's newest one are skipped (after an unwind, rehashed-back nodes repeat).
  Two version size classes (160 B: leaves, extensions, sparse branches; 646 B: dense
  branches). Lookup is O(versions at the path newer than N), at most the window length; fine
  for windows in the thousands, a jump-pointer chain is the upgrade if long windows need it.
  Paths are never freed (stale paths keep one base version): bounded by `paths_max`; the
  window pruner item should reclaim them.

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
