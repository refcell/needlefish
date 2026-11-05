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
  (`db/history.zig`; in memory, rebuilt by `reset` after restart; not yet fed by `Database`)
- [x] Window pruner: bounded work per tick, removes history older than the window; crash-safe
  by rebuild (history is in memory; `reset` at the recovered head, see Decisions).
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
- [ ] Node canonical index after a reorg back (node lane, found here): `Chain.mark_canonical`
  stops at the first matching entry, so after head A6 -> side B5 -> A6 the number index still
  maps 5 to B5 (number-tagged RPCs resolve the side block). Clear entries above a lower head.
- [x] Witness codec for the proof lane: canonical binary encoding of a `Witness` (strict
  decoder, encode(decode(x)) == x) plus a keccak256 preimage view (iterator + lookup by digest).
  (`db/witness_codec.zig`)
- [ ] Witness size + build-time benchmarks (nodes, bytes, us per block) for 1k-account and
  storage-heavy blocks; record in docs/PERF.md.
- [ ] Byte-compare our `debug_executionWitness` against reth's output for public fixture
  blocks (committed small vectors); document any intended differences.
- [ ] Witness generator memory: default limits allocate ~40-60 MB at node start even if
  `debug_executionWitness` is never called; size from limits more tightly or allocate through
  `utilities.lazy_alloc` (node lane pattern). Large witnesses can exceed the 1 MiB HTTP buffer.
- [ ] Witness generation blocks the state for one unwind + re-apply per block between target
  and head; consider generating from the history store instead (no state disturbance).

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
- History is not journaled: it is derived data. After a restart it is rebuilt with
  `reset(state_trie, head)` at the recovered head; proofs for blocks before that head are
  unavailable until the window refills (one window of blocks). Journaling every node
  version would multiply the journal volume per block for data the node can regenerate.
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

- Database-owned history (`DatabaseType`, `Config.history`, null = off): the database owns a
  `history.Store` and enables `StateTrie.track_changes` only when it is configured. Live head
  moves update it inside `move_state`: unwinds, then `unwind_to(fork point)`, then
  `commit_block` after each applied block (a state root per applied block, so a multi-block
  reorg costs one extra root per block); `commit_applied` commits its one block. Replay at
  open never touches history; `open` ends with `reset` at the recovered head (O(state) once;
  older proofs return as the window refills). Any history failure (`HistoryFull`, a reorg
  below the window, `NotNextBlock`) never fails the operation and never touches state: the
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
