# Lane: trie-db

Owns `src/execution/{trie,db}`. Reference: reth trie/db, base/base `crates/execution/trie`.

## Backlog
- [x] Merkle Patricia Trie: node encoding (RLP), in-memory trie, root computation, proofs (eth_getProof), ordered-trie root for tx/receipt/withdrawal roots. No recursion. Vectors from ethereum/tests TrieTests.
- [x] Fast incremental state root: sorted batch updates, parallel hashing of subtries, cached branch nodes.
- [x] Storage engine (own design, TigerBeetle-inspired): append-only data file + fixed-size block grid or LSM, checksummed blocks, crash-safe superblock, all disk I/O through `utilities.io` (io_uring on Linux), static memory budget. Flat account/storage tables + history for reorgs.
- [x] State provider implementing the evm `Host` backend: accounts, storage, code-by-hash, block hashes; overlay/journal for pending block execution; commit + state root.
- [x] Block/receipt/header storage and canonical chain indices; reorg (unwind) support.
- [x] Fault injection tests on the simulated disk (torn writes, corruption, crash at any point) — state must recover to last committed block.
- [ ] Benchmarks: state root of N updates, random reads, commit latency. (trie cases landed in
  `trie/bench.zig`; commit latency waits on the storage engine)
- [x] Durable database facade (`db/database.zig`): journal block/head entries, state moves
  only on head moves, checkpoints = State snapshot + chain blocks, crash-recovery tests.
- [x] Real storage backend over `utilities.io` (io_uring/kqueue): `db/storage/io_storage.zig`.
- [ ] Checkpoint fallback / redundancy so one rotten checkpoint block is not data loss.
- [ ] Batch keccak (crypto lane's SIMD batch, 74 vs 146 ns) for sibling nodes in
  `update_cache`; compact node layout (packed paths, out-of-line values).

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
- `DatabaseType(Storage)`: one operation per journal entry (block insert or head move);
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
- Trie node stores path/children/value inline (simple, ~300 B/node); compact later.

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
