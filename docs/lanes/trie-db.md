# Lane: trie-db

Owns `src/execution/{trie,db}`. Reference: reth trie/db, base/base `crates/execution/trie`.

## Backlog
- [x] Merkle Patricia Trie: node encoding (RLP), in-memory trie, root computation, proofs (eth_getProof), ordered-trie root for tx/receipt/withdrawal roots. No recursion. Vectors from ethereum/tests TrieTests.
- [x] Fast incremental state root: sorted batch updates, parallel hashing of subtries, cached branch nodes.
- [ ] Storage engine (own design, TigerBeetle-inspired): append-only data file + fixed-size block grid or LSM, checksummed blocks, crash-safe superblock, all disk I/O through `utilities.io` (io_uring on Linux), static memory budget. Flat account/storage tables + history for reorgs.
- [x] State provider implementing the evm `Host` backend: accounts, storage, code-by-hash, block hashes; overlay/journal for pending block execution; commit + state root.
- [ ] Block/receipt/header storage and canonical chain indices; reorg (unwind) support.
- [ ] Fault injection tests on the simulated disk (torn writes, corruption, crash at any point) — state must recover to last committed block.
- [ ] Benchmarks: state root of N updates, random reads, commit latency. (trie cases landed in
  `trie/bench.zig`; commit latency waits on the storage engine)
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
- Trie node stores path/children/value inline (simple, ~300 B/node); compact later.

## Log
- 2026-11-05: MPT (rlp, nibbles, node, HashBuilder, mutable trie, proofs, ordered root);
  all ethereum/tests TrieTests vectors pass.
- 2026-11-05: StateTrie (account + shared-pool storage tries, dirty-set incremental root,
  account/storage proofs), differential-tested against HashBuilder.
- 2026-11-05: state provider: State + block Overlay (O(1) wipes via epochs), canonical
  Changeset codec, unwind; tested with replica replay and multi-block reorgs.
- 2026-11-05: trie benchmarks: 1k-account state block on 100k accounts in 2.0 ms.
