# Lane: trie-db

Owns `src/execution/{trie,db}`. Reference: reth trie/db, base/base `crates/execution/trie`.

## Backlog
- [x] Merkle Patricia Trie: node encoding (RLP), in-memory trie, root computation, proofs (eth_getProof), ordered-trie root for tx/receipt/withdrawal roots. No recursion. Vectors from ethereum/tests TrieTests.
- [ ] Fast incremental state root: sorted batch updates, parallel hashing of subtries, cached branch nodes.
- [ ] Storage engine (own design, TigerBeetle-inspired): append-only data file + fixed-size block grid or LSM, checksummed blocks, crash-safe superblock, all disk I/O through `utilities.io` (io_uring on Linux), static memory budget. Flat account/storage tables + history for reorgs.
- [ ] State provider implementing the evm `Host` backend: accounts, storage, code-by-hash, block hashes; overlay/journal for pending block execution; commit + state root.
- [ ] Block/receipt/header storage and canonical chain indices; reorg (unwind) support.
- [ ] Fault injection tests on the simulated disk (torn writes, corruption, crash at any point) — state must recover to last committed block.
- [ ] Benchmarks: state root of N updates, random reads, commit latency.

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
- Trie node stores path/children/value inline (simple, ~300 B/node); compact later.

## Log
- 2026-11-05: MPT (rlp, nibbles, node, HashBuilder, mutable trie, proofs, ordered root);
  all ethereum/tests TrieTests vectors pass.
