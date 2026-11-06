# Disk-backed state

Status: design, phase 0 (measurement) done. Owner: trie-db lane. Measurement:
`zig build bench -Doptimize=ReleaseFast -- db/footprint` (`src/execution/db/footprint_bench.zig`).

Bottom line: today `State` holds every account, every slot, and every trie node in RAM, and a
checkpoint serializes all of it. That costs ~570-780 bytes per account and ~280-360 bytes per
slot, so a Base-mainnet-sized state needs roughly 0.4-2.4 TiB of RAM (plus as much again for the
history store) and 100-480 GiB per checkpoint. This document picks a disk-backed design: a
TigerBeetle-style LSM forest on a block grid inside the existing engine file, keyed by hashed
keys, with trie branch records stored by path (reth's `AccountsTrie`/`StoragesTrie` model),
bounded static caches, and checkpoints that write a manifest instead of the state.

## 1. What the in-memory state costs today

Measured on aarch64-macos (Apple M4 Pro), ReleaseFast. Every byte is counted by a counting
allocator around the real structs and pools; nothing is estimated from field lists.

Per-structure bytes (from `@sizeOf` and std `HashMapUnmanaged` allocation):

| Structure | Bytes per entry (bucket) | Notes |
| --- | ---: | --- |
| `State.account_table` bucket (`Address` -> `AccountEntry`) | 117 | 1 metadata + 20 key + 96 value |
| `StateTrie.entries` bucket (`Hash` -> `Entry`) | 129 | 1 + 32 + 96 (a second account copy) |
| `State.storage_table` bucket (`SlotKey` -> `u256`) | 97 | 1 + 64 (key padded to 16 B align) + 32 |
| account-trie pool node | 194 | 152 hot `Node` + 34 cached `RlpNode` + 8 rehash order word |
| storage-trie pool node | 114 | 72 hot `Node` + 34 cached `RlpNode` + 8 rehash order word |
| history store, per state node (when on) | ~299 | 65.0 MiB / 227 620 nodes (PERF.md, history) |
| checkpoint image (`snapshot.zig`) | 92 / acct, 84 / slot | also staged in RAM while it streams |

std hash maps keep load at or under 80% and round capacity up to a power of two, so the bytes
per entry of a table swing between 1.25x and 2.5x the bucket size depending on the count.

Trie nodes per entry (random keccak keys, so this is the shape of real tries):

| Shape | account nodes / account | storage nodes / slot |
| --- | ---: | ---: |
| 100k accounts, 1k contracts x 64 slots | 1.386 (138 620) | 1.391 (89 000) |
| 1M accounts, 10k contracts x 64 slots | 1.359 (1 358 887) | 1.391 (890 000) |
| 10k accounts, 100 contracts x 10k slots | 1.388 (13 878) | 1.389 (1 389 100) |

Bytes per account and per slot, tables sized to exactly the live count ("tight") plus live trie
nodes. Per account = account table + `entries` map + account-trie nodes; per slot = storage table
+ storage-trie nodes:

| Shape | B / account | B / slot | tight total | reserved by `State.init` |
| --- | ---: | ---: | ---: | ---: |
| 100k acct, 64k slots | 591.4 | 357.2 | 78.2 MiB | 119.7 MiB |
| 1M acct, 640k slots | 779.5 | 317.5 | 937.2 MiB | 1353.2 MiB |
| 10k acct, 1M slots (deep storage) | 672.3 | 361.8 | 351.4 MiB | 530.0 MiB |
| at exactly 80% load (no power-of-two rounding) | 573 | 280 | | |

"Reserved" is what a node allocates today under the bench sizing rule (pools at 3 nodes per
entry + 1024, so an apply never runs out). The 80%-load row is the best a hash table can do:
146 + 161 + 1.37 x 194 per account, 121 + 1.39 x 114 per slot.

### Extrapolation to Base mainnet

There is no exact public count of live accounts and slots in Base mainnet state. Public
indicators, all approximate: Ethereum L1 state is commonly cited at roughly 3e8 accounts and
1.5e9 storage slots; public Base posts and studies report that Base adds state far faster than
L1 (hundreds of GB of logical state per year, most of it storage slots) and that a Base reth
full node needs on the order of 2 TB of disk. So this design plans for a range, with 500M
accounts and 2B slots as the planning point:

| Assumed state | State in RAM (80% load .. measured worst) | + history state copy | checkpoint image | trie nodes |
| --- | ---: | ---: | ---: | ---: |
| 300M accounts, 1B slots | 421 .. 555 GiB | +502 GiB | 104 GiB | 1.80B |
| 500M accounts, 2B slots | 788 .. 1037 GiB | +965 GiB | 199 GiB | 3.46B |
| 1B accounts, 5B slots | 1836 .. 2412 GiB | +2317 GiB | 477 GiB | 8.32B |

Hard walls hit before RAM does:
- `NodeIndex` is `u32`: one pool holds at most 4.29B nodes; 5B slots need 6.95B storage nodes.
- `State.Config` counts are `u32`, and `Database.Config.checkpoint_staging_bytes` is `u32`: a
  checkpoint image caps at 4 GiB, about 45M accounts with no storage.
- Open decodes the whole image and rebuilds the trie: 1.1-1.4 s at 1M accounts today
  (PERF.md, restart), so hours at mainnet scale.

## 2. Requirements

- Zero dependencies; all disk IO through the `Storage` duck type (`SimStorage` in tests,
  `IoStorage` over `utilities.io` io_uring/kqueue in production).
- Static allocation: every cache, memtable, buffer, and queue sized from config at start; no
  allocation per block.
- Crash-safe with the existing superblock + journal: after a crash at any point, open yields
  the newest durable checkpoint plus the hash-chained journal prefix, as today.
- DST: compaction and flush scheduled by commit count, never by wall clock; same seed, same
  disk image.
- 200 ms blocks (sealed at 150 ms): reads, root, and commit fit the slot with margin.
- Memory bounded by config, independent of state size (apart from small per-table indexes).
- Unchanged consensus behavior: same roots, proofs, and witnesses, byte for byte.

## 3. Options

| | Copy-on-write B+tree (MDBX/LMDB style) | LSM forest on a grid (TigerBeetle style) | Append-only node log + compaction |
| --- | --- | --- | --- |
| Point read | best: 1 leaf read, interior pages cached | 1-2 block reads with filters + fences | 1 read, but needs a full key -> offset index |
| Write amplification | worst: a random key dirties a whole page (16 KiB / ~100 B = ~160x) | ~10-20x, sequential writes | ~2-4x, sequential |
| Index RAM | interior pages (~0.5 GiB at plan point) | fences + filters (~0.5-1 GiB) | key -> offset for 3.5B nodes: ~56 GiB, or an on-disk index (an LSM again) |
| Crash safety | root swap in the superblock (natural fit) | manifest + free set in the checkpoint (natural fit) | log + index checkpoint |
| Static memory, deterministic | yes | yes (TigerBeetle runs this in Zig) | yes |
| Complexity | medium (page splits, free list, two-root GC) | high (compaction, manifest, pacing) | low write path, hard GC |

Workload at 200 ms blocks: a typical block writes ~1k accounts + 1k slots, a heavy one 1k + 4k,
plus ~10 trie branch updates per changed leaf before sharing. Keys are keccak hashes, so writes
are uniformly random. A B+tree that flushes every block dirties one page per changed key:
~5k x 16 KiB x 5 blocks/s = ~400 MB/s; coalescing over a 60 s checkpoint only removes repeats,
not random spread. An LSM writes each entry once per level, sequentially: ~5k x ~100 B x ~15
levels-worth x 5/s = tens of MB/s. The append-only log has the cheapest writes but needs an
index that is either too big for RAM or is itself an LSM.

Decision: LSM forest on a block grid. Reasons: write amplification an order of magnitude below
a B+tree for uniformly random hashed keys, sequential IO, a proven Zig design with static
allocation and deterministic compaction pacing (TigerBeetle), and a manifest that slots into
our superblock + fallback-checkpoint protocol. Its weakness, read amplification, is handled by
per-level filters, in-memory fences, a static block cache, and batched prefetch (section 6).

## 4. Design

### 4.1 Layout

The engine file keeps its superblock copies, checkpoint zones, and journal ring, and gains a
grid: fixed-size, checksummed blocks addressed by index (`[superblock][ckpt A][ckpt B]
[journal][grid ...]`). A free set (one bit per grid block, ~8 MiB for 4 TiB of 64 KiB blocks)
tracks allocation. Checkpoint zones shrink from "the whole state" to "manifest + free set +
retained chain blocks", O(tables + retention), a few MiB.

### 4.2 Trees (the forest)

All keys are fixed width; values are length-prefixed and small.

| Tree | Key | Value | reth equivalent |
| --- | --- | --- | --- |
| accounts | keccak(address) 32 B | nonce, balance, code hash, slot count (EIP-7610) | `HashedAccounts` |
| storage | keccak(address) 32 B, keccak(slot) 32 B | value, leading zeros trimmed | `HashedStorages` |
| trie branches | owner (zero = account trie, else keccak(address)) 32 B, packed path <= 33 B | state mask, hash mask, child refs, extension path | `AccountsTrie`, `StoragesTrie` |
| codes | code hash 32 B | (grid address, length) into an append-only code log | `Bytecodes` |
| history (phase 5) | owner, path, block | versioned node | base/base `AccountTrieHistory`, `StorageTrieHistory` |

Hashed keys only, no plain-state tables. Trie order equals key order, so the root walk and
proofs are range scans; the EVM hashes the address and slot it reads (~70-150 ns with the SIMD
batch, already done on every write today). This halves disk and write volume versus reth's
plain + hashed pair. Leaves are not stored as trie nodes: a leaf is derived from its account
or slot record. Only branches (with the extension above them folded in, like reth's
`BranchNodeCompact`) are stored, about 0.39 per leaf.

Disk estimate at the plan point: ~90 B per account record, ~85 B per slot record (prefix
compression shares the owner hash within a data block), ~80 B of branch records per leaf, so
~0.45 TB before ~10% LSM space amplification.

### 4.3 Tables, levels, filters

Each tree is a leveled LSM: a mutable memtable, one immutable memtable being flushed, then
levels of sorted, immutable tables with a growth factor of 8. A table is a run of 16 KiB data
blocks (sorted entries, prefix-compressed keys) plus an index block (first key of each data
block). Resident per table: fences (8-byte key prefix per data block: ~150 MiB at the plan
point) and a Bloom filter for every level except the last (Monkey-style; ~90% of keys live in
the last level, so filters cost ~0.3 GiB instead of ~3 GiB). A point miss on the last level
reads one data block.

Compaction runs in bounded steps paced per durable commit (TigerBeetle's beats and bars): each
commit grants a fixed number of grid block reads/writes, so compaction never stalls a slot and
is a pure function of the commit sequence (DST). The memtable holds at least one bar of
commits; a full memtable with compaction behind applies backpressure (`error.Busy`, as the
journal does today) rather than allocating.

### 4.4 State trie over the store

The state root becomes a sparse trie over the branch tree, the same model `trie/sparse.zig`
already uses for witnesses: unresolved child refs are resolved on demand.
- Bounded static node cache: the account trie's top 4 levels pinned (~70k branches, ~40 MiB),
  plus a CLOCK cache of decoded branches for the rest, shared with storage tries.
- Per block: resolve the branches on every changed path (cache, else grid reads, batched),
  apply the changeset, rehash dirty nodes (existing batched keccak and rehash pool), and write
  the changed branch records to the memtable. Removed branches become tombstones.
- Dirty nodes stay pinned until their records reach the memtable; capacity is bounded by
  `block changes x depth`.

### 4.5 Commit, journal, checkpoint

- Journal: unchanged. `block_and_head` still carries the changeset, still one write and one
  sync per block. Durability of a block is the journal entry, as today.
- Apply: the changeset's new values go to the account/storage memtables, the trie's changed
  branches to the branch memtable. No grid IO on the commit path except paced compaction.
- Checkpoint: at a bar boundary (no compaction step in flight), flush the memtables to level 0
  tables, then write the manifest (table list per level, with checksums and key ranges), the
  free set, and the retained chain blocks into the idle checkpoint zone; sync; write the
  superblock naming it with `journal_start`. Size is O(tables + changes since the last
  checkpoint), not O(state); the full-image staging buffer goes away.
- Block reuse: a grid block released by compaction stays allocated until no retained
  checkpoint (newest or fallback) references it, i.e. it joins the free set two checkpoints
  later. That keeps the fallback checkpoint fully readable, the property the engine's
  redundancy argument relies on today.
- Open: superblock -> manifest -> fences and filters -> replay the journal tail into the
  memtables. O(journal tail + tables), seconds at any state size; no trie rebuild.

### 4.6 Unwind, reorgs, history

- Unwind applies a changeset's old values as new writes (the same data `State.unwind` uses),
  so a reorg is ordinary memtable writes plus a root update. Depth is bounded by the retained
  changesets in `ChainStore`, as today; L2 reorgs are shallow (unsafe head back to safe).
- Recent changesets must stay retained at least as far back as the deepest reorg we accept;
  nothing else depends on keeping old tree versions.
- History (phase 5) moves to its own tree keyed `(owner, path, block)`: "newest version at or
  before N" is a seek, the window prunes by dropping shadowed versions in compaction (like
  base/base's `BlockChangeSet` reverse index, but done by the compaction filter). This removes
  the in-memory history state copy (~299 B per node) and the rebuild on open, and makes
  base/base's 15-day window possible.

### 4.7 Proofs and witnesses

- `eth_getProof` at head walks branch records from the root (cache, else grid) and takes leaf
  values from the account/storage trees; leaf nodes are re-encoded on the fly.
- `debug_executionWitness` uses the same walk (the sorted multi-key walk of
  `visit_paths_in`, over the store instead of the pool); older blocks keep coming from history.
- Every node read from disk is checked against its parent's reference, as history walks do now.

## 5. Static memory at the plan point (500M accounts, 2B slots)

| Item | Size |
| --- | ---: |
| block cache (CLOCK, config) | 4-16 GiB |
| fences | ~0.15 GiB |
| filters (all but the last level) | ~0.3 GiB |
| pinned top trie levels + node cache | 0.1-1 GiB |
| memtables (2 per tree, one bar of commits) | ~0.3 GiB |
| free set, manifest | ~10 MiB |
| total | ~5-18 GiB, set by config, not by state size |

## 6. Read-path latency targets at 200 ms blocks

| Path | Today (in memory) | Target |
| --- | ---: | ---: |
| account/slot read, cache hit | 18-24 ns | <= 1 us |
| account/slot read, miss | n/a | 1 grid read, p99 <= 200 us on NVMe |
| cold reads of one block | n/a | <= 20 ms of the 150 ms seal budget, batched at QD >= 32 |
| state root, typical block | ~7 ms | <= 30 ms incl. branch resolution |
| commit (journal sync) | ~1 fsync | unchanged |
| open | 1.1-1.4 s at 1M accounts | <= 5 s at any state size |

Serial misses cannot meet the cold-read target (5k misses x 100 us = 500 ms). Reads must be
batched: prefetch each transaction's sender, recipient, and access list before execution,
and resolve each block's changed trie paths in one batched pass; io_uring submits them
together. Refills of the block cache never wait on a write and are bounded per block.

## 7. Testing

- DST over `SimStorage`: crash, torn write, and bit rot at any point in flush, compaction,
  checkpoint; recovery equals the last durable commit's root.
- Differential oracle: the in-memory `State` stays as the reference. Random changesets with
  apply/unwind on both; every root, read, proof, and witness must match byte for byte.
- Seeded and coverage fuzz for every on-disk decoder (data block, index block, manifest, free
  set, branch record).
- Benchmarks: point read hit/miss, block cold-read batch, root over store, compaction MB per
  block, open time, at 1M, 10M, and 100M synthetic entries.

## 8. Phases

0. Measure (done): `db/footprint` bench and this document.
1. Grid + free set + immutable sorted tables (writer, reader, point lookup, range scan,
   checksums) over `Storage`, superblock v3 naming a manifest; first user: the code store
   (append-only code log + table index), taking `code_arena` out of RAM and out of the image.
   Smallest useful step: real data on disk, the crash-safety and block-reuse rules exercised,
   no compaction yet (codes are immutable).
2. Flat state LSM: account and storage trees with memtables, leveled compaction paced per
   commit, filters, fences, block cache. `State` reads through it; checkpoints stop
   serializing the flat tables. Trie still in memory, built by range scan at open.
3. Trie branch store + sparse root over it, bounded node cache; drop the full in-memory pools.
   Checkpoints become manifest-only; open no longer rebuilds anything.
4. Proofs and witnesses over the store; batched prefetch; meet the section 6 targets.
5. History on disk (`(owner, path, block)` tree), base/base's 15-day window, no rebuild on open.
6. Scale proof: synthetic 100M+ entry state, then state import from a public snapshot.

## 9. Corrections from phase 1

- The superblock does not name the manifest. The engine streams its free set ahead of the
  caller's checkpoint bytes, and the table list (manifest) is part of the caller's bytes;
  superblock v3 only adds the grid size. Same protection (the superblock names a checkpoint
  whose bytes include the manifest), no extra on-disk structure. Section 4.5 still holds.
- Codes are stored inline as table values (a record never spans a block, so a code is at most
  the block payload, ~64 KiB at 64 KiB blocks), not in a separate code log: codes are
  immutable and phase 1 compacts nothing, so a log only adds an indirection. Revisit with
  compaction (a log keeps compaction from rewriting code bytes).
- Taking codes out of RAM needs a read path that does not hand out evictable slices, because
  `code_by_hash` callers (the evm caches the slice for a whole block) are synchronous and
  hold the slice. Codes first leave the checkpoint image while staying resident; they leave
  RAM with phase 4's batched prefetch (or per-block pinning). See the trie-db lane Decisions.
- Open reads tables in an explicit engine open phase: after the checkpoint loads and before
  journal replay the engine pauses (`Consumer.on_checkpoint_loaded`), the caller scans its
  tables through the normal asynchronous storage interface, then resumes (`open_resume`);
  data that does not verify resumes as corrupt and falls back like a rotten checkpoint. The
  storage interface gained no synchronous read.
- Phase 1d (done): codes are in tables and out of the image, still in `code_arena`. A
  watermark on the append-only arena says which codes tables hold; the flush before each
  checkpoint spends the checkpoint's per-commit block budget; when the table list is full,
  all codes are rewritten from RAM and the old blocks freed through the free set. Measured in
  docs/PERF.md "db code tables".
- Phase 2a (LSM tree primitive, done; see docs/PERF.md "db LSM tree"): a checkpoint may start
  in the middle of a compaction job instead of only at a bar boundary. The tree's checkpoint
  bytes carry the manifest (the job's inputs, still live), both memtables (so no flush is
  forced before a checkpoint), and the blocks the job acquired so far; open releases those
  orphans and the job reruns. Filters are rebuilt by the open scan rather than stored (open
  scans every table in phase 2 anyway); they move to the grid with phase 3's scan-free open.
  Measured write amplification at ~2.6M storage entries is 6.8x (whole blocks over logical
  bytes), consistent with the 10-20x planned for the full-size tree.
