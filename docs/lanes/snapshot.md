# Lane: snapshot

Owns `src/execution/import/*` (new) and the snapshot import command. SYNC_PLAN M3: get
verified state at a recent block into needlefish from Base's public snapshots, then hand it
to the staged catch-up (M4).

## Source

`https://chain.base.org/api/snapshots` lists the latest modular snapshot per chain; each
manifest names components with sizes and blake3 hashes. Only `state` is needed: a reth MDBX
database (`db/mdbx.dat`). Base Sepolia, block 55006660: 310 GB compressed, 438 GB MDBX.
Base mainnet, block 53523727: 762 GB compressed, 1.14 TB MDBX. Downloaded artifacts stay
outside the repository.

## Backlog

- [x] Streaming state root over hashed-key-ordered accounts and slots, constant memory,
  untrusted-input errors; seeded differential against `StateTrie`.
- [x] Read-only MDBX reader (meta choice, B-tree walk, large pages, DUPSORT sub-pages and
  nested trees), checked against a file real libmdbx wrote (`etc/import/mdbx_fixture.c`)
  and libmdbx's own dump; seeded fuzz of damaged files.
- [x] reth table decoders (Compact): hashed accounts, storage entries, bytecodes, stage
  checkpoints (`import/reth.zig`); `HashedAccounts` + `HashedStorages` streamed into the root
  (`import/hashed_state.zig`, seeded differential against `StateTrie`, mutation-checked).
- [x] `base snapshot-import --db mdbx.dat`: reads `Metadata["storage_settings"]` and
  `StageCheckpoints["Finish"]`, recomputes the state root, requires it to equal the header
  `stateRoot` of that block (fetched over RPC, bound to its hash, or `--state-root`), and
  checks the streamed item counts against the table descriptors.
- [ ] Run it on the Sepolia snapshot (download, verify the manifest's blake3 of `mdbx.dat`,
  extract, import).
- [x] Stream the snapshot into the needlefish store: `base snapshot-import --out <path>`
  (`import/to_disk.zig`, disk-state import plan step 10): one MDBX pass into the four flat
  trees by bulk load, codes into the arena, head N via `Database.import_head`, checkpoint,
  reopen self-check. Not yet run on the Sepolia file.
- [x] The 256 block hashes below the snapshot block (RPC or `--headers` file, hash-chained).
- [ ] Spot-check 10,000 random accounts and slots against public RPC at the snapshot block.

## Decisions

- 2026-11-06: the snapshot writer is reth 2.5.2 with storage v2 likely: plain state tables
  are not maintained there, so import reads `HashedAccounts` / `HashedStorages` (already in
  trie key order, exactly what the streaming root needs) and `Bytecodes`. Headers are in
  static files, not in the state component, so the expected state root comes from the
  block header over public RPC (bound by its hash). Confirm `Metadata["storage_settings"]`
  on the real file first.

- 2026-11-07: `--out` (plan step 10). The library part is `import/to_disk.zig`
  (`ImporterType(Storage)` over `EntrySource`s, a `HeaderSource` and a storage `Driver`); the
  bin (`bin/base/snapshot_import_out.zig`) only opens files, ticks io_uring and prints. Order:
  `Bytecodes` first (each code keccak-checked into the arena) so every account's code hash is
  checked as it streams (`CodeMissing`); then `HashedAccounts` + `HashedStorages` once through
  `hashed_state.compute` with the `LeafSink` (slots, then accounts with storage roots) and
  `StateRootBuilder`'s record sink (`branch_record.encode` at `path_key`/`storage_key`, the
  same emission `db/disk_state_test.zig` imports) into the four bulk loaders, ticking on
  `Busy`; then `bulk_end`, the header chain's 256 hashes into the state, `import_head`
  (root must resolve in the trees), one unpaced checkpoint.
- 2026-11-07: headers. `fetch_chain` takes N first and walks down 255 parents (fewer near
  genesis), requiring numbers to descend by one and each hash to be the parent hash of the
  block above; each link is decoded by `header_json`, which binds its fields to its hash. The
  computed root must equal header N's `stateRoot` (`StateRootMismatch` otherwise, after the
  load). Sources: `--rpc` (one `eth_getBlockByNumber` each, retried with backoff on errors,
  e.g. the public endpoint's 25/s limit) or `--headers <file>` (one result object per line).
  `--test-head` (test-only, needs `--state-root`) uses synthetic hashes
  (`to_disk.SyntheticHeaders`): the file opens but must never execute real blocks.
- 2026-11-07: sizing (`to_disk.sizing`) from the MDBX counts (HashedAccounts items,
  HashedStorages items, Bytecodes count and bytes) and a `Shape` (`shape_node`: the node's
  64 MiB journal, 16 MiB chain, per-block changeset limits, reorg depth 4, 16384 branch writes
  per block, flush triggers 16k / 4096, 64 MiB code headroom). Flat key limits = count x 1.25
  + 1024; branch trees sized for 0.5 records per leaf (+ one root per storage trie); grid =
  estimated tree blocks (0.4 records per leaf at ~200 B, leaves exact) x 1.5 + code blocks +
  two tables per loader; code tables max(16, the code store's minimum for the arena);
  checkpoint staging = header + code table list + the trees' `checkpoint_size_max` + a
  snapshot of block hashes and unflushed codes + the chain ring; the zone holds it plus the
  free set image. Codes over ~4 GiB are refused (`CodesTooLarge`: plan step 9 widens the u32
  code limits; not needed until a snapshot measures that much). The sizing fixes tree layouts
  and the grid, so it is part of the file: `<path>.counts` records the counts
  (`Counts.encode`, magic + four u64) and every open sizes from it.
- 2026-11-07: self-check after reopen: head number, hash, root, the 256 block hashes, and a
  deterministic reservoir sample (64 accounts, 64 slots) read through the trie from the root
  (`DiskState.verify_leaf`: every node rebuilt from records and checked against its parent's
  hash) and from the flat trees. A missing storage-branch record is not caught by the open's
  root check (it only resolves the root record), only by reads below it: the in-repo test
  checks every leaf; the CLI checks the sample. Small additive hooks in the trie-db lane for
  this: `SparseState.account_hashed`/`storage_hashed`, `DiskState.verify_leaf`,
  `FlatTrees.tree_configs`/`checkpoint_size_max_of`, `Tree.checkpoint_size_max_of`,
  `CodeStore.tables_max_min`.

## Log

- 2026-11-06: Sepolia `state` component download started (resumable, 8 ranges).
- 2026-11-07: `--out` end to end (ReleaseSafe) on a generated reth-shaped MDBX file (real
  libmdbx, 20,000 accounts, 456,997 slots, 16 codes, 46 MB): `--test-head` imports in ~1 s
  (~40k accounts/s, ~0.9M slots/s, 6,704 + 162,042 records, 93 MiB of tables, 94 MB on disk
  of a 5.4 GB sparse file), reopens at head N with the root, 256 hashes and 128 samples
  matching. Peak RSS 5.7 GB, independent of the state: `shape_node`'s fixed buffers (branch
  memtables ~0.4M x 1.1 KiB x 2 per tree, DiskState memo and sparse pool, replay memtables).
  With the 256 real Base Sepolia headers below 55006660 (`--headers` file, and `--rpc`): the
  chain links and the synthetic root is refused (`StateRootMismatch`); a tampered header
  fails its hash (`HashMismatch`), a missing one `BlockNotFound`, before any file is created.
