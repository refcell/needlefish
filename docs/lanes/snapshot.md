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
- [ ] reth table decoders (Compact): plain or hashed accounts, storage, bytecodes, the
  snapshot block header and the 256 hashes below it.
- [ ] `base snapshot import`: stream the snapshot into the needlefish store, recompute the
  state root, require it to equal the snapshot block's header `stateRoot`.
- [ ] Spot-check 10,000 random accounts and slots against public RPC at the snapshot block.

## Decisions

- 2026-11-06: the snapshot writer is reth 2.5.2 with storage v2 likely: plain state tables
  are not maintained there, so import reads `HashedAccounts` / `HashedStorages` (already in
  trie key order, exactly what the streaming root needs) and `Bytecodes`. Headers are in
  static files, not in the state component, so the expected state root comes from the
  block header over public RPC (bound by its hash). Confirm `Metadata["storage_settings"]`
  on the real file first.

## Log

- 2026-11-06: Sepolia `state` component download started (resumable, 8 ranges).
