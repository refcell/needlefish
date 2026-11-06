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
- [ ] Read-only MDBX reader (meta pages, B-tree walk, large pages, DUPSORT), fuzzed decoder.
- [ ] reth table decoders (Compact): plain or hashed accounts, storage, bytecodes, the
  snapshot block header and the 256 hashes below it.
- [ ] `base snapshot import`: stream the snapshot into the needlefish store, recompute the
  state root, require it to equal the snapshot block's header `stateRoot`.
- [ ] Spot-check 10,000 random accounts and slots against public RPC at the snapshot block.

## Log

- 2026-11-06: Sepolia `state` component download started (resumable, 8 ranges).
