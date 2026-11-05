# Performance tracking

Numbers from `just bench` (`zig build bench -Doptimize=ReleaseFast -- [filter]`). The
harness (`src/testing/bench.zig`) calibrates each case to ~50 ms per sample and reports the
fastest of 5 samples. Claim a speedup only with before/after rows from the same machine.

How to add a case: put a `cases` table next to the hot code (fields `name`, `iterations`,
`run: *const fn (u32) u64`, optional `bytes_per_op`) and list it in
`src/testing/bench_main.zig`. Append a dated section here when a result moves.

## 2026-11-05 baseline (aarch64-macos, Apple Silicon, ReleaseFast, de38bfa)

| Case | ns/op | MB/s | Notes |
| --- | ---: | ---: | --- |
| field/bn254 mul | 19.7 | | Montgomery, 4 limbs |
| field/bls12-381 mul | 31.5 | | 6 limbs |
| keccak256/32B | 145.8 | | std: 139.4 |
| keccak256/32B batch | 74.0 | | per message, SIMD batch |
| keccak256/4KiB | 4283.5 | 956 | std: 4206.8 |
| sha256/32B | 25.3 | | std: 32.3 |
| sha256/4KiB | 1406.4 | 2912 | std: 1600.4 |
| rlp/validate 64x32B list | 383.1 | 5520 | 2115-byte list |
| rlp/reencode 64x32B list | 651.0 | 3249 | |
| sim/cluster seed | 3881808 | | 16 simulated minutes per seed (3.9 ms) |

## 2026-11-05 trie (aarch64-macos, Apple M4 Pro, ReleaseFast)

| Case | ns/op | Notes |
| --- | ---: | --- |
| trie/get 100k | 168 | includes ~146 ns keccak of the key |
| trie/block 1k puts+root on 100k | 1 699 793 | dirty-path rehash, 1.7 µs/update |
| trie/hash_builder 10k leaves | 3 019 320 | 302 ns/leaf, streaming |
| trie/ordered root 200x200B | 70 763 | tx/receipt root shape |
| trie/state block 1k accounts | 2 013 084 | StateTrie, 100k accounts |

## 2026-11-05 trie batch keccak (aarch64-macos, Apple M4 Pro, ReleaseFast)

Dirty nodes are rehashed level by level (deepest first) and equal-length encodings go through
`keccak256_batch` (2 lanes on NEON). Same machine, same session, interleaved runs.

| Case | before ns/op | after ns/op | Change |
| --- | ---: | ---: | --- |
| trie/block 1k puts+root on 100k | 1 730 830 | 1 308 295 | -24% (after runs 1.31-1.41 ms) |
| trie/state block 1k accounts | 1 977 875 | 1 602 292 | -19% (after runs 1.60-1.65 ms) |

## 2026-11-05 db (aarch64-macos, Apple M4 Pro, 48 GB, internal SSD, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/` (whole db run ~8 s). Block = 1k account writes
(nonce+balance) + 4k storage writes on distinct existing keys, over 100k accounts (1k
contracts x 64 slots). Changeset of one block: 629 018 bytes.

| Case | ns/op | MB/s | Notes |
| --- | ---: | ---: | --- |
| db/block 1k acct+4k slot apply+root | 13 294 208 | | overlay writes + build_changeset + State.apply + root, in memory |
| db/changeset encode 1k acct+4k slot | 50 326 | 12 499 | |
| db/changeset decode 1k acct+4k slot | 215 150 | 2 924 | strict canonical decode |

Commit loop (`run_commit`, own runner): 128 blocks in 4 rounds of 32, a timed checkpoint after
setup and after each round (5 samples, so p99 = max). Each block waits until its head entry
is durable before the next starts (then 2 journal entries, 2 fsyncs per block). Overlay writes
are outside the clock. "cpu" = `execute_and_commit` returning; "durable" = head entry fsynced.

| Storage | cpu p50 | cpu p99 | durable p50 | durable p99 | checkpoint p50 | checkpoint max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SimStorage (1-tick latency) | 13.5 ms | 17.9 ms | 13.6 ms | 18.0 ms | 14.6 ms | 16.6 ms |
| IoStorage, kqueue, temp file, F_FULLFSYNC | 13.4 ms | 16.5 ms | 21.0 ms | 26.0 ms | 40.2 ms | 53.1 ms |

Checkpoint = 17.1 MB (100k-account snapshot + 4 retained blocks): serialize + write + sync +
superblock copies. Takeaways: commit CPU (~13 ms) is the in-memory block cost; the state root
for 4k storage writes dominates (trie/state block 1k accounts alone is 2.0 ms). Durability
adds ~7.5 ms (two full fsyncs of ~630 KB). Second run on the same machine: cpu p50 13.1-13.8
ms, durable p50 21.0 ms, checkpoint p50 41.1 ms; sim p99 swings 18-27 ms (noise, laptop).

### 2026-11-05 db: one fsync per `execute_and_commit`

`execute_and_commit` now journals one `block_and_head` entry instead of a `block` entry plus a
`head` entry: 1.0 syncs/block (was 2.0). Same command, same machine, IoStorage (kqueue, temp
file, F_FULLFSYNC); "before" is one run on the previous commit, "after" two runs.

| Run | cpu p50 | cpu p99 | durable p50 | durable p99 | durable - cpu (p50) |
| --- | ---: | ---: | ---: | ---: | ---: |
| before (2 entries, 2 fsyncs) | 15.0 ms | 25.7 ms | 24.1 ms | 36.6 ms | 9.1 ms |
| after, run 1 (1 entry, 1 fsync) | 13.2 ms | 25.0 ms | 17.6 ms | 34.8 ms | 4.4 ms |
| after, run 2 | 11.2 ms | 12.8 ms | 15.3 ms | 17.6 ms | 4.1 ms |

The durability cost per block halves (about 9 -> 4 ms of fsync wait). The laptop was noisier
than the first db run (before-run cpu p50 15.0 ms vs 13.4 ms earlier), so compare the
durable - cpu column, not absolute numbers; p99 is dominated by CPU noise in noisy runs.

### 2026-11-05 db: storage-heavy block apply+root

Where `db/block 1k acct+4k slot apply+root` spent its time (temporary phase timers in the bench,
averages over ~1 500 blocks, ReleaseFast, loaded machine; not committed):

| Phase | before µs | after µs | What changed |
| --- | ---: | ---: | --- |
| overlay writes (bench's EVM stand-in) | 910 | 960 | nothing |
| `build_changeset` | 1 720 | 540 | sort was ~1 600 µs, now ~310 µs |
| `State.apply` | 2 660 | 1 900 | one address hash + lookup per slot run; batched keys |
| `StateTrie.flush` (storage rehash + account puts) | 2 960 | 3 160 | nothing (noise) |
| account trie root | 1 720 | 1 820 | nothing (noise) |

Fixes (all bit-identical; tests unchanged plus a sort-vs-reference test and a
`set_storage_slots` differential test):
- `Changeset.sort`: `std.mem.sort` (block sort) on 128-224 byte entries with a byte-wise
  `std.mem.order` compare took ~2 ms for 4k slots. Now pdqsort over `address[0..4] << 32 |
  index` words (most compares are one integer compare; ties compare `u160` address + slot
  through pointers), then an in-place cycle permutation (each entry moves once). Keys are
  unique, so the unstable sort gives the canonical order. +8 bytes per changeset entry.
- `State.apply`: the address keccak ran once per storage slot (4k extra hashes); now once per
  run of one address's slots. Slot and account keys go through `keccak256_batch` in pairs.
  `StateTrie.set_storage_slots` writes a run with one `entries` lookup.
- The dirty-account sort in `StateTrie.flush` is pdqsort (exact: duplicates are equal bytes).

Tried and dropped: an in-place counting sort by depth instead of pdqsort in the batched rehash
(collect order 230 -> 140 µs but the per-level length sort got slower by the same amount).

Interleaved runs of the before and after binaries (5 each, median; `db/` and `trie/state`):

| Case | before | after | Change |
| --- | ---: | ---: | --- |
| db/block 1k acct+4k slot apply+root | 10.34 ms | 7.93 ms | -23% (runs 9.4-10.5 vs 7.75-8.23) |
| db/commit sim cpu p50 (2 runs) | 10.1-10.5 ms | 7.8-8.3 ms | |
| db/commit os cpu p50 / durable p50 (2 runs) | 10.3-10.9 / 14.1-15.0 ms | 7.6-7.9 / 12.0 ms | |
| db/changeset decode | 2 921 MB/s | 3 142 MB/s | +8% (faster `check_sorted` compare) |
| trie/state block 1k accounts | 1.50-1.66 ms | 1.46-1.60 ms | noise |

What remains is mostly trie work this block shape really has. The block dirties 2 056 accounts
(1k written + ~1k contracts whose storage root changed) vs 1 000 in trie/state, and its
account-trie part (puts 750 µs + root 1 820 µs = ~1.25 µs per account) runs at the trie/state
rate. The 4k slot writes touch ~1k storage tries and dirty 9 822 storage nodes; their batched
rehash takes ~2 360 µs (collect 300, depth sort 230, level hashing 1 810), mostly keccak.
Storage writes in `apply` are ~420 ns per slot (two hash-table updates plus a trie descent,
cache-miss bound). Next step if this matters: hash dirty storage tries on worker threads
(lane backlog).

### 2026-11-05 db witness (aarch64-macos, Apple M4 Pro, 48 GB, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/witness` (`db/witness_bench.zig`, ~2 s; whole
`db/` run ~7.5 s). State = the db bench state (100k accounts, 1k contracts x 64 slots), every
contract running `old = SLOAD(cd[0]); SSTORE(cd[0], cd[32]); LOG1`. Each block is built once,
never committed, and measured 11 times (median). The write blocks' "execution" reads every
written key's old value once; the evm block runs 200 calls (distinct senders, distinct
contracts, one SLOAD + SSTORE each) through the real evm. Bytes = canonical
`witness_codec` encoding; keys = 20-byte addresses + 32-byte slot keys.

| Block | state nodes | bytes | codes | keys | build | load + replay |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1k account writes | 3 004 | 751 314 | 0 | 1 000 | 7.1 ms | 0.37 + 1.0 + 1.36 ms |
| 1k acct + 4k slot writes | 5 613 | 1 276 542 | 0 | 5 989 | 30.7 ms | 0.38 + 1.7 + 12.7 ms |
| 200 evm SLOAD+SSTORE calls | 1 484 | 391 701 | 1 | 611 | 4.4 ms | 0.38 + 0.51 + 1.25 ms |

"build" = `Builder.build` (proofs of every touched key, deleted keys' siblings, replay on
its scratch sparse state, witness copy-out); this table is the original builder, see
"2026-11-05 db witness builder: sorted multi-key walk" below for the current numbers. "load + replay" = `SparseState.reset` +
`load` (decoded witness) + `witness.replay` (reads + changeset, root checked against the
builder's).

| Block | recorder overhead | encode | decode | stateless evm |
| --- | ---: | ---: | ---: | ---: |
| 1k account writes | 4 us (200 -> 204 us of reads) | 1.21 ms, 619 MB/s | 1.00 ms, 752 MB/s | |
| 1k acct + 4k slot writes | 177 us (326 -> 503 us) | 2.80 ms, 455 MB/s | 1.73 ms, 740 MB/s | |
| 200 evm calls | 34 us (200 -> 235 us of execution) | 0.67 ms, 589 MB/s | 0.52 ms, 751 MB/s | 1.67 ms |

"stateless evm" = the 200 calls re-executed over `SparseState.database()` + `apply_evm`
(after load), vs 0.20 ms for the same calls over the full state. Two runs agreed within ~5%
(the storage-heavy build 29.5-30.7 ms, replay 11.4-12.7 ms).

Takeaways:
- Size: ~750 B per touched account for 1k scattered accounts (3 nodes per account; the top
  two account-trie levels are shared), ~1.3 MB for the storage-heavy block. A 1 MiB HTTP
  buffer is already too small for it (hex doubles it).
- `Builder.build` is 4-5x the cost of applying the same block to the full state (30.7 vs
  8.2 ms for the storage-heavy block): it proves each key separately (no shared path walk),
  then replays the block on a sparse trie that decodes every node from RLP. The replay half
  is what `load + replay` shows for the verifier (12.7 ms).
- `SparseState.reset` is O(pool capacity), not O(witness): ~370 us here for a 104 600-node
  pool (5x witness nodes estimated from the block shape), and it runs inside every
  `build` too. Size the pool from limits tightly or clear only used nodes.
- The Recorder costs ~30 ns per recorded key (bounded hash-set insert); noise for the
  account-only block.
- Codec: encode sorts by keccak256 of every item (~400 ns per node), decode re-hashes every
  item for the strict order check; both ~0.5-0.75 GB/s, small next to build.

## 2026-11-05 db witness builder: sorted multi-key walk (aarch64-macos, Apple M4 Pro, ReleaseFast)

Same bench and blocks as "db witness" above (`zig build bench -Doptimize=ReleaseFast --
db/witness`), two runs (medians of 11 each). `Builder.build` now collects candidate nodes in
one depth-first walk per trie over the touched keys sorted by hashed path (each node visited
once with its cached hash: no per-key proof, re-encoding, or keccak per node), pre-marks read
keys' proof nodes instead of replaying the reads, and applies only the changeset on the
scratch sparse trie. "unverified" = `build_with(.., .{ .verify_root = false })`: no post-root,
and blocks without deletions (all three here) skip the sparse apply. Witnesses are unchanged:
the same node counts and encoded bytes as before (and byte-equal to the old collection in
`db/witness_differential_test.zig`).

| Block | build before | build after | unverified | apply (full state) |
| --- | ---: | ---: | ---: | ---: |
| 1k account writes | 7.8 ms | 3.2-3.3 ms | 0.63-0.71 ms | |
| 1k acct + 4k slot writes | 36.9 ms | 15.8-16.0 ms | 4.6-4.7 ms | 8.2 ms |
| 200 evm SLOAD+SSTORE calls | 4.0 ms | 2.2-2.3 ms | 0.40-0.45 ms | |

"before" = the same machine just before the change (run-to-run spread ~15%; the table above
recorded 30.7 ms for the storage-heavy build). The verifier's `witness.replay` also got
cheaper (16.8 -> 9.9 ms storage-heavy, 1.48 -> 1.10 ms 1k-account): materializing a child of a
decoded branch now skips to its RLP item instead of decoding all seventeen.

Profile of the storage-heavy build before (temporary timers, per build): per-key proofs
14.2 ms, sparse reads replay 5.9 ms, sparse changeset apply 5.3 ms, post-root 2.8 ms, rest
< 0.2 ms. After: account walk ~1.4 ms, storage walks ~3.2 ms (mostly keccak of 5k keys and
cache misses on ~1k storage tries), sparse apply ~9 ms (it now also resolves the nodes the
reads replay used to), post-root ~2.6 ms.

Takeaways:
- The verified build is ~2x the full-state apply (16 vs 8.2 ms), down from 4.5x; the rest
  is the sparse apply (node resolution, RLP decode, per-write keccak of slot and address
  keys) and its root. Next: pass the walk's hashed keys into the apply and batch-hash keys.
- Collection alone (unverified, no deletions) is ~0.6x the full-state apply.

## 2026-11-05 db witness: hashed keys and batched sparse rehash (aarch64-macos, Apple M4 Pro, ReleaseFast)

Same bench (`zig build bench -Doptimize=ReleaseFast -- db/witness`), medians of 11; the
machine was loaded (load average 35-80), so ranges are over 3-4 runs and the "before" column
is the same tree just before the change. The builder hashes every touched key once (batched)
and hands the changeset's hashes to `SparseState.apply_hashed`; the verifier's `apply` hashes
keys in batches; storage is applied per account run with one account lookup per run; storage
and account roots are rehashed level by level with equal-length encodings paired through
`keccak256_batch` (all written storage tries in one pass). Witnesses are byte-identical (same
node counts and bytes below; differential-test witness digests equal before and after).

| Block | build before | build after | unverified before | unverified after | replay before | replay after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1k account writes | 3.2-3.3 ms | 2.5-2.6 ms | 0.66-0.84 ms | 0.64-0.68 ms | 1.10-1.23 ms | 1.04-1.07 ms |
| 1k acct + 4k slot writes | 15.7 ms | 12.5-13.1 ms | 4.6-4.75 ms | 4.2-4.65 ms | 9.9 ms | 8.2-9.4 ms |
| 200 evm SLOAD+SSTORE calls | 2.2-2.4 ms | 1.8-2.0 ms | 0.41-0.56 ms | 0.45-0.47 ms | 1.08-1.13 ms | 0.94-0.97 ms |

Stateless evm re-execution (`apply_evm`) 1.54 -> 1.31-1.34 ms. Two "before" storage-heavy
samples (30-33 ms build, 15-21 ms replay) were load spikes and are left out.

Takeaways:
- Hashing keys was a smaller share than estimated: the verified storage-heavy build still
  spends ~8 ms in the sparse apply. A whole-run `sample` profile (setup included) puts the
  rest in node keccak (the rehash itself), RLP decode (`decode_item`, `decode_node`, which
  also re-decodes dirty witness branches for their unloaded children's refs at rehash), and
  memmove of pool nodes. Decode is the next target.
- Do not hash read keys and changeset keys separately: the first cut (changeset hashed, then
  reads hashed for the walk) made the unverified build 30% slower (6.0-6.4 ms) because reads
  repeat the written keys; hashing `touched` once and looking up changeset entries fixed it.

## 2026-11-05 trie compact node layout (aarch64-macos, Apple M4 Pro, ReleaseFast)

`TrieType` nodes keep only what their kind needs: a packed path (2 nibbles per byte, stored in
hex-prefix layout) and inline value for leaves, 17 `u32` children for branches (the 17th is the
branch value as an empty-path leaf), and the cached `RlpNode` moved to a parallel array.
Lookups compare leaf paths against the packed key bytes directly.

| Memory (account config: 32-byte keys, 112-byte values) | before | after |
| --- | ---: | ---: |
| bytes per pool node (hot + cached ref) | 284 | 152 + 34 = 186 (-35%) |
| storage config node (33-byte values) | 204 | 72 + 34 = 106 (-48%) |
| live bytes per entry, 100k bench trie (138 493 nodes) | 393 | 257 |
| allocated bytes per entry, bench pool (4 nodes/entry) | 1 136 | 744 |

Timings: medians of 3-7 interleaved before/after runs on a loaded machine (single runs vary
up to ±15%).

| Case | before ns/op | after ns/op | Change |
| --- | ---: | ---: | --- |
| trie/get 100k | 173 | 166 | -4% (after runs 165-168, before 172-177) |
| trie/block 1k puts+root on 100k | 1 378 792 | 1 360 301 | noise |
| trie/hash_builder 10k leaves | 3 061 979 | 3 117 547 | noise (an earlier round had after lower) |
| trie/ordered root 200x200B | 73 308 | 73 874 | noise |
| trie/state block 1k accounts | 1 653 791 | 1 627 583 | noise |

## 2026-11-05 trie parallel storage rehash (aarch64-macos, Apple M4 Pro 14 cores, ReleaseFast)

`StateTrie.Config.rehash_threads` (also `db.state.Config.rehash_threads`; default 0) starts
a static pool at init. `flush` collects the dirty storage nodes serially (per-trie offsets,
change marks), splits them at trie boundaries into up to 4 chunks per thread (cap 64), and
the caller and workers claim chunks from one generation-tagged counter. Workers write only the
caches of their chunk's nodes; roots, caches and change marks are bit-identical to serial
(seeded differential threads 3-4 vs 0, plus a fuzz). The account trie still hashes serially
after the join.

Load average 25-60 on 14 cores during every run, so medians of interleaved runs:

| Case (threads) | 0 | 2 | 4 | 8 | Runs |
| --- | ---: | ---: | ---: | ---: | --- |
| trie/storage 4k slots (new case) | 3.40 ms | 2.57 ms | 2.37 ms | 2.28 ms | 9 (0: 3.19-3.74, 4: 1.91-2.98) |
| db/block 1k acct+4k slot apply+root | 8.05 ms | 7.05 ms | 6.87 ms | 6.89 ms | 7 (0: 7.92-8.50, 4: 6.74-7.19) |
| db/commit sim cpu p50 | 8.08-8.27 ms | | 6.68-7.21 ms | | 3 each |

`trie/storage` = 1k contracts x 64 slots, a block writes 4k random slots (precomputed key
hashes) then takes the root: ~9.8k dirty storage nodes per block, about 0.9 ms of writes,
2.3 ms of storage rehash (0.27 ms of it the serial collect) and 0.24 ms of account root at 0
threads. The other `trie/` cases (threads 0) are unchanged: get 164 ns, block 1.38 ms,
hash_builder 3.08 ms, ordered 84 us, state block 1.64 ms.

Tried first: one static range per thread. With 8 threads the caller hashed its 1/9 in
~210 us and then waited 550-850 us for the workers (late wakeups, descheduling and E-cores
on the loaded machine), so 8 threads gained little over 2. Claimed chunks fixed that.
Not parallel: the dirty-node collect (one walk, ~28 ns per node, ~12% of the rehash).

## 2026-11-05 p2p (aarch64-macos, Apple M4 Pro, ReleaseFast)

| Case | ns/op | MB/s | Notes |
| --- | ---: | ---: | --- |
| p2p/noise XX handshake | 633 434 | | ~1 580 handshakes/s per core; was 770 µs on std secp256k1, now `common.crypto.secp256k1`; X25519 (std) is most of the rest |
| p2p/noise transport seal+open 64 KiB | 83 000 | 785 | 16-block ChaCha20 passes (8-block tail) + std Poly1305; 8-block only: 729 MB/s; std AEAD: 338 MB/s |
| p2p/poly1305 std 64 KiB | 16 361 | 4006 | std; a 4-lane 26-bit variant gave +8%, not kept |
| p2p/snappy compress 128 KiB | 77 974 | 1 681 | semi-compressible payload |
| p2p/snappy decompress 128 KiB | 20 618 | 6 357 | |
| p2p/gossip rpc decode 128 KiB publish | 21 | | zero-copy: cost is independent of payload size |
| p2p/gossip seen insert | 5.7 | | open addressing, 8192 ids |
| p2p/gossip publish+drain to 8 peers | 64 539 | 2 031 | id hash + 8 framed RPCs (copy per peer) |
| p2p/block gossip end to end 128 KiB | 1 087 778 | 120 | sequencer service -> noise -> verifier service, one real signed block; no yamux/socket |
| p2p/block gossip sequencer 128 KiB | 300 315 | 436 | SSZ + sign + snappy + publish + drain (the EL's block hash is excluded) |

End-to-end split (same run, which was ~25% noisier than the rows above: handshake 833 µs):
sequencer ~0.30 ms, wire (noise seal+open of the ~90 KiB snappy frame) ~0.15 ms, verifier
~0.6 ms by subtraction. The verifier pays the block-hash check (keccak transactions root over
the full payload plus decoding every transaction), signature recovery, and decompression.
One block per 2 s costs ~0.05% of a core per peer hop.

Verifier stages (quiet rerun, µs per 128 KiB block): message id (snappy + sha256) 65,
decode (snappy + SSZ + keccak payload hash) 156, transactions root (keccak trie) 136,
recover signer 29, check transactions 1, then `pop_block` decoded again: 156. Fix: the
handler keeps the payload hash validation computed next to each accepted id and
`block.decode_known_hash` skips the second 128 KiB keccak (re-checked in Debug builds).

| case | before ns/op | after ns/op | change |
|---|---:|---:|---|
| p2p/block gossip end to end 128 KiB | 1 021 471 | 829 305 | -19%: verifier ~0.6 -> ~0.42 ms |

Remaining verifier cost is two keccaks over the payload (payload hash, transactions root;
different preimages, both required) at ~980 MB/s (`common/crypto/keccak`, crypto lane) and
two decompressions (message id, validation; ~20 µs each).

## Targets

- Simulator: keep a full seed under 50 ms as real components replace the models, so CI
  can keep running 20k seeds per push.
- Hashing: match or beat std at every size (single-message keccak is within 5% today).

## 2026-11-05 primitives (aarch64-macos, Apple M4 Pro, ReleaseFast)

| Case | ns/op | Notes |
| --- | ---: | --- |
| consensus/tx_encode_1559_512b | 64.0 | ~650-byte signed EIP-1559 tx |
| consensus/tx_decode_1559_512b | 98.4 | strict canonical, zero copy |
| consensus/tx_hash_1559_512b | 834.6 | streamed into keccak, ~1.2 ns/byte |
| consensus/tx_signing_hash_1559_512b | 813.2 | |
| consensus/tx_recover_sender | 32138.1 | crypto lane secp256k1 ecrecover + keccak |
| consensus/header_hash_prague | 919.1 | all optional fields present |
| consensus/receipt_encode_empty | 9.7 | |
| flz/compress_length_tx | 920.7 | same tx |
| l1_fees/tx_l1_cost_fjord | 1143.4 | FastLZ length + fee math |

## EVM (execution/evm)

2026-11-05, Apple M-series laptop, ReleaseFast, `zig build bench -- "evm:"`. One execution per
op against a freshly reset state (Prague rules).

| case | ns/op | notes |
|---|---|---|
| evm/arithmetic_loop_13k_ops | 9624.3 | ~0.74 ns per instruction (threaded dispatch) |
| evm/keccak256_loop_1000x64B | 171946.2 | ~172 ns per KECCAK256, dominated by the hash |
| evm/storage_loop_200 | 7591.6 | ~38 ns per cold SSTORE + warm SLOAD pair |
| evm/call_loop_200_staticcall | 23448.3 | ~117 ns per call frame push/pop |
| evm/value_transfer_tx | 701.5 | validate, buy gas, warm, settle, state reset |
| evm/erc20_transfer_tx | 1442.9 | 2 cold slots read+written, 2 keccak, LOG3 (~51k gas) |

Snailtracer (`just vectors` fetches the public bytecode from revm's bench fixtures), one
`Benchmark()` call of 165 962 868 gas, ReleaseFast, Apple M4 Pro, 2026-11-05, measured with
the shared machine at load average ~35, so treat it as a ceiling:

| case | ns/op | notes |
|---|---|---|
| evm: snailtracer | 50 479 625 | ~3.3 Ggas/s; arithmetic, memory, and jump heavy |

Not yet compared with revm on the same machine: building revm needs a Rust toolchain build
the shared disk cannot spare right now.

## Test suite time

`zig build test` runs on every push of every lane, so its wall time is a shared budget.
Find the slowest tests with `just test-times`. Keep any single test under ~1 s in Debug;
long simulations belong in `zig build sim` / swarm, not the unit suite.

2026-11-05: suite ~90 s run time; 73 s in one p2p discv5 cluster test (flagged to the lane).
