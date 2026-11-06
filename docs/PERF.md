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

## 2026-11-05 db witness: sparse apply without re-decoding (aarch64-macos, Apple M4 Pro, ReleaseFast)

Same bench (`zig build bench -Doptimize=ReleaseFast -- db/witness`), medians of 11 per run;
the machine was loaded (load average 50-75 on 14 cores), so "before" (the tree just before
the change) and "after" binaries ran interleaved, 4 full runs each, and the table gives the
median of the four medians. Witnesses are byte-identical: the same node counts and encoded
bytes as before, and the differential, codec, rpc, and proof-lane tests pass unchanged.

| Block | build before | build after | unverified before | unverified after | replay before | replay after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1k account writes | 2.59 ms | 1.96 ms | 0.72 ms | 0.61 ms | 1.07 ms | 0.70 ms |
| 1k acct + 4k slot writes | 16.1 ms | 10.8 ms | 5.1 ms | 4.2 ms | 9.6 ms | 6.4 ms |
| 200 evm SLOAD+SSTORE calls | 2.11 ms | 1.35 ms | 0.49 ms | 0.36 ms | 0.98 ms | 0.63 ms |

Stateless evm re-execution (`apply_evm`) 1.35 -> 0.98 ms. Under this load the storage-heavy
build's spread was 12.2-17.3 ms before and 9.6-11.2 ms after; a separate 5-round interleave
gave 12.6-23.5 ms (before) vs 9.7-13.0 ms (after). The sparse apply plus post-root
(verified minus unverified) is ~11 -> ~6.6 ms on this run, ~8 -> ~5.5 ms on quieter samples.

What changed (`trie/sparse.zig`, `db/witness.zig`):
- An unloaded child slot holds the byte offset of the child's RLP item in the parent's
  preimage (`unloaded_first + offset`; pool indices stay below it). Materializing a child and
  rehashing a dirty branch over unloaded children read that one item in place: no
  `decode_node` of the parent at rehash (was ~10% of the build in the profile) and no
  item-by-item skip in `child_at`.
- `resolve` uses `decode_layout` (offsets, no `RlpNode` copies), with a one-pass branch scan
  (`decode_branch_fast`: each child is `0x80`, `0xa0` + 32 bytes, or a short list) and the
  item decoder as the strict fallback for everything else. A seeded and a coverage fuzz check
  the scan accepts exactly the branches the item decoder accepts, with the same offsets.
- Dirty branches encode straight into the hash buffer from the children's cached references
  or the parent's preimage (no `[16]RlpNode` gather), with fixed-size copies for the 1- and
  33-byte items.
- `NodeStore` and `SparseState.storage_roots` key their maps by keccak digests, so the map
  hash is the digest's first eight bytes instead of a wyhash of all 32.

Profile (`sample`, 600 extra storage-heavy builds; share of samples in the build): before,
apply + post-root 66% (rehash keccak ~23%, `decode_node`/`decode_item` ~23% of which ~9% at
rehash, memmove ~5%); after, ~57%: rehash keccak ~32% (15 270 node encodings of 1-2 keccak
blocks each, batched two at a time on NEON), `resolve` ~13% (the branch scan and first touch
of each preimage), the rest `put`, map lookups, and copies.

Takeaways:
- The apply is now keccak-bound: every dirty node of the 1k storage tries and the account
  trie must be rehashed; fewer hashes would need fewer dirty nodes, not faster decode.
- Do not cache decoded child refs per resolved branch (16 x 34 B per node, ~8 MB for this
  pool): the item offsets fit in the existing child slots and cost nothing.

## 2026-11-05 db reads (aarch64-macos, Apple M4 Pro, 48 GB, ReleaseFast, 34023ca8)

`zig build bench -Doptimize=ReleaseFast -- db/read` (`db/read_bench.zig`, ~4 s after the
fixture; whole `db/` run ~15 s). State = the db bench state (100k accounts, 1k contracts x 64
slots) plus 1k 64-byte codes; the overlay holds one uncommitted measured block (1k accounts,
4k slots). Each case reads 65 536 random keys from a seeded `Prng`; median of 15 passes,
ns/op. The machine was heavily loaded (load average ~35-46 from other jobs): the table gives
the best of 5 runs and the range; keccak-bound rows swing the most.

| Read | best | range | notes |
| --- | ---: | ---: | --- |
| `State.basic` hit / miss | 17.0 / 19.8 | 17-56 / 20-22 | one `AutoHashMap` probe |
| `State.storage` hit | 29.2 | 29-42 | 52-byte key |
| `State.storage` miss, account exists / absent | 19.8 / 20.0 | 20-21 / 20-21 | |
| `State.code_by_hash` hit | 14.2 | 14-16 | |
| vtable `basic` hit / miss | 326 / 22.4 | 326-829 / 22-39 | hit keccaks the address |
| vtable `storage` hit | 28.8 | 29-65 | |
| vtable `storage` miss, account exists / absent | 21.8 / 21.7 | 22-27 / 22-23 | |
| vtable `code_by_hash` hit | 15.5 | 15-38 | |
| `Overlay.basic` in overlay / fall-through | 8.4 / 21.5 | 8-9 / 21-41 | 1k-entry map, then State |
| `Overlay.storage` in overlay / fall-through | 21.4 / 52.8 | 21-58 / 53-139 | fall-through = 3 probes |
| `StateTrie.get_account` prehashed / +keccak | 23.3 / 300 | 23-71 / 300-758 | by-hash entry map |
| account trie walk (`accounts.get`) prehashed | 26.3 | 26-59 | real path walk |
| `StateTrie.get_storage` prehashed / +2 keccak | 34.2 / 449 | 34-109 / 449-1144 | storage trie walk |

Takeaways:
- Flat tables vs trie: the trie walk itself is cheap at this size (account walk 26 ns vs
  17 ns for `State.basic`, storage walk 34 ns vs 29 ns; the working set is mostly
  cache-resident), but a trie read needs keccak of its keys first: 300 ns per account and
  450 ns per slot here. The flat tables keyed by raw address/slot are what make reads cheap.
- The vtable indirection costs ~1-3 ns per call (storage, code, misses): noise. `basic` hits
  were the exception: `evm_backend.basic` keccaked the address to answer `has_storage` from
  `StateTrie`, ~310 ns extra per account load (19x a table read). Fixed: see "evm backend
  `basic` without keccak" (294 -> 24 ns).
- Overlay reads: a key in the overlay is as cheap as State or cheaper (small map); a miss
  costs the overlay probe on top of State (basic +4 ns; storage ~+20 ns because it probes the
  account map and the slot map before falling through).
- Misses are as cheap as hits (no negative-lookup penalty in the open-addressing tables).

## 2026-11-05 evm backend `basic` without keccak (aarch64-macos, Apple M4 Pro, ReleaseFast)

`evm_backend.basic` keccaked the address on every hit only to answer `has_storage` (EIP-7610)
from `StateTrie`. `State.account_table` values now carry each account's nonzero slot count
(`AccountEntry.storage_slots`), kept by every path that adds or removes a slot (`apply`,
`unwind`, `put_storage`, snapshot load), so the vtable read is the one table probe. Same
fixture as "db reads"; A/B on one machine back to back, load average ~25 (noisy).

| Case | before | after |
| --- | ---: | ---: |
| vtable `basic` hit | 294 ns | 24.0 ns |
| vtable `basic` miss | 20.7 ns | 22.0 ns |
| `State.basic` hit | 17.1 ns | 18.1 ns |
| db/block 1k acct + 4k slot apply+root (3 runs) | 7.84-8.25 ms | 7.43-7.77 ms |

Takeaways:
- An account load through the evm backend is now a table read (12x faster); the remaining
  ~6 ns over `State.basic` is the vtable call and the larger `AccountInfo` result.
- Write path: one count update per slot change in the same `storage_table` probe
  (`getOrPut`/`remove` already ran); db/block is unchanged within noise.
- Memory: `AccountEntry` is 16 bytes larger than `AccountInfo` (alignment), ~1.6 MB per 100k
  accounts.

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

## 2026-11-05 node parallel storage rehash on (aarch64-macos, Apple M4 Pro 14 cores, ReleaseFast)

`base node` now starts `state_db.rehash_threads_auto(cores)` = min(cores - 1, 4) storage-rehash
workers (`--rehash-threads N` overrides, 0 disables); 4 on this machine. DST (`Service(SimIo)`
asserts 0), the simulator, benches and tests keep 0. The node's commit path is the db commit
path, so `db/commit sim (zero latency, 4 rehash threads)` (new case, `shape_bench` with 4
workers) against `db/commit sim (zero latency)` measures it end to end: `execute_and_commit`
of 1k accounts + 4k slots over 100k accounts, 128 blocks, interleaved runs, load average 15-25.

| Case (`execute_and_commit` cpu p50) | 0 threads | auto (4) | Runs |
| --- | ---: | ---: | --- |
| db/commit sim (zero latency) | 7.81 ms | 6.79 ms | 4 each (0: 7.68-8.07, 4: 6.59-6.99) |

-13% per storage-heavy block. Blocks that dirty no storage (the `node: execute block, 500
transfers` case) never wake the pool (`flush` returns before the split), and flushes under
1 024 dirty storage nodes rehash on the caller, so small blocks pay nothing.

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
| p2p/gossip control flood rpc (4000 iwant + 1000 idontwant ids) | 53 162 | – | hostile 170 KB RPC; was 3 838 523 ns before per-peer IWANT/IDONTWANT id budgets (256/heartbeat) |
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

## 2026-11-05 db history memory at 200 ms blocks (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/history` (`db/history_bench.zig`). State: the db
bench state (100k accounts, 1k contracts x 64 slots: 227 620 trie nodes). A `history.Store`
with a 64-block window is reset at that state, then 128 `bench.write_block` blocks are
committed (distinct existing accounts and slots); the second 64 are measured with the window
full and pruning in steady state. Bytes = `Store.bytes_used` (occupied paths and versions at
their unit sizes: small version 196 B, large version 682 B, path 147 B including its index
entry). Typical block = ~200 transactions (1k account + 1k slot writes); heavy = 1k + 4k.

| Block | versions/block | bytes/block | at 5 blocks/s | state | steady (64 blocks) | commit p50 / max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| typical 1k acct + 1k slot | 8 025 | 2.82 MiB | 14.1 MiB/s, 846 MiB/min | 78.7 MiB | 259.0 MiB | 11.9-13.1 / 19.9-36.4 ms |
| heavy 1k acct + 4k slot | 15 309 | 4.68 MiB | 23.4 MiB/s, 1.37 GiB/min | 78.7 MiB | 378.3 MiB | 33.7 / 116.6 ms |

Rewritten paths repeat block to block (paths 227 620 before and after the run): a block adds
versions, not paths. Budget check: with `bytes_max` = state + half the steady window, the next
64 commits keep a 32-block window (95 early prunes, one per commit after the first drain),
bytes always at or under the budget. Max commit times include first-touch page faults of the
lazily committed pools and are noisy (two runs: 19.9 and 36.4 ms typical).

Window as wall-clock span (state + span x bytes/block, this state):

| Span | Blocks | typical | heavy |
| --- | ---: | ---: | ---: |
| 12.8 s | 64 | 259 MiB | 378 MiB |
| 60 s (node default) | 300 | 925 MiB | 1.45 GiB -> 1 GiB budget keeps ~202 blocks (40 s) |
| 15 days (base/base default, on disk) | 6 480 000 | ~17.4 TiB | ~28.9 TiB |

Node defaults from this: `--proofs-history.window` 300 (60 s at 200 ms) and
`Limits.history_bytes_max` 1 GiB. The history commit (~12 ms typical, ~34 ms heavy) runs on top
of the block apply + root (~8 ms heavy) inside the 200 ms slot. (Commit time and path bytes
since cut: see "db history commit at 200 ms blocks" below.)

## 2026-11-05 db history commit at 200 ms blocks (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/history`, same state and blocks as the memory
section above. Before = parent commit, after = this change; both binaries run interleaved,
three runs each, medians of the per-run p50 and max (64 steady-state commits per run). The
machine was loaded (load average 70-150 from other builds), so max is mostly scheduling
noise; one run of each saw a 73-160 ms outlier.

| Block | before p50 / max | after p50 / max | p50 change |
| --- | ---: | ---: | --- |
| typical 1k acct + 1k slot | 9.97 / 17.3 ms | 3.75 / 13.5 ms | -62% |
| heavy 1k acct + 4k slot | 17.03 / 23.4 ms | 5.73 / 8.65 ms | -66% |

Profile (`sample` on the bench binary, heavy, before): visit walk + version writes 52%,
tombstone diff (`bury_removed`) 32%, the second `drain` walk 17%, pruning ~0 (46 µs per
block once the window is full). Changes, in order of gain:
- The `drain` walk only cleared change marks but re-encoded every changed node:
  `TrieType.clear_changes` memsets the bitsets instead (heavy 20 -> ~16 ms in a first run).
- Version metadata in the record's padding (still 32 bytes): node kind, branch child mask
  (both from the trie node, `Visit.kind`/`branch_mask`), and a 14-bit fingerprint of the
  node reference (`Visit.reference`, the hash the trie already has). The diff reads masks
  instead of RLP-decoding the old and new encodings (decode only for account leaves and
  extensions), and an unchanged-encoding check loads the old encoding only when length and
  fingerprint match (heavy ~16 -> 10.8 ms).
- `db/path_index.zig` replaces `std.AutoHashMapUnmanaged(Key, u32)`: 8-byte slots (key
  hash, path id), keys compared in the path records the lookup loads anyway, linear probing
  with backward-shift deletion (no tombstones, no periodic rehash). One slot line plus the
  record instead of metadata + key + value + record (heavy 10.8 -> 5.7 ms).

Memory: `path_bytes` 147 -> 84 B (the key lives once, in the path record). State bytes
78.7 -> 65.0 MiB; steady 64-block window 259.0 -> 245.3 MiB typical, 378.3 -> 364.6 MiB
heavy; bytes per block unchanged (2.82 / 4.68 MiB). At the node default 300 blocks the
1 GiB budget keeps ~204 heavy blocks (40.8 s). The index is filled at init and `reset`
(1.5 slots per path: ~37 MiB for the node's ~3.1M paths, vs ~4 MiB of hash map metadata).

Remaining heavy commit (~5.7 ms): the trie's full-node re-encode per visited node, copying
15k encodings (~4.7 MiB) into the pools, and one random path record + version per node.
Moving the commit off the block's critical path was evaluated and not done: at ~6 ms of a
200 ms slot it does not pay for a second history state (proofs at the head would have to
wait or fall back to live state) and the ordering it adds under DST.

## 2026-11-05 node Engine API slot at 200 ms (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "node: 200"`: one Denim slot is FCU with
attributes (build), getPayload, the follower's newPayload, then FCU on both nodes; 500
transfers (10.5 Mgas) plus the L1-info stand-in and BaseTime deposits, forced through the
attributes; recovery threads as `base node` (cores - 1, at most 7). In-memory state.

| step | before | after |
|---|---|---|
| whole slot | 56.5 ms | 11.7 ms (894 Mgas/s) |
| build (FCU with attributes) | 18-44 ms | 5-7 ms |
| follower newPayload | 6-12 ms | 6 ms |
| adopting FCUs (builder + follower) | 17-33 ms each | 0.1-0.2 ms each |

Fixes: forkchoice pool pruning no longer recovers every included sender (the executor
reports senders and the chain keeps the last 4 blocks'); forced attribute transactions
are recovered in parallel. Well under the 150 ms seal offset.

Durable mode (`node: 200 ms slot, durable (sim storage)`: `--datadir` layout from the
default limits, journal settled every slot): 14.5-17.7 ms against 17.1-18.5 ms in memory
in the same runs (machine shared with other builds; the spread is noise). The
`settle_head` unwind after each build/import and the re-apply on the adopting FCU do not
show up next to execution. Real-disk write latency is not measured (journal writes run
asynchronously off the slot).

## 2026-11-05 db history: multi-key `eth_getProof` in one walk (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "db/history proof"`: the db bench state (100k
accounts, 1k contracts x 64 slots), a 16-block history window of heavy blocks (1k acct + 4k
slot) committed twice over, then `eth_getProof(contract 0, [slot 0..n-1], oldest + 1)`:
1 account and n keys (its 64 slots present, the rest absent). Medians of 64 iterations, two
runs (the machine was loaded by other builds).

| Keys | per-key (old RPC path) | per-slot `get_proof` | multi `get_proofs` + fill | vs old |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 344-384 µs | 102-114 µs | 48-56 µs | 6.9-7.2x |
| 256 | 1307-1314 µs | 343 µs | 96-98 µs | 13.4-13.7x |

- per-key: what `eth_getProof` at an older block did before: an account proof, then one
  `Chain.proof_at` per key, each re-walking the account path and walking the storage path
  (n + 1 account walks, n storage walks, every node looked up and keccak-checked each time).
- per-slot: `Store.get_proof` with every slot (one account walk, n storage walks).
- multi: `Store.get_proofs` (`db/proof_set.zig`): the slots are hashed, sorted and
  deduplicated (`trie.path_targets`), and the storage trie is walked once depth-first
  (`Store.walk_frames`, shared with the witness `walk_paths`): each node on a shared prefix
  is looked up, keccak-checked and decoded once, and every key whose path enters it records a
  slice to it. `fill` then copies one key's proof into the RPC buffer (included in the time).

The remaining cost is linear in the output: every key still gets its full node list copied
(root and upper branches repeated per key, as `eth_getProof` requires), plus one keccak per
slot. The 256-key case is 4x the keys for 2x the time of 64 because most of the extra keys
are absent and end at the shared upper nodes.

## 2026-11-05 db commit with checkpoints at 200 ms blocks (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "db/commit steady"` (`db/steady_bench.zig`; only
runs when the filter names "steady"; ~20 min). Typical block = 1k account + 1k slot writes
(~200 transactions, 281 KB entry) over 100k accounts (1k contracts x 64 slots), node layout:
64 MiB journal, 16 MiB / 1024 retained blocks, so each checkpoint is 31.2 MB (14.6 MB
snapshot + ~57 retained blocks) and checkpoints start on their own when the journal passes
half full. Latency = `execute_and_commit` until its entry is durable, classified by the
checkpoint: `start` (serializes the staging image in that commit's tick), `advance` (a
checkpoint writing before and after), `finish`, `none`. Os = `IoStorage` on kqueue, scratch
file (~160 MB, deleted), F_FULLFSYNC, 2k blocks paced at 200 ms slots: after a block is
durable the storage ticks every 2 ms (the node's `storage_tick_ns`) until the slot ends. Sim
= zero-latency `SimStorage`, 3k blocks back to back with 8 idle ticks (CPU only). The machine
was heavily loaded (load average 100-150), so p99/max are mostly scheduling noise: compare
`advance` against `none` from the same run. One run each.

| Case | n | p50 | p90 | p99 | max | > 50 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| os unpaced, all | 2000 | 15.6 ms | 37.0 ms | 95.0 ms | 153.7 ms | 91 |
| os unpaced, none | 1641 | 14.7 ms | 33.8 ms | 85.4 ms | 142.5 ms | 55 |
| os unpaced, start | 16 | 20.8 ms | 93.5 ms | 105.5 ms | 105.5 ms | 2 |
| os unpaced, advance | 342 | 20.3 ms | 49.6 ms | 107.7 ms | 153.7 ms | 34 |
| os paced 4 MiB, all | 2000 | 17.5 ms | 59.2 ms | 157.8 ms | 505.0 ms | 244 |
| os paced 4 MiB, none | 1571 | 16.6 ms | 55.5 ms | 149.2 ms | 505.0 ms | 178 |
| os paced 4 MiB, advance | 412 | 20.3 ms | 77.1 ms | 205.9 ms | 295.2 ms | 65 |
| sim unpaced, all | 3000 | 4.44 ms | 10.9 ms | 36.5 ms | 111.2 ms | 18 |
| sim paced 4 MiB, all | 3000 | 4.50 ms | 9.7 ms | 22.4 ms | 86.2 ms | 7 |

Serializing the 31.2 MB staging image (`request_checkpoint` on an idle database): sim
2.2 ms, os 3.3-5.7 ms (one 23.5 ms sample, noise). Os unpaced: 51 checkpoints in 2k blocks
(one per ~39 blocks), 0 slot overruns, longest idle tick 157 ms; os paced: 12 slot overruns,
longest idle tick 200 ms (the paced run hit a noisier period: its `none` p90 is 55 vs 34 ms).
No `error.Busy` in any run. The sim's `start`/`finish` rows are 1 and 12 samples (checkpoints
run back to back there, so starts land in `finish` commits); its outliers are scheduling.

Reading: no stall is attributable to serialization (2-6 ms). A checkpoint spreads over ~7
commits already at the 2 ms tick (the writer submits one 64 KiB block per tick), and
overlapping commits cost p50 +5.6 ms and exceed 50 ms 3x as often as the rest (10% vs 3.4%,
unpaced run), because each journal fsync also flushes the checkpoint blocks written since
the previous one: up to ~6.4 MB per 200 ms slot at the 2 ms tick, unbounded with a faster
tick or io_uring. `checkpoint_bytes_per_commit` (node 4 MiB) makes that bound explicit; its
gain is not measurable on this machine (same p50 for `advance`, noise elsewhere). Before
first measurements (back to back, no slot pacing, not committed): the journal outran the
checkpoint (12.7k Busy retries, `finish` commits p50 420 ms) — an artifact of committing 20x
faster than 200 ms slots, which is why the os case paces.

## 2026-11-05 db commit steady rerun: paced vs unpaced, kqueue and io_uring (Apple M4 Pro, ReleaseFast)

Same bench and shape as above; cases are now `db/commit steady os unpaced` and
`db/commit steady os paced` (4 MiB per commit), and each run also prints `overlap`: every
commit that overlapped a checkpoint (`start` + `advance` + `finish`). Runs interleaved, 2k
blocks at 200 ms slots each, load average (1 min) at the start and end of each run. Every
run: 51 checkpoints of 31.2 MB, 0 busy retries, 0 slot overruns; serialization 2.1-6.0 ms.
Unpaced runs take 1.01-1.02 syncs/block, paced 1.00.

macOS kqueue (F_FULLFSYNC, host load 10-50, one run per row in run order):

| Run | load | all p50 / p90 / p99 / max | > 50 ms | overlap n | overlap p50 / p90 / p99 / max | > 50 ms | idle tick max |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: |
| 1 unpaced | 19 -> 21 | 9.62 / 18.0 / 43.3 / 89.6 ms | 14 | 276 | 11.3 / 21.0 / 64.7 / 76.5 ms | 7 | 150 ms |
| 1 paced | 21 -> 28 | 10.1 / 16.3 / 30.6 / 146.4 ms | 7 | 352 | 10.9 / 17.7 / 46.2 / 112.9 ms | 3 | 91 ms |
| 2 unpaced | 28 -> 20 | 8.97 / 12.6 / 19.1 / 68.6 ms | 2 | 259 | 10.7 / 14.5 / 22.0 / 32.0 ms | 0 | 60 ms |
| 2 paced | 20 -> 50 | 10.3 / 24.5 / 53.7 / 106.2 ms | 27 | 358 | 11.2 / 31.6 / 66.0 / 91.3 ms | 12 | 138 ms |
| 3 paced | 16 -> 18 | 9.04 / 12.7 / 18.4 / 57.6 ms | 1 | 352 | 9.85 / 14.6 / 20.7 / 33.4 ms | 0 | 41 ms |
| 3 unpaced | 18 -> 10 | 8.66 / 10.1 / 14.6 / 35.1 ms | 0 | 256 | 9.82 / 12.6 / 15.1 / 35.1 ms | 0 | 20 ms |

Linux io_uring (`just test-linux` approach: alpine:3.20 in Docker, seccomp=unconfined,
`-Drequire-io-uring=true`, source and caches copied into the container so the scratch file
is on the container filesystem; 6 vCPUs, kernel 6.8, VM load ~1; host load 6-10):

| Run | all p50 / p90 / p99 / max | > 50 ms | overlap n | overlap p50 / p90 / p99 / max | > 50 ms | idle tick max |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| 1 unpaced | 6.33 / 7.76 / 9.25 / 20.6 ms | 0 | 285 | 7.98 / 8.84 / 11.2 / 13.3 ms | 0 | 2.3 ms |
| 1 paced | 6.51 / 7.81 / 9.44 / 25.0 ms | 0 | 352 | 7.76 / 8.60 / 10.3 / 16.1 ms | 0 | 2.3 ms |
| 2 unpaced | 6.48 / 8.37 / 13.2 / 61.0 ms | 2 | 240 | 8.90 / 11.5 / 17.2 / 61.0 ms | 1 | 2.8 ms |
| 2 paced | 6.50 / 7.84 / 11.6 / 16.0 ms | 0 | 352 | 7.75 / 11.0 / 13.0 / 14.0 ms | 0 | 2.2 ms |

Reading: on macOS the run-to-run spread (overlap p99 15-66 ms within one mode) is larger
than any paced/unpaced difference; the cleanest pair (run 3) is equal within 1 ms at p50 and
the tails track host load, not the mode. Pacing lowers the overlap-commit p50 penalty over
`none` slightly (paced +0.9 / +1.2 / +1.0 ms vs unpaced +1.9 / +1.9 / +1.2 ms) at the cost
of more overlapping commits per checkpoint (~7 vs ~5). On io_uring, where the ring can
submit many checkpoint blocks per tick, paced overlap commits are at or below unpaced ones
(p50 7.76 / 7.75 vs 7.98 / 8.90 ms, p99 10.3 / 13.0 vs 11.2 / 17.2 ms) and the only > 50 ms
commits were unpaced. Pacing is neutral to slightly better, never clearly worse: the node
keeps 4 MiB. The Docker VM's fsync is cheaper than F_FULLFSYNC on the host SSD, so the
io_uring numbers bound the CPU and submission path, not a bare-metal Linux disk.

## 2026-11-05 db witness rpc: `debug_executionWitness` at 200 ms blocks (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "db/witness rpc"` (`db/witness_rpc_bench.zig`).
State: the db bench state (100k accounts, 1k contracts x 64 slots) with a 4-block history
window; four `write_block` blocks committed, then the head and head - 1 are witnessed from
history (`Generator.generate_history`, the node's path, state untouched). The executor
replays each block's changeset through an evm `State` over the recorded database (the
block's read/write set without the interpreter: a lower bound of real re-execution). JSON
is the `{state, codes, keys, headers}` object written through `json.Writer` into a
response-sized buffer, as `rpc/debug.zig` does; it is checked byte-identical to the old
per-byte writer every sample. Medians of 11 (ms); the machine was loaded (load average
70-85), so single steps move by ~10-20% between runs. "build" is `Builder.build_from`
timed again on its own after the call; "fold" is total - execute - build (`commit_evm`,
history changeset, headers), clamped at 0.

| Block | Step | Before | After |
| --- | --- | ---: | ---: |
| heavy head (6.0k nodes, 6.0k keys, 3.20 MB JSON) | execute (history reads) | 31.5 | 10.7 |
| | build | 19.9 | 16.1 |
| | fold | 35.8 | 0.8 |
| | JSON write | 1.61 | 0.14 |
| | **end to end** | **88.9** | **27.7** |
| heavy head-1 | execute | 46.6 | 10.5 |
| | build | 20.2 | 15.7 |
| | fold | 59.2 | 0.7 |
| | JSON write | 1.58 | 0.14 |
| | **end to end** | **127.5** | **27.3** |
| typical head (5.3k nodes, 2.8k keys, 2.61 MB JSON) | execute | 13.4 | 4.7 |
| | build | 11.8 | 7.2 |
| | fold | 13.5 | 0.0 |
| | JSON write | 1.31 | 0.11 |
| | **end to end** | **40.0** | **12.1** |
| typical head-1 | execute | 13.5 | 5.2 |
| | build | 11.3 | 7.6 |
| | fold | 16.9 | 0.2 |
| | JSON write | 1.26 | 0.10 |
| | **end to end** | **43.0** | **12.7** |

What changed:
- Every history walk keccak-checks each node it enters. Disabling the check (experiment,
  not kept) took the heavy head from 39 to 22 ms, so most of the old cost was hashing the
  same nodes again: an account walk per slot read (for its storage root), a second walk per
  written key to fold the changeset's old values, the witness walk over all of them.
- `witness_block.HistoryMemo`: parent values read in the call, indexed like the recorder's
  key sets. Each account is walked once; the changeset's old values come from what execution
  read. Heavy head 87 -> 45 ms, head-1 126 -> 42 ms (this step alone).
- `history.Store.verified`: (version id, digest) cache for one store generation (every
  public mutation bumps it). Heavy 45 -> 28 ms. 1.25 MiB per store, cleared at `init`.
- `json.write_hex`: 16 bytes per vector step (nibble -> digit with a select, interleave with
  a shuffle) straight into the writer's buffer: 1.6 -> 0.14 ms for 3.2 MB (~23 GB/s).
- `db/witness_json.length` is O(1) per list (the byte total is the list's last end);
  `rpc/debug.zig` `witness_json_length` delegates to it.

Remaining: `Builder.build_from` (~60%: sparse apply + post-root rehash for the
`WitnessMismatch` check) and the history reads of execution (~40%: path-index probes per
node, one keccak per distinct node). A real block also pays the interpreter (the 200-call
evm block in "db witness" above). End to end through HTTP adds the socket send of 3.2 MB
(not measured here; the large send buffer is filled by the same write).

## 2026-11-06 db node restart (`Database.open`) (aarch64-macos, Apple M4 Pro 14 cores, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "db/restart"` (`db/restart_bench.zig`; only runs
when the filter names "restart"; ~20 min). Each case builds a database once (bench fill
blocks, then 300 typical blocks of 1k account + 1k slot writes, journal and checkpoints as
the node), drains it, then reopens it 3 times per variant and reports the median per step
(`Database.open_trace`, wall and caller-thread CPU). History on = the node's history
config: window 300, `bytes_max` 1 GiB, 1k versions per block. Shapes: 100k = 100k accounts,
1k contracts x 64 slots (head 340); 1m = 1M accounts, 10k contracts x 64 slots (head 365).
Os = `IoStorage` over kqueue on a scratch file (1m: under 2 GiB, deleted after). Variants:
`incremental` = the old load path (snapshot decoded key by key into the tries, history
window unwound through the trie; kept as the reference), `bulk` = the new path, `bulk 4
threads` = bulk with `rehash_threads = 4`. The machine was loaded (load average 15-45):
one run of 3 opens each, compare variants within a case.

| Case, ms (median) | open | ckpt read | snapshot tables | snapshot trie | snapshot root | replay | hist unwind | hist trie | hist reset | hist apply |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100k sim, incremental | 299 | 83 | 90 | - | 47 | 73 | | | | |
| 100k sim, bulk | 261 | 81 | 7.6 | 70 | 28 | 65 | | | | |
| 100k sim, bulk 4 threads | 230 | 83 | 8.5 | 71 | 0.4 | 61 | | | | |
| 100k os, incremental | 540 | 245 | 105 | - | 57 | 124 | | | | |
| 100k os, bulk | 440 | 258 | 8.3 | 65 | 28 | 85 | | | | |
| 100k os, bulk 4 threads | 381 | 217 | 8.9 | 75 | 0.8 | 77 | | | | |
| 100k sim history, incremental | 3231 | 82 | 93 | - | 49 | 68 | 601 | - | 78 | 2232 |
| 100k sim history, bulk | 2666 | 82 | 7.5 | 78 | 28 | 63 | 58 | 67 | 70 | 2185 |
| 100k os history, incremental | 3435 | 147 | 93 | - | 49 | 86 | 640 | - | 78 | 2291 |
| 100k os history, bulk | 2792 | 124 | 8.6 | 67 | 29 | 70 | 60 | 68 | 76 | 2260 |
| 100k os history, bulk 4 threads | 2614 | 131 | 8.4 | 72 | 0.4 | 75 | 61 | 67 | 45 | 2137 |
| 1m sim, incremental | 2957 | 185 | 2278 | - | 364 | 123 | | | | |
| 1m sim, bulk | 1408 | 180 | 80 | 773 | 273 | 96 | | | | |
| 1m sim, bulk 4 threads | 1073 | 183 | 80 | 705 | 6.9 | 88 | | | | |
| 1m sim history, incremental | 9536 | 189 | 2411 | - | 363 | 112 | 1280 | - | 805 | 4322 |
| 1m sim history, bulk | 7503 | 183 | 89 | 778 | 281 | 105 | 71 | 785 | 842 | 4296 |
| 1m os history, incremental | 9752 | 399 | 2447 | - | 386 | 150 | 1246 | - | 778 | 4216 |
| 1m os history, bulk | 7186 | 366 | 78 | 769 | 285 | 107 | 73 | 789 | 881 | 3974 |
| 1m os history, bulk 4 threads | 5811 | 241 | 74 | 714 | 6.9 | 93 | 68 | 696 | 455 | 3478 |

`blocks` (retained blocks into the chain index) is 5-9 ms everywhere and left out. The
trie build alone (`db/restart trie`, `State.rebuild_trie` + root on a filled state, fastest
of 5): 100k 64 + 28 ms; 1m 714 + 266 ms; 1m with 4 threads 706 ms including the root.
Earlier bulk builds measured the parts at 1m: sorting the slot records by address with one
pdq 340 ms and the 1M address hashes 370 ms (cache misses on 32-84 byte elements); an
in-place 256-bucket pass (American flag) and a pdq per bucket brought them to 67 and 42 ms,
and carrying each account's map entry pointer to the account-trie build saved the lookups
(finish 290 -> 220 ms).

Reading: snapshot decode + trie build drops from 2.3-2.4 s to 0.85 s at 1m (2.8x, 1.1 s
with the root) and from 90 to 78 ms at 100k; the root step goes to ~0 with rehash threads
(the account trie is hashed on the pool in subtries two levels down). History unwind is now
table-only plus one bulk trie rebuild: 600-1280 ms -> 58-73 ms + 67-785 ms. With history
on, open is now dominated by `history_apply` (re-applying the window with `commit_block`:
~7.3 ms per typical block at 100k, ~14 ms at 1m); at 1m the 1 GiB budget keeps only the
last 86 blocks (window from 280), so ~214 of the 300 re-applied blocks are pruned again
(see the lane's limitations). The checkpoint read (80-190 ms CPU) is the AEGIS checksum of
the image. Before this change (incremental, same binary; the old code was identical to it
except for a shared branch-encode copy fast path) 100k: 299-540 ms open without history,
3.2-3.4 s with; 1m: 3.0 s without, 9.5-9.8 s with.

## 2026-11-06 trie parallel account rehash, radix changeset sort (aarch64-macos, Apple M4 Pro 14 cores, ReleaseFast)

`StateTrie.root` now hashes the account trie on the rehash pool too (`rehash_threads` > 0):
after `flush` it takes the subtries two levels below the root (`TrieType.subtries`, up to
256), collects their dirty nodes with per-subtrie end offsets, splits them into chunks of
whole subtries (as the storage path does), runs them on the pool, then hashes the top two
levels on the caller. Below `rehash_parallel_nodes_min` (1024) dirty nodes it stays serial;
0 threads (DST, sim) never reaches it. `Changeset.sort` replaced the pdqsort of its order
words (`address[0..4] << 32 | index`) with a stable LSD radix sort of the 32-bit prefix
(byte passes, constant bytes skipped) and sorts only runs of equal prefixes (one account's
slots) with the full key. Medians of 5 interleaved runs of the old (HEAD^ plus the new bench
cases) and new binaries, load average 6-8:

| Case | Before | After | Change |
| --- | ---: | ---: | --- |
| trie/transfers 1k accts, 0 threads (new case) | 1 262 us | 1 268 us | noise (serial path unchanged) |
| trie/transfers 1k accts, 4 threads (new case) | 1 344 us | 721 us | -46% |
| trie/storage 4k slots, 4 threads | 1 415 us | 1 212 us | -14% (its 1k-account trie is now parallel) |
| trie/storage 4k slots, 0 / 2 / 8 threads | 2 814 / 1 590 / 1 214 us | 2 946 / 1 539 / 1 150 us | 0 threads: noise |
| trie/block, trie/state block | 1 218 / 1 461 us | 1 213 / 1 418 us | noise |
| db/build_changeset 1k acct+4k slot (new case) | 298 us | 227 us | -24% (radix sort) |
| db/block 1k acct+4k slot apply+root (0 threads) | 7.08 ms | 6.79 ms | -4% (radix sort) |
| db/commit sim cpu p50 (0 threads) | 6.99 ms | 6.84 ms | -2% |
| db/commit sim cpu p50 (4 rehash threads) | 5.62 ms | 4.40 ms | -22% |

`trie/transfers` is the shape of a 500-transfer block: 1k random account updates (no
storage) on 100k accounts, precomputed address hashes, then the root, so nearly all of it is
account-trie rehash. Changeset sort alone (sort disabled vs enabled) was ~200 of ~365 us of
`build_changeset`; the radix pass removes ~100 us of it; the rest is the hash-map lookups
(`State.basic`, `State.storage`, overlay account per slot) and the permutation.

Tried and dropped for the changeset sort: u256 order words holding the whole address and a
monotone 32-bit slot summary (no fallback compares, but 32-byte words made it 40% slower),
and u128 words (8 address bytes + slot summary, re-sorting runs whose 8-byte prefix holds
several addresses): 15% slower. Compares were not the cost; pdqsort's branchy passes were.
Not parallel: the account dirty-node collect and the top two levels (a few hundred nodes).

## 2026-11-06 db state memory footprint (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/footprint` (`db/footprint_bench.zig`). A `State`
filled with `put_account` / `put_storage` and hashed; every byte counted by a counting
allocator around `State.init`, and each hash table rebuilt at exactly its live count
("tight"). Per account = account table + `StateTrie.entries` + account-trie nodes; per slot =
storage table + storage-trie nodes. Input for docs/design/disk-state.md.

| Shape | acct nodes/acct | slot nodes/slot | B/account | B/slot | tight | reserved |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100k acct, 1k x 64 slots | 1.386 | 1.391 | 591.4 | 357.2 | 78.2 MiB | 119.7 MiB |
| 1M acct, 10k x 64 slots | 1.359 | 1.391 | 779.5 | 317.5 | 937.2 MiB | 1353.2 MiB |
| 10k acct, 100 x 10k slots | 1.388 | 1.389 | 672.3 | 361.8 | 351.4 MiB | 530.0 MiB |

Unit sizes: account table bucket 117 B, `entries` bucket 129 B, storage table bucket 97 B,
account pool node 194 B (152 + 34 cached ref + 8 order), storage pool node 114 B (72 + 34 +
8). Tables round capacity to a power of two at <= 80% load, so B/entry swings 1.25-2.5x the
bucket; at exactly 80% load the floor is 573 B/account and 280 B/slot. History adds ~299 B
per trie node when on; the checkpoint image 92 B/account and 84 B/slot.

Takeaways: at a Base-mainnet-like 500M accounts + 2B slots the in-memory state is ~0.8-1.0 TiB
(+~0.9 TiB history, ~200 GiB per checkpoint image), and the `u32` node index and the `u32`
checkpoint staging size break first. Design response: docs/design/disk-state.md.

## 2026-11-06 db sorted tables on the grid (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- db/table` (`db/table_bench.zig`). Disk state phase 1:
one immutable table of 10k code-shaped records (32-byte hash key, 100..8000-byte value,
38.8 MiB in 651 data blocks of 64 KiB) built and read through `SimStorage` with one tick of
latency, so a miss is the CPU side of a read (copy, block checksum, structural check, cache
insert), not device latency. Four runs:

| Case | Result |
| --- | ---: |
| build (pull, pack, seal, write) | 16.0-17.5 ms (2.2-2.4 GiB/s) |
| lookup, warm cache (two binary searches + one 16-way set scan) | 213-280 ns |
| lookup, cold cache (one verified 64 KiB block read) | 24.6-25.7 us |
| absent key, cold cache (no filters yet: still reads one data block) | 24.4-25.5 us |

Takeaways: a cache hit is inside the <= 1 us target of docs/design/disk-state.md section 6. A
miss costs ~25 us of CPU before any device time because the reader reads, checksums, and
copies a whole 64 KiB block; reading only the sectors the header names and checking the
block once on insert are the next cuts when misses matter (phase 2 brings filters, so absent
keys stop reading data blocks). Code lookup through the database and the checkpoint image
size without codes are not measured yet: the code store (phase 1 item d) is not wired in.

## 2026-11-06 node mainnet replay (aarch64-macos, Apple M4 Pro, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- "node: replay"`: the ten committed Base mainnet
blocks 53715983..53715992 (253 txs, 46.5 Mgas) through the node executor over the replay
witness backend, best of 30, setup untimed.

| bench | ms/block | Mgas/s |
|---|---|---|
| node: replay 10 Base mainnet blocks | 12.3 | 379 |

`sample` profile (top of stack, ~2.4k samples): `Evm.push_frame` 40% (inlined
`Arena.analyze_code`: every call frame copies and re-analyzes its code, no cache), keccak
13%, interpreter 9%, sparse trie (replay backend only) ~6%, secp256k1 recovery ~5%. The
code-analysis cache is the largest lever for the gigagas/s target (sent to nf-evm).

After nf-evm's code-analysis cache (51a037d5): **6.11 ms/block, 762 Mgas/s** (2.0x).
`push_frame` fell from 40% to ~7% of samples. Remaining (of ~610 collapsed samples):
keccak ~30% (mostly the replay-only sparse trie and witness backend), sparse trie/witness
~15%, secp256k1 sender recovery ~10% (serial here; the production node recovers on up to
7 threads), interpreter ~17%.

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
| evm: snailtracer | 50 479 625 | before `uint.zig`: LLVM's generic u256 division |
| evm: snailtracer | 27 078 208 | ~6.1 Ggas/s with Knuth division over 32-bit limbs |
| evm: snailtracer | 21 813 084 | ~7.6 Ggas/s with 64-bit-limb MLOAD/MSTORE/PUSH loads |
| evm: snailtracer | 20 983 416 | ~7.9 Ggas/s; interpreter runs on the frame in place |

u256 division microbench (same machine): LLVM's lowering of `u256 / u256` costs ~500 ns
(u64-sized divisor) and ~230 ns (wide divisor), against ~3 ns for a u256 multiply. DIV, MOD,
SDIV, SMOD, ADDMOD, and MULMOD now go through `src/execution/evm/uint.zig` (Knuth D on 32-bit
limbs, every step a hardware 64-bit divide), differentially fuzzed against the builtins.

`std.mem.readInt(u256, .., .big)` lowered to 32 byte loads plus shifts; `word_from_be` /
`word_to_be` (four byte-swapped 64-bit loads or stores) took MLOAD/MSTORE from ~26% to a
minor share of snailtracer samples.

revm comparison (revm ee9ab3f, `revme bench snailtracer -w 2 -m 6 -s 10`, back to back with
ours at load average ~24): revm 31.3-45.8 ms per call (criterion intervals of two runs);
needlefish 50.4-51.0 ms before `uint.zig`, 27.1 ms after (best of samples).

Profile (macOS `sample`, 5 s of snailtracer, top of stack): the threaded interpreter loop
~80% (dispatch plus inlined arithmetic/stack ops), `memory_op` MLOAD/MSTORE ~15% (mostly the
u256 byte swap; an in-bounds fast path that skips expansion pricing measured ~1%, within
noise, so it was not kept), Keccak-f ~2%, memmove/memset ~1%. No call-frame cost shows up:
snailtracer makes almost no calls. The call-frame path is covered by `evm: call loop`
(~117 ns per frame push/pop).

## 2026-11-05 builder slot at full gas (aarch64-macos, Apple Silicon, 14 cores, ReleaseFast)

`zig build bench -Doptimize=ReleaseFast -- builder:` (`src/builder/core/bench.zig`). Each
200 ms slot goes through the payload `Service` and `BlockBuilder`: `send_new_payload` (FCU
with attributes), the build tick (L1-info + BaseTime deposits, then best pool transactions
until the gas limit, the pool end, or the 150 ms cutoff on the real clock), and `resolve`
(getPayload). The pool holds one transaction per sender: 3000 transfers (tip 1) and 64 calls
into a contract writing 16 storage slots each (tip 2, ~102k gas steady state), more than one
60 M gas block. The sequencer then imports its own block (newPayload + FCU, timed apart) and
the pool is refilled outside the clock. 4 warm-up slots, 64 measured (p99 = max).

| Metric | p50 | p99 / max |
| --- | ---: | ---: |
| FCU..getPayload, thread CPU | 19.8 ms | 26.6 ms |
| FCU..getPayload, wall | 21.0 ms | 259 ms |
| import (newPayload + FCU), wall | 55.4 ms | 313 ms |
| transactions / block | 2610 | 2610 |
| gas / block | 59.99 M | 59.99 M |

Load average was 140-160 on 14 cores (other agents), so wall times include waiting for a
core: the CPU column is the build cost (~7.6 us per transaction, single-threaded), well under
the 150 ms cutoff; no slot was cut off. Same run, `node: 200 ms slot ... 500 transfers` read
11.5 ms (b78026d4 recorded 11.7 ms). The sequencer's self-import costs more than the build:
it re-recovers every sender (parallel recovery threads starve under this load) and
re-executes the block (see the builder lane's Engine API decision); a direct commit of the
builder's state, or handing the builder's known senders to the import, would remove most of it.

## Test suite time

`zig build test` runs on every push of every lane, so its wall time is a shared budget.
Find the slowest tests with `just test-times`. Keep any single test under ~1 s in Debug;
long simulations belong in `zig build sim` / swarm, not the unit suite.

2026-11-05: suite ~90 s run time; 73 s in one p2p discv5 cluster test (flagged to the lane).
