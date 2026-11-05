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

## 2026-11-05 p2p (aarch64-macos, Apple M4 Pro, ReleaseFast)

| Case | ns/op | MB/s | Notes |
| --- | ---: | ---: | --- |
| p2p/noise XX handshake | 757 468 | | ~1 300 handshakes/s per core; secp256k1 sign+verify dominate |
| p2p/noise transport seal+open 64 KiB | 83 000 | 785 | 16-block ChaCha20 passes (8-block tail) + std Poly1305; 8-block only: 729 MB/s; std AEAD: 338 MB/s |
| p2p/poly1305 std 64 KiB | 16 361 | 4006 | std; a 4-lane 26-bit variant gave +8%, not kept |
| p2p/snappy compress 128 KiB | 77 974 | 1 681 | semi-compressible payload |
| p2p/snappy decompress 128 KiB | 20 618 | 6 357 | |
| p2p/gossip rpc decode 128 KiB publish | 21 | | zero-copy: cost is independent of payload size |
| p2p/gossip seen insert | 5.7 | | open addressing, 8192 ids |
| p2p/gossip publish+drain to 8 peers | 64 539 | 2 031 | id hash + 8 framed RPCs (copy per peer) |

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

## Test suite time

`zig build test` runs on every push of every lane, so its wall time is a shared budget.
Find the slowest tests with `just test-times`. Keep any single test under ~1 s in Debug;
long simulations belong in `zig build sim` / swarm, not the unit suite.

2026-11-05: suite ~90 s run time; 73 s in one p2p discv5 cluster test (flagged to the lane).
