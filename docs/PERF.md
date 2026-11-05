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

## Targets

- Simulator: keep a full seed under 50 ms as real components replace the models, so CI
  can keep running 20k seeds per push.
- Hashing: match or beat std at every size (single-message keccak is within 5% today).
