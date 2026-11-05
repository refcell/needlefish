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

## 2026-11-05 p2p (aarch64-macos, Apple M4 Pro, ReleaseFast)

| Case | ns/op | MB/s | Notes |
| --- | ---: | ---: | --- |
| p2p/noise XX handshake | 757 468 | | ~1 300 handshakes/s per core; secp256k1 sign+verify dominate |
| p2p/noise transport seal+open 64 KiB | 92 351 | 710 | 8-block column ChaCha20 + std Poly1305 (std AEAD: 338 MB/s) |
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
