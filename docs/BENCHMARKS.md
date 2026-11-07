# Benchmarks: needlefish vs base/base

needlefish and the Rust [base/base](https://github.com/base/base) implementation execute the
same real Base mainnet blocks from the same pre-state, on the same machine, and both must
reproduce every block's canonical header (state root, receipts root, gas used, block hash).
A block that does not reproduce fails the run, and the numbers do not count.

This is the second version of this document. The first version (one laptop run) had the
biases listed in [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md): few runs, no confidence intervals,
7 recovery threads against 1, a faster needlefish build than base/base's, and no
attribution. This version follows that plan. It runs on a cloud VM rather than a dedicated
server; [What these numbers are not](#what-these-numbers-are-not) says what that costs.

## Summary

Headline pair: needlefish `ReleaseSafe` against base/base `maxperf`, both tuned for the
native CPU, both single-threaded, fresh process, page cache warm. Times are the median
window time divided by the window's blocks; the speedup is the ratio of the same medians,
with its 95% bootstrap interval.

| Workload | Phase | needlefish ms/block | base/base ms/block | needlefish speedup (95% CI) |
| --- | --- | ---: | ---: | ---: |
| 10-block fixture | execution | 9.85 | 15.77 | 1.60x (1.59-1.62) |
| 10-block fixture | execution + roots | 14.03 | 36.39 | 2.59x (2.57-2.61) |
| 100-block window | execution | 5.17 | 8.86 | 1.72x (1.64-1.75) |
| 100-block window | execution + roots | 8.06 | 61.26 | 7.60x (7.33-7.73) |
| 1,000-block window | execution | 4.20 | 8.00 | 1.90x (1.87-1.92) |
| 1,000-block window | execution + roots | 6.88 | 169.34 | 24.62x (24.19-24.79) |
| 100-block window, EVM only | transactions over a flat in-memory state | 3.92 | 3.33 | 0.85x (0.78-0.98) |

- **Execution** (system calls, sender recovery, transactions over the witness): needlefish
  is 1.6-1.9x faster. With state reads and tries taken out (**EVM only**), base/base's revm
  is about 15% faster than needlefish's interpreter. The execution gap is state access
  (how each side reads accounts and slots from the witness), not the interpreter.
- **Roots**: base/base's state root time grows with every block it has replayed (11 ms/block
  over the first tenth of the 100-block window, 82 ms/block over the last tenth; 39 and
  253 ms/block over the first and last tenth of the 1,000-block window). needlefish's
  commit + root stays between 2 and 2.6 ms/block. base/base's `TrieDB` re-hashes every
  trie node it holds on each block; needlefish caches node hashes and re-hashes only dirty
  nodes. This is a design difference in base/base's proof executor, which is built for
  fault proofs over a few blocks, not for long replays.
  base/base's node (reth) computes state roots differently; it is compared in
  [node to node](#node-to-node-b4).
- **Where base/base wins**: the interpreter (above), sender recovery (C libsecp256k1), and
  the executor's memory. Peak RSS on the 100-block window: base/base 181 MiB; needlefish
  ReleaseFast 224 MiB, ReleaseSafe 780 MiB.
- **Node to node** (B4, small synthetic chain): needlefish's node answers
  `engine_newPayload` in 4.00 ms median against `base-reth-node`'s 8.03 ms, with 213 MiB
  peak RSS against 351 MiB. needlefish's node cannot yet hold a large state, so this is a
  10,000-account chain, not mainnet.
- **Profiles** found a needlefish inefficiency: about 21% of its replay time re-hashes
  unchanged contract code after each block.
- **Build settings matter as much as the implementation on this machine**: native CPU
  tuning made both sides slower (base/base generic is 1.70x faster than native with roots,
  needlefish baseline 1.10x faster than native). The full matrix is below.

## Results

Every number below was measured on 2026-11-06 and 2026-11-07 on the [machine](#environment)
described below, with every block matching its canonical header in every run.

### Configurations

| Label | Side | Build | Threads |
| --- | --- | --- | --- |
| `nf-safe-native-t0` | needlefish | `zig build -Doptimize=ReleaseSafe` (native CPU) | 1 (`--recovery-threads 0`) |
| `nf-safe-native-t1` | needlefish | same | 2 (1 recovery worker on the SMT sibling) |
| `nf-safe-baseline-*` | needlefish | `-Doptimize=ReleaseSafe -Dcpu=baseline` (x86-64 baseline) | 1 or 2 |
| `nf-fast-*` | needlefish | `-Doptimize=ReleaseFast` (no safety checks), native or baseline | 1 or 2 |
| `base-maxperf-native` | base/base | `cargo build --profile maxperf` (fat LTO, 1 codegen unit), `-C target-cpu=native` | 1 |
| `base-maxperf-generic` | base/base | `--profile maxperf`, x86-64 generic | 1 |
| `base-release-*` | base/base | `--profile release` (thin LTO, 16 codegen units), native or generic | 1 |

base/base's harness has no threaded mode: sender recovery happens inside `build_block`,
which the harness cannot parallelize without changing the executor.

### 100-block window, full matrix

Blocks 53775088..53775187 (1571 transactions, 271.9 Mgas). Warm runs, 30 per
configuration. Per-block statistics use every (block, run) sample; the window time is the
median over runs of the sum of the blocks' times, with its 95% bootstrap interval.

| configuration | runs | execution ms/block (median / p90 / p99) | execution + roots ms/block (median / p90 / p99) | window ms, execution + roots (95% CI) | Mgas/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| nf-safe-native-t0 | 30 | 4.38 / 10.80 / 24.67 | 7.10 / 15.96 / 34.52 | 805.9 (795.0-827.6) | 337 |
| nf-safe-native-t1 | 30 | 3.49 / 9.37 / 24.17 | 6.25 / 14.61 / 32.99 | 721.1 (710.8-748.8) | 377 |
| nf-safe-baseline-t0 | 30 | 4.17 / 10.44 / 23.79 | 6.35 / 15.21 / 34.02 | 734.4 (722.5-756.0) | 370 |
| nf-safe-baseline-t1 | 30 | 3.36 / 9.10 / 22.32 | 5.71 / 13.78 / 32.76 | 665.8 (650.6-690.4) | 408 |
| nf-fast-native-t0 | 30 | 4.22 / 10.44 / 21.69 | 6.85 / 15.36 / 30.94 | 774.2 (763.6-792.1) | 351 |
| nf-fast-native-t1 | 30 | 3.34 / 8.58 / 20.42 | 5.96 / 14.19 / 29.95 | 695.7 (683.8-711.9) | 391 |
| nf-fast-baseline-t0 | 30 | 3.93 / 9.81 / 21.63 | 6.08 / 14.22 / 31.41 | 686.0 (676.0-709.9) | 396 |
| nf-fast-baseline-t1 | 30 | 3.14 / 8.28 / 19.37 | 5.23 / 13.09 / 30.00 | 611.3 (602.2-643.7) | 445 |
| base-maxperf-native | 30 | 7.38 / 17.01 / 40.61 | 68.06 / 94.56 / 111.88 | 6126.4 (5993.9-6172.1) | 44 |
| base-maxperf-generic | 30 | 6.52 / 14.77 / 34.01 | 41.01 / 58.63 / 91.54 | 3610.8 (3555.8-3812.1) | 75 |
| base-release-native | 30 | 7.31 / 16.59 / 39.20 | 59.05 / 82.71 / 100.55 | 5251.9 (5188.0-5379.2) | 52 |
| base-release-generic | 30 | 6.59 / 14.81 / 34.24 | 42.10 / 59.59 / 89.91 | 3715.1 (3614.3-3881.6) | 73 |

Speedups (ratio of median window times, 95% CI), warm:

| faster | slower | execution | execution + roots |
| --- | --- | ---: | ---: |
| nf-safe-native-t0 | base-maxperf-native | 1.72x (1.64-1.75) | 7.60x (7.33-7.73) |
| nf-safe-native-t1 | base-maxperf-native | 2.08x (1.99-2.12) | 8.50x (8.15-8.64) |
| nf-safe-baseline-t0 | base-maxperf-generic | 1.53x (1.49-1.61) | 4.92x (4.76-5.19) |
| nf-fast-native-t1 | base-release-generic | 1.89x (1.84-1.98) | 5.34x (5.15-5.60) |
| nf-safe-native-t1 | nf-safe-native-t0 | 1.21x (1.17-1.25) | 1.12x (1.08-1.15) |
| nf-fast-native-t0 | nf-safe-native-t0 | 1.06x (1.03-1.10) | 1.04x (1.02-1.07) |
| nf-safe-native-t0 | nf-safe-baseline-t0 | 0.95x (0.92-0.98) | 0.91x (0.88-0.94) |
| base-maxperf-generic | base-maxperf-native | 1.18x (1.12-1.20) | 1.70x (1.60-1.73) |

The fairest single-threaded pair whatever the CPU tuning is `nf-safe-baseline-t0` against
`base-maxperf-generic` (both untuned, both single-threaded): 1.53x on execution, 4.92x with
roots. Cold runs (page cache dropped) and in-process repeats change the headline pair by
less than its interval: 1.67x (1.63-1.72) and 7.36x (7.23-7.57) cold, 1.64x (1.59-1.69)
and 7.52x (7.26-7.67) repeat.

### 10-block fixture, full matrix

Blocks 53715983..53715992 (253 transactions, 46.5 Mgas), warm, 30 runs each.

| configuration | runs | execution ms/block (median / p90 / p99) | execution + roots ms/block (median / p90 / p99) | window ms, execution + roots (95% CI) | Mgas/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| nf-safe-native-t0 | 30 | 9.16 / 18.88 / 20.41 | 12.12 / 26.04 / 28.12 | 140.3 (139.6-141.5) | 332 |
| nf-safe-native-t1 | 30 | 7.95 / 16.26 / 17.28 | 12.11 / 23.49 / 24.88 | 126.4 (125.7-127.0) | 368 |
| nf-safe-baseline-t0 | 30 | 8.54 / 18.02 / 19.64 | 12.36 / 24.01 / 26.62 | 130.7 (129.8-133.9) | 356 |
| nf-safe-baseline-t1 | 30 | 7.71 / 15.26 / 16.88 | 11.13 / 21.61 / 23.04 | 116.8 (115.8-118.1) | 398 |
| nf-fast-native-t0 | 30 | 9.19 / 17.97 / 19.33 | 12.93 / 25.07 / 26.83 | 139.0 (138.1-140.4) | 335 |
| nf-fast-native-t1 | 30 | 7.67 / 15.55 / 16.69 | 11.74 / 22.67 / 23.79 | 125.7 (124.9-127.1) | 370 |
| nf-fast-baseline-t0 | 30 | 8.66 / 16.92 / 18.34 | 11.66 / 22.55 / 24.46 | 125.8 (125.0-126.8) | 370 |
| nf-fast-baseline-t1 | 30 | 7.27 / 14.53 / 15.77 | 10.67 / 20.38 / 22.38 | 113.4 (113.2-115.5) | 410 |
| base-maxperf-native | 30 | 14.32 / 29.88 / 31.20 | 35.44 / 60.73 / 70.31 | 363.9 (362.8-365.4) | 128 |
| base-maxperf-generic | 30 | 13.67 / 25.37 / 28.36 | 24.97 / 41.43 / 49.75 | 241.4 (239.7-243.4) | 193 |
| base-release-native | 30 | 13.70 / 28.24 / 29.86 | 27.36 / 48.75 / 62.56 | 323.9 (322.9-325.4) | 144 |
| base-release-generic | 30 | 13.57 / 23.90 / 26.54 | 23.92 / 41.07 / 47.77 | 242.6 (240.7-246.0) | 192 |

Headline pair: 1.60x (1.59-1.62) on execution and 2.59x (2.57-2.61) with roots, warm; cold
1.63x and 2.59x; with one recovery worker 1.87x and 2.88x.

### 1,000-block window

Blocks 54048836..54049835 (14,883 transactions, 2,780.2 Mgas), the headline configurations
only, 5 rounds of cold and warm runs. There is no in-process repeat here: one base/base
pass takes about ten minutes of wall time, most of it the harness's untimed feedback of
storage-trie nodes between blocks.

| configuration | mode | runs | execution ms/block (median / p90 / p99) | execution + roots ms/block (median / p90 / p99) | window ms, execution + roots (95% CI) | Mgas/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| nf-safe-native-t0 | cold | 5 | 3.48 / 7.76 / 16.34 | 6.08 / 12.30 / 22.75 | 6882.4 (6845.9-7020.8) | 404 |
| nf-safe-native-t0 | warm | 5 | 3.49 / 7.75 / 16.64 | 6.04 / 12.27 / 22.86 | 6877.6 (6829.8-7001.7) | 404 |
| nf-safe-native-t1 | cold | 5 | 2.76 / 6.70 / 14.15 | 5.34 / 11.28 / 20.74 | 6168.5 (6090.5-6255.0) | 451 |
| nf-safe-native-t1 | warm | 5 | 2.78 / 6.69 / 14.33 | 5.34 / 11.24 / 20.98 | 6161.0 (6076.9-6263.9) | 451 |
| base-maxperf-native | cold | 5 | 6.92 / 14.52 / 29.52 | 178.77 / 254.38 / 279.60 | 169497.9 (169237.4-170545.9) | 16 |
| base-maxperf-native | warm | 5 | 6.85 / 14.60 / 29.26 | 178.50 / 254.97 / 279.14 | 169339.6 (169077.1-169548.4) | 16 |

| faster | slower | mode | execution | execution + roots |
| --- | --- | --- | ---: | ---: |
| nf-safe-native-t0 | base-maxperf-native | cold | 1.91x (1.87-1.92) | 24.63x (24.14-24.78) |
| nf-safe-native-t0 | base-maxperf-native | warm | 1.90x (1.87-1.92) | 24.62x (24.19-24.79) |
| nf-safe-native-t1 | base-maxperf-native | cold | 2.31x (2.28-2.35) | 27.48x (27.10-27.83) |
| nf-safe-native-t1 | base-maxperf-native | warm | 2.31x (2.28-2.34) | 27.49x (27.03-27.87) |

The longer the window, the larger the root gap. State commit + state root, mean ms per
block (warm):

| | first tenth | last tenth |
| --- | ---: | ---: |
| needlefish (`nf-safe-native-t0`) | 2.04 | 2.55 |
| base/base (`base-maxperf-native`) | 39.39 | 252.79 |

base/base's root grows with the number of trie nodes its `TrieDB` holds, which grows with
every block it replays; needlefish's stays nearly flat. Execution alone is 1.90x faster on
needlefish here (1.72x on the 100-block window); the transactions phase is 3.42 against
7.23 ms/block (mean), on different blocks than the 100-block window.

### Where the time goes (B2)

Mean ms per block of each phase, 100-block window, warm, single-threaded headline pair
(the phase boundaries are in [Phases](#phases)):

| Phase | needlefish | base/base | Main reason for the difference |
| --- | ---: | ---: | --- |
| pre-block (system calls, setup) | 0.02 | 0.15 | base/base builds its EVM environment and executor per block; needlefish reuses one executor |
| sender recovery | 1.00 | 0.80 | **base/base faster**: C libsecp256k1 against needlefish's pure-Zig secp256k1 (library) |
| transactions | 4.42 | 8.07 | state reads: over the same transactions on a flat in-memory state (EVM only, below) the times are 3.93 and 3.49, so reading the witness costs needlefish about 0.5 ms/block and base/base about 4.6 ms/block (data structure) |
| post-block | 0.003 | 0.009 | negligible |
| receipts root | 0.11 | 0.20 | both hash the same receipts; not profiled further |
| state commit + state root | 2.81 | 52.15 | needlefish caches node hashes and re-hashes only dirty nodes; base/base's `TrieDB` re-hashes every node it holds on every block, so its cost grows with the window (algorithm) |
| header and other | 0.08 | 0.46 | transactions root and header seal; not profiled further |
| **total** | **8.44** | **61.84** | |

The phase sums are means and include the slow tail, so they differ from the medians above.

### Profiles

[etc/bench/profile.sh](../etc/bench/profile.sh) samples both sides with `perf record -e
cpu-clock -F 1999 --call-graph dwarf` over 10 single-threaded passes of the 100-block window
and keeps only stacks inside the timed region:
[needlefish](assets/bench/flame-needlefish.svg) (`ReleaseSafe`, native) and
[base/base](assets/bench/flame-base.svg) (`release-symbols`: release codegen with line
tables, native). Inclusive shares of the timed region:

| needlefish | share | base/base | share |
| --- | ---: | --- | ---: |
| transactions (`Executor.apply`) | 68% | state root (`TrieDB::state_root`) | 85% |
| - interpreter (`interpreter.run`) | 38% | - RLP-encode and hash every node (`TrieNode::blind`) | 84% |
| - sender recovery (`secp256k1.ecrecover`) | 15% | - of which keccak | 54% |
| - storage reads from the witness (`SparseState.storage`) | 10% | - of which RLP length recomputation (`TrieNode::length`) | 30% |
| - jump-table analysis (`analyze_frame_code`) | 6% | transactions (`execute_transaction`) | 13% |
| state commit (`Replayer.commit`) | 25% | - interpreter (`run_plain`) | 11% |
| - re-hashing unchanged contract code (`SparseState.add_code`) | 21% | - storage reads from the witness (`TrieDB` storage) | 4% |
| keccak, all callers | 31% | | |

What the profiles say:

- **base/base**: 85% of a block is the state root, and almost all of it is re-encoding and
  re-hashing trie nodes that did not change: `TrieDB::state_root` calls `blind` on the
  whole trie it holds, and RLP lengths are recomputed recursively on every encode. That is
  why its root time grows with the window. Its interpreter is about 11% of the block.
- **needlefish**: two thirds of a block is transactions; the interpreter is the largest
  single part. The next is a needlefish inefficiency the profile found: after every
  block, the replayer re-adds the bytecode of every changed contract to its code store,
  which hashes the code (up to 24 KB) only to find it is already there. That is about 21%
  of the block and most of the 2.5 ms/block "state commit" phase above. Checking the
  account's known code hash first would remove it. It is left in place so the numbers here
  describe the code as it was measured.
- **Sender recovery** is 15% of needlefish's block; base/base's (C libsecp256k1) does not
  reach 1.5% of its much longer block. It is the one execution phase where base/base is
  faster in absolute time (0.80 against 1.00 ms/block).


### EVM only (B3)

The 100-block window's transactions over a flat in-memory pre-state (the same `NFPS` file
on both sides), senders recovered before the timed region, single-threaded, no state root.
Warm, 30 runs each:

| configuration | transactions ms/block (median / p90 / p99) | window ms, execution (95% CI) | Mgas/s |
| --- | ---: | ---: | ---: |
| nf-safe-native-evm | 3.03 / 7.74 / 18.76 | 392.1 (370.7-421.9) | 694 |
| nf-fast-native-evm | 2.88 / 7.24 / 16.51 | 367.5 (339.2-388.9) | 740 |
| base-maxperf-native-evm | 2.62 / 7.19 / 17.48 | 333.1 (314.3-376.6) | 816 |
| base-release-native-evm | 2.52 / 6.96 / 16.68 | 332.6 (300.7-358.2) | 818 |

| faster | slower | speedup (95% CI) |
| --- | --- | ---: |
| nf-safe-native-evm | base-maxperf-native-evm | 0.85x (0.78-0.98) |
| nf-fast-native-evm | base-maxperf-native-evm | 0.91x (0.84-1.07) |
| nf-safe-native-evm | base-release-native-evm | 0.85x (0.74-0.93) |

base/base's interpreter (revm) is faster on this workload: needlefish `ReleaseSafe` takes
about 1.18x as long, and `ReleaseFast` about 1.10x (its interval includes parity). The EVM
windows are short (about 0.35 s) and noisier than the full replays, so the intervals are
wider. One difference favours base/base: revm analyzes bytecode (jump tables) while the
`CacheDB` is filled, outside the timed region; needlefish analyzes during execution.

### Memory and size

| | needlefish ReleaseSafe | needlefish ReleaseFast | base/base |
| --- | ---: | ---: | ---: |
| Peak RSS, 10-block fixture | 625 MiB | 59 MiB | 52 MiB |
| Peak RSS, 100-block window | 780 MiB | 224 MiB | 181 MiB |
| Peak RSS, EVM only | 797 MiB | 241 MiB | 112 MiB |
| Peak RSS, 1,000-block window | 2537 MiB | | 921 MiB |
| Binary | 44.8 MB (`base`, the whole multi-tool) | | 17.6 MB (`nf-replay-bench`, executor only, maxperf native) |

base/base uses less memory in every configuration. needlefish allocates its pools from
configured limits at startup (static allocation); `ReleaseSafe` adds about 560 MiB, most
likely the safety-checked allocator's bookkeeping. The replayer sizes its pools from the
archive (`replayer.config_for`), so its footprint grows with the window. Peak RSS is per
process and includes loading the archive.

### Build settings on this machine

Native CPU tuning made both implementations slower here: base/base `maxperf` generic is
1.18x faster than native on execution and 1.70x with roots; needlefish baseline is 1.05x
and 1.10x faster than native. The machine is an Ice Lake server CPU with AVX-512, and code
tuned for it may use wider vector instructions that lower the core's clock. That is a
hypothesis; the VM has no performance counters to confirm it. The headline pair is
native-tuned on both sides as the plan asks, and the untuned pair is in the matrix.

### Node to node (B4)

[etc/bench/node-bench.sh](../etc/bench/node-bench.sh) builds a synthetic chain on the
needlefish devnet and imports it into two fresh nodes through the Engine API, one block at a
time (`engine_newPayloadV4`, then `engine_forkchoiceUpdatedV3`), timing each `newPayload`
call from the same client:

- **Chain**: a devnet genesis prefilled with 10,000 funded accounts, then `base load-test`
  for 60 s at 200 tx/s from 64 senders (transfers 40%, ERC-20 transfers 30%, storage
  writes 30%): 332 blocks of 200 ms, 12,778 transactions, 707.4 Mgas. Every block had to
  return `VALID` on both nodes.
- **needlefish**: `base node` (`ReleaseFast`, native CPU; what `just release` builds), its
  default storage and its default storage-rehash workers (one per spare core).
- **base/base**: `base-reth-node` at the same pinned commit, `--profile release` for
  x86-64 generic (what its Docker images ship), its default MDBX storage, and its default
  threads (reth's parallel state root).
- All four CPUs, no isolation (both nodes use worker threads); one import per node and
  mode, run back to back. Cold drops the page cache after the node starts.

| Node | Mode | newPayload median | p90 | p99 | Total newPayload time | Peak RSS | Datadir on disk |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| needlefish | warm | 4.00 ms | 4.71 ms | 5.21 ms | 1281 ms | 213 MiB | 14.7 MB |
| needlefish | cold | 4.10 ms | 4.84 ms | 5.39 ms | 1301 ms | 213 MiB | 14.7 MB |
| base/base (`base-reth-node`) | warm | 8.03 ms | 9.52 ms | 10.46 ms | 2459 ms | 351 MiB | 12.6 MB |
| base/base (`base-reth-node`) | cold | 8.00 ms | 9.46 ms | 11.55 ms | 2463 ms | 354 MiB | 12.6 MB |

A first run of the same imports gave 4.09 ms and 8.19 ms warm medians. Disk is the
allocated size of the data directory after the import (MDBX's map file is sparse; its
apparent size is 4.1 GB).

needlefish validates and stores a block in about half the time on this chain (median 2.0x,
total 1.92x) and uses less memory; base/base's database is slightly smaller. This is the
first node-to-node result and it is small: synthetic workloads, a 10,000-account state
(mainnet has hundreds of millions of accounts), one run per mode, and timings taken by a
shell client (curl's `time_total` on localhost). Two needlefish limits shaped it:

- needlefish's node is sized for a devnet, with fixed limits and no flag to raise them:
  65,536 accounts in the state trie and 16,384 changed accounts per block, the genesis
  included. A genesis with 100,000 prefilled accounts fails with `ChangesetFull`, so the
  plan's 10M and 100M account prefills cannot run yet.
- It cannot hold mainnet state yet ([SYNC_PLAN.md](SYNC_PLAN.md) M2 and M3), so the
  mainnet import the plan asks for is still to come.


## Correctness found along the way

The 1,000-block window first failed at two blocks, both real needlefish bugs in Base's
native B-20 token precompiles, now fixed with regression tests:

- **Block 54049206**: a `permit` call used 100 gas less than on mainnet. base/base reads the
  owner's nonce slot a second time before incrementing it (a warm SLOAD); needlefish
  reused its first read.
- **Block 54049777**: a token created through the B-20 factory was missing from
  needlefish's state (receipts matched, the state root did not). Installing the token's
  marker code did not mark the new account as touched, so it was not persisted.

Neither affects the fixture or the 100-block window, which contain no such calls.

## What these numbers are not

- **Not a dedicated server.** A 4-vCPU cloud VM with no frequency control, no PMU, and other
  tenants on the host. The intervals capture run-to-run noise in this session, not the
  difference between this machine and another. Ratios between the two implementations
  are more portable than the absolute times.
- **Not node against node** (except the B4 section). The main comparison is between
  **stateless executors**: both read state from a witness of trie nodes, not from a
  database. base/base's executor over a witness is `base-proof-executor`
  (`StatelessL2Builder`), the block builder of its fault-proof program. base/base's node
  (reth, an MDBX database, and a parallel sparse-trie state root) is a different code path,
  and its state root in particular is not what the executor comparison shows.
- **Not a language comparison.** The phase breakdown names the reasons for each gap; they
  are algorithms and data structures (how state is read from the witness, how the state
  root is recomputed), build settings, and parallelism, not Zig against Rust. With state
  reads and tries taken out (EVM only), base/base's interpreter is about 15% faster.
- **Not instructions or cycles.** The VM exposes no hardware counters, so `perf stat`
  could not count instructions or cycles per block; profiles use the `cpu-clock` software
  event.

## Environment

Measured on 2026-11-06 and 2026-11-07 on a cloud virtual machine, not the dedicated server
the plan calls for. Recorded by [etc/bench/env.sh](../etc/bench/env.sh):

| | |
| --- | --- |
| CPU | Intel Xeon, Ice Lake-SP (family 6, model 106), 2.6 GHz nominal, AVX-512 |
| vCPUs | 4: 2 cores x 2 SMT threads (siblings 0-1 and 2-3), 1 socket, 1 NUMA node |
| L3 | 54 MiB (shared with other tenants of the host) |
| RAM | 7.8 GiB |
| Disk | virtio block device, 68 GB |
| Kernel | Linux 6.1, KVM guest, Debian 12 |
| Frequency control | none: the guest has no cpufreq or intel_pstate, so no governor or turbo setting, and `/proc/cpuinfo` always reports 2600 MHz |
| PMU | none ("no PMU driver, software events only"): no instruction or cycle counts |
| Isolation | cgroup cpuset: benchmark processes in their own slice on CPUs 2-3, everything else confined to CPUs 0-1 (see below for the first runs) |
| Pinning | single-threaded runs on CPU 2 with its SMT sibling (CPU 3) idle; threaded needlefish runs on CPUs 2-3 (main thread plus 1 recovery worker on the sibling thread) |
| Memory | `numactl --membind=0` (one node) |
| Toolchains | Zig 0.17.1; rustc 1.96.0 (base/base's `rust-toolchain.toml`) |
| Versions | needlefish `22dfc4c` (fixture, 100-block and EVM-only runs) and `1af6718` (1,000-block runs: adds the two B-20 fixes, the trie pool sizing and a logging fix; the benchmark code is unchanged); base/base `a8b34b69ee43d12fd9f4b4f9335521315f6953ff` |

The host's other tenants and its clock policy are invisible from inside the guest, so the
frequency check between rounds cannot detect throttling here; the per-round load average
stayed near 1.0 (the benchmark process itself).

The fixture, 100-block and EVM-only runs confined `system.slice`, `user.slice` and
`init.scope` but not the sandbox agent's own slice (`amp.slice`), so its processes, among
them a public RPC fetch during part of those runs, could be scheduled on the benchmark
CPUs. `reproduce.sh` now confines every top-level slice except the benchmark's; the
1,000-block runs used that. Both sides were exposed equally (interleaved rounds), and the
intervals above include whatever noise it caused.

## Methodology

### Workloads

| Workload | Blocks | Transactions | Gas | Source |
| --- | ---: | ---: | ---: | --- |
| fixture | 53715983..53715992 (10) | 253 | 46.5 Mgas | committed `src/infra/replay/testdata/base-mainnet-53715983-10.nfrp` |
| window100 | 53775088..53775187 (100) | 1571 | 271.9 Mgas | pinned window of `just replay-check` |
| window1000 | 54048836..54049835 (1000) | 14883 | 2780.2 Mgas | `base replay fetch --count 1000 --from 54048836` |
| evm100 | the 100-block window, `--evm-only` | 1571 | 271.9 Mgas | flat pre-state recorded from the window |

All inputs are needlefish replay archives ([REPLAY.md](REPLAY.md)): the blocks' raw
transactions and headers, the pre-state trie nodes and bytecodes they touch (every byte bound
to the chain by hash or proof), and 256 ancestor block hashes. Both implementations read the
**same archive file**. base/base also gets the first block's parent header from public RPC
(`eth_getBlockByNumber`); the harness checks that it hashes to the archive's parent hash and
carries the archive's parent state root.

### What each side runs

- **needlefish**: `base replay bench <archive> <passes> --recovery-threads <n>`
  ([bin/base/replay_bench.zig](../bin/base/replay_bench.zig)), the replayer behind
  `base replay run`: `execution/node/executor.zig` over `SparseState`, chained so block N+1
  runs on needlefish's own post-state of block N.
- **base/base**: `nf-replay-bench`, a small binary added to a base/base checkout at commit
  `a8b34b69ee43d12fd9f4b4f9335521315f6953ff` by
  [etc/bench/base-harness.patch](../etc/bench/base-harness.patch). It builds
  `StatelessL2Builder` with `BaseEvmFactory` and the Base mainnet `RollupConfig` from
  `base-common-chains`, and calls `build_block` once per block, chaining the sealed header
  as the next parent. That is how base/base's proof program drives it. Payload attributes
  come from the canonical header: timestamp, prev randao, fee recipient, gas limit, parent
  beacon root, and the EIP-1559 and minimum base fee parameters from `extraData`, plus
  empty withdrawals and the raw transactions.
- **Crypto backends.** The harness builds with the crypto backends base/base's node binary
  (`base-reth-node`) uses: C libsecp256k1 for sender recovery and ECRECOVER (alloy-consensus
  and revm `secp256k1`), `blst`, `c-kzg` and aws-lc P256. Built alone, the proof executor
  compiles pure-Rust k256 and arkworks instead; the first version of this harness did that,
  and this document wrongly said it used libsecp256k1. needlefish's crypto is pure Zig.

The patch adds the harness crate, one workspace member line, and small changes in two
base/base crates (`base-proof-mpt`, `base-proof-executor`). None of them alters execution or
the root computations:

1. `TrieProvider::is_opaque_branch` (default `false`) and its use in
   `TrieNode::collapse_if_possible`. When a branch collapses onto a child that the witness
   holds only as a hash, the parent becomes an extension over that hash. That is the same
   result as unblinding a branch child. needlefish archives list such branches (no public
   endpoint serves their preimage). The harness also treats any other sibling that the
   witness lacks as such a reference: `TrieDB` collapses a branch on every delete, and a
   later insert in the same block can re-expand it. If a sibling was really merged, the
   state root would differ and the block would fail. No block failed.
2. `TrieDBProvider::block_hash_by_number` (default `None`), checked first in
   `TrieDB::block_hash`. BLOCKHASH reads come from the archive's 256 ancestor hashes, as in
   a node with a block index.
3. Phase timing: a `clock`, `last_execute_ns` and `last_phases` on `StatelessL2Builder`.
   `build_block` runs `BlockExecutor::execute_block`'s three steps (pre-execution changes,
   each transaction, post-execution changes) itself, so it can read the clock between them;
   that is the body of the trait's default method, which base/base's executor does not
   override. A `trie_db()` accessor reads the computed storage tries (point 4).
4. Between blocks, outside the timed region, the harness gives the provider the
   storage-trie nodes `TrieDB` computed in earlier blocks. `TrieDB` reopens each account's
   storage trie from its root hash in every block, and in the proof program the host serves
   those post-state nodes. needlefish keeps its post-state trie in memory and pays nothing
   for this, so this step favours base/base.
5. `bench_execute_in_memory`: steps 1 to 3 of `build_block` over a caller's revm `State`
   instead of `TrieDB` (EVM only, below).

### Phases

Both sides split every block at the same boundaries and print them on each `BENCH` line:

| Phase | needlefish (`Executor.Phases`) | base/base (`BenchPhases`) |
| --- | --- | --- |
| pre-block | `begin_block`: state cache reset, L1 info, EIP-4788 and EIP-2935 system calls | environment and executor setup, `apply_pre_execution_changes` |
| sender recovery | inline ecrecover in each transaction (or, with workers, waiting for them) | `recovered_transactions_with_encoded`, all senders before the first transaction |
| transactions | the rest of `apply_list` | `execute_transaction` for each transaction |
| post-block | withdrawals (`finish_changes`) | `apply_post_execution_changes` |
| receipts root | `receipts_root` | `compute_receipts_root` |
| state commit | `Backend.commit`: fold the block into the sparse tries (no hashing) | `merge_transitions` and `take_bundle` |
| state root | `Backend.root`: hash the dirty trie nodes | `TrieDB::state_root`: fold the bundle into the tries and hash them |
| header and other | the rest: transactions root, header check and seal | the rest: transactions root, logs bloom, header seal |

*Execution* is pre-block + sender recovery + transactions; *execution + roots* is the whole
block. Because base/base folds the bundle into its tries inside `state_root`, compare
*state commit + state root* across the two sides, not each alone. Reading the clock costs
two calls per transaction on both sides (needlefish around inline recovery, base/base around
each transaction).

The clock is the monotonic clock: `std.Io.Clock.awake` for needlefish, `std::time::Instant`
for base/base. Loading and decoding the archive, hashing the witness, and building the node
index are not timed.

### EVM only

`base replay bench <archive> <passes> --evm-only`
([bin/base/replay_evm.zig](../bin/base/replay_evm.zig)) first replays the window normally,
untimed, and records the first value of every account, slot, code and block hash the
blocks read: the window's pre-state. It writes it as an
`NFPS` file for the base/base harness (`--prestate-out`). Then each pass executes the blocks
through the same block executor over a flat in-memory state (`evm.MemoryDatabase`),
single-threaded, with every sender recovered before the timed region and given to the
executor; a block's changes are written back into the flat state, and no state root is
computed. base/base's `--evm-only` loads the same file into a revm `CacheDB`, recovers the
senders up front, and runs `bench_execute_in_memory` per block over one `State` that keeps
every block's changes. Both must match each block's gas used and receipts root (needlefish
also the logs bloom). The EVM time is *transactions*. revm analyzes bytecode (jump tables)
when the `CacheDB` is filled, outside the timed region; needlefish analyzes during execution.

### Runs and statistics

[etc/bench/reproduce.sh](../etc/bench/reproduce.sh) runs each configuration as a fresh
process per run. Each round runs every configuration once, in a rotated order (round *r*
starts with configuration *r*), so no configuration always runs first, and both sides
interleave. Modes:

- *cold*: page cache dropped (`echo 3 > /proc/sys/vm/drop_caches`) before the process
  starts, first pass. The archive is read before the timed region, so cold mostly adds the
  cost of faulting in the binary's code and first-touch memory.
- *warm*: page cache warm, fresh process, first pass. The headline mode.
- *repeat*: the same warm process's second pass over the same decoded archive, from a fresh
  replayer or `TrieDB`. This was the "warm" of the first version of this document.

[etc/bench/stats.zig](../etc/bench/stats.zig) computes, per configuration and mode: median,
p90 and p99 ms per block over every (block, run) sample; the median window time (sum of the
blocks' times in one pass) with a 95% bootstrap confidence interval (10,000 resamples of the
runs, fixed seed); Mgas/s as window gas over the median window time; and for each compared
pair the speedup (ratio of median window times) with its 95% bootstrap interval, resampling
each side's runs independently. Peak RSS is GNU time's maximum resident set size over each
whole process (including archive loading).

A block that does not reproduce its canonical header (state root, receipts root, gas used,
logs bloom, block hash) fails the run, and `stats.zig` rejects an input with any such block.
In EVM-only mode the check is gas used and receipts root (no state root is computed).

## Reproduce

On a Linux machine with sudo (for dropping the page cache and the cgroup cpuset), `perf`,
`numactl`, GNU time, curl, jq, a Rust toolchain and clang:

```sh
BENCH_ISOLATE=1 etc/bench/reproduce.sh 30     # B1 and B3: every workload, 30 rounds
etc/bench/profile.sh                          # B2: flame graphs into docs/assets/bench/
etc/bench/node-bench.sh 10000 60              # B4: node to node (accounts, load seconds)
```

[etc/bench/reproduce.sh](../etc/bench/reproduce.sh) prints the environment block
([etc/bench/env.sh](../etc/bench/env.sh)), builds the needlefish and base/base matrices,
fetches the archives from public keyless RPC (cached under `.cache/bench/`), clones base/base
at the pinned commit and applies the harness patch, runs the interleaved rounds, and prints
every table in this document through [etc/bench/stats.zig](../etc/bench/stats.zig).
Variables: `BENCH_WORKLOADS` (any of `fixture window100 window1000 evm100`), `BENCH_CPUS`,
`BENCH_SYSTEM_CPUS`, `BENCH_THREADS`, `BENCH_RUNS_1000`, `BENCH_SKIP_BUILD`. Raw samples go
to `.cache/bench/results/<workload>/results.txt`; recompute any table with

```sh
zig run -OReleaseSafe etc/bench/stats.zig -- --pair nf-safe-native-t0/base-maxperf-native \
    < .cache/bench/results/window100/results.txt
```

Everything stays under the git-ignored `.cache/`. The Rust harness never enters this
repository's build, and needlefish keeps zero dependencies.

Both sides print one line per block in the same format:

```
BENCH run=<r> block=<n> txs=<k> gas=<g> exec_ns=<e> total_ns=<t> pre_ns=<p>
    recover_ns=<s> post_ns=<w> receipts_ns=<c> commit_ns=<m> root_ns=<o> ok=<0|1>
```

(one line in the output; wrapped here). Run 0 is the first pass in the process; runs 1 and
up are in-process repeats. needlefish: `base replay bench <archive> [<repeats>]
[--recovery-threads <n>] [--evm-only [--prestate-out <file>]]`. base/base:
`nf-replay-bench <archive> <parent-block.json> [<repeats>] [--evm-only <prestate.nfps>]`.
