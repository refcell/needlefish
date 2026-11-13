# Benchmarks: needlefish vs base/base and revm

needlefish and the Rust [base/base](https://github.com/base/base) implementation execute the
same real Base mainnet blocks from the same pre-state, on the same machine, and both must
reproduce every block's canonical header (EVM only: gas used and receipts root). A block
that does not reproduce fails the run, and the numbers do not count.

Each comparison names what runs on the other side, because base/base has two block
executors: the node (`base-reth-node`, reth's engine over revm) and the fault proof executor
(`base-proof-executor`, which re-hashes its whole trie on every block). The
[first section](#against-the-base-node-and-revm) compares against the node and against revm
on standard EVM fixtures. The [proof executor comparison](#proof-executor-comparison) below it
is older and compares against the proof executor only.

## Against the Base node and revm

Measured November 13, 2026 on one core (pinned, SMT sibling not reserved) of an AMD Ryzen AI
MAX+ 395 (Zen 5, 32 threads), at nice 19 while a live mainnet node ran on other cores.
needlefish at `main` after the instruction fusion change, `-Dcpu=native`; base/base at
`a8b34b69` with `maxperf` and `-C target-cpu=native`.

### Mainnet blocks against the node's execution path

The 100-block window (Base mainnet 53775088 to 53775187) over a flat in-memory pre-state,
senders recovered before the timed region, single-threaded
([EVM only](#evm-only) in the method). 10 rounds; each round runs every configuration once
as a fresh process, in a rotated order, with 3 more passes in the same process (*repeat*).
Every block of every pass reproduced its gas used and receipts root.

| configuration | ms per 100 blocks, first pass (95% CI) | repeat passes (95% CI) | Mgas/s |
| --- | ---: | ---: | ---: |
| needlefish `ReleaseSafe` | 108.1 (105.7-110.0) | 107.6 (106.6-108.1) | 2514 |
| needlefish `ReleaseFast` | 109.8 (107.5-116.1) | 108.8 (107.6-110.5) | 2499 |
| needlefish `ReleaseSafe` before instruction fusion | 114.5 (112.0-116.7) | 113.5 (111.8-114.7) | 2375 |
| base/base node path (revm) | 144.5 (139.8-153.6) | 138.0 (135.8-138.8) | 1881 |
| base/base proof executor, EVM only (revm) | 138.8 (133.6-139.4) | 132.5 (131.4-134.9) | 1959 |

| faster | slower | first pass (95% CI) | repeat (95% CI) |
| --- | --- | ---: | ---: |
| needlefish `ReleaseSafe` | base/base node path | 1.34x (1.29-1.43) | 1.28x (1.26-1.30) |
| needlefish `ReleaseFast` | base/base node path | 1.32x (1.26-1.41) | 1.27x (1.24-1.29) |
| needlefish `ReleaseSafe` before fusion | base/base node path | 1.26x (1.21-1.35) | 1.22x (1.19-1.24) |
| needlefish `ReleaseSafe` | needlefish before fusion | 1.06x (1.03-1.09) | 1.05x (1.04-1.07) |

- **The node path** (`nf-replay-bench --evm-only <prestate> --node`) is what `base-reth-node`
  runs for a new payload (reth `crates/engine/tree/src/tree/payload_validator.rs`): the
  node's `BaseEvmConfig` for Base mainnet, `ConfigureEvm::executor_for_block` over a `State`
  with bundle updates, `apply_pre_execution_changes`, every transaction,
  `apply_post_execution_changes`, and `merge_transitions`. It is built with the features the
  node binaries enable by default, `asm-keccak` and `keccak-cache-global`. What differs from
  the running node: its database is an in-memory `CacheDB` instead of MDBX behind reth's
  execution cache (this favours it), its precompile result cache is not installed, and no
  prewarming threads run. *Execution* is pre-block changes plus transactions on both sides;
  post-block changes and the commit (`merge_transitions`, needlefish `Backend.commit`) are
  timed separately.
- **Before this run the comparison was unfair to revm in two ways**, both fixed: the harness
  built revm with the portable Keccak instead of the node's `asm-keccak` and global Keccak
  cache (1.15x slower on this window), and it analyzed bytecode while filling `CacheDB`,
  outside the timed region, while needlefish analyzed inside it. needlefish now analyzes
  the window's code into its process-lifetime analysis cache before timing, as a running
  node holds it. Under the old harness needlefish's `main` measured 1.28x; the earlier
  0.85x in this document came from a different, slower machine and an older needlefish.
- **State roots** are not compared with the node: reth computes them against its database,
  and there is no offline harness for that yet.

### EVM fixtures against revm and evm2

evm2's 31 fixtures (`data/*.json` minus the precompile cases) as in
[EVM vs evm2](#evm-vs-evm2), 8 rounds, keccak memo off on every side. revm 43 and evm2 run
through evm2's CLI (`--engine revm`, `--engine evm2`, stable-Rust build). Median µs per
transaction over processes; the speedup is the ratio of medians.

| case | gas | needlefish ReleaseSafe µs | ReleaseFast µs | evm2 µs | revm µs | ReleaseSafe vs revm | ReleaseFast vs revm |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| aggregation_router_v6 | 321324 | 104.759 | 101.024 | 142.648 | 149.895 | 1.43x | 1.48x |
| airdrop | 23435 | 0.413 | 0.351 | 0.920 | 0.881 | 2.13x | 2.51x |
| balancer_vault | 77348 | 25.711 | 24.770 | 40.482 | 44.859 | 1.74x | 1.81x |
| bswap64 | 21986 | 0.567 | 0.487 | 1.125 | 1.136 | 2.00x | 2.33x |
| bswap64_opt | 21836 | 0.532 | 0.464 | 1.036 | 1.070 | 2.01x | 2.31x |
| burntpix | 92399448 | 16437.311 | 16907.208 | 32943.487 | 44647.039 | 2.72x | 2.64x |
| counter | 43363 | 0.384 | 0.325 | 0.903 | 0.818 | 2.13x | 2.52x |
| curve_3pool | 55057 | 9.636 | 9.320 | 14.380 | 18.548 | 1.92x | 1.99x |
| curve-stableswap-2pool | 157780 | 28.781 | 28.663 | 50.964 | 62.051 | 2.16x | 2.16x |
| curve_tricrypto2 | 100307 | 21.330 | 19.957 | 35.349 | 45.558 | 2.14x | 2.28x |
| eip2935 | 23365 | 0.361 | 0.305 | 0.813 | 0.758 | 2.10x | 2.48x |
| eip4788 | 25496 | 0.391 | 0.325 | 0.858 | 0.796 | 2.04x | 2.45x |
| entry_point_v0_7 | 251245 | 117.324 | 113.529 | 138.730 | 146.704 | 1.25x | 1.29x |
| erc20_transfer | 13529850 | 3668.921 | 3726.171 | 4366.317 | 5143.326 | 1.40x | 1.38x |
| factorial | 87203 | 15.828 | 15.825 | 30.506 | 42.793 | 2.70x | 2.70x |
| fiat_token | 23445 | 0.414 | 0.350 | 0.920 | 0.845 | 2.04x | 2.42x |
| fibonacci-calldata | 84203 | 14.196 | 14.063 | 30.318 | 43.197 | 3.04x | 3.07x |
| hash_10k | 2572907 | 2267.415 | 2278.490 | 2710.522 | 3092.054 | 1.36x | 1.36x |
| onchain_lm_v2 | 456640284 | 161527.275 | 159499.692 | 239351.467 | 291067.024 | 1.80x | 1.82x |
| push0_proxy | 23652 | 0.406 | 0.331 | 0.889 | 0.875 | 2.16x | 2.65x |
| seaport | 24051 | 0.647 | 0.563 | 1.128 | 1.096 | 1.69x | 1.95x |
| snailtracer | 205087902 | 24138.335 | 23901.860 | 42233.907 | 54970.656 | 2.28x | 2.30x |
| succinct_staking | 49735 | 3.494 | 3.120 | 5.996 | 7.133 | 2.04x | 2.29x |
| uniswap_v2_pair | 23568 | 0.463 | 0.390 | 0.996 | 0.964 | 2.08x | 2.47x |
| uniswap_v3_pool | 79765 | 6.913 | 6.841 | 10.455 | 12.764 | 1.85x | 1.87x |
| uniswap_v4_pool_manager | 100521 | 3.598 | 3.418 | 5.560 | 6.667 | 1.85x | 1.95x |
| univ2_router | 22601 | 0.558 | 0.494 | 1.232 | 1.272 | 2.28x | 2.57x |
| universal_router | 116932 | 27.617 | 26.919 | 42.192 | 45.846 | 1.66x | 1.70x |
| usdc_proxy | 25644 | 0.529 | 0.441 | 1.051 | 1.015 | 1.92x | 2.30x |
| usdt | 41285 | 2.034 | 1.941 | 3.311 | 3.620 | 1.78x | 1.87x |
| weth | 51318 | 1.264 | 1.166 | 1.973 | 2.110 | 1.67x | 1.81x |
| geometric mean | | | | | | 1.94x | 2.11x |

- needlefish `ReleaseSafe` is 1.94x revm and 1.76x evm2 by geometric mean, `ReleaseFast`
  2.11x revm. The same `ReleaseSafe` before instruction fusion was 1.92x revm: fusion gains
  1.10-1.24x on contract-heavy cases (balancer_vault, universal_router, snailtracer) and
  costs 4-8% on the 21k-gas cases and 3% on onchain_lm_v2. The cause of that cost is not
  measured; the analysis cache is kept across iterations, so it is not analysis time. A
  likely candidate is the larger interpreter (59 fused handlers).
- The precompile fixtures, measured separately: ecrecover 25 µs on both sides (revm uses C
  libsecp256k1), bn254 pairing 610 µs against 800 µs, modexp from 0.8x to 2x.

## Proof executor comparison

Everything from here to [Correctness found along the way](#correctness-found-along-the-way)
compares needlefish with base/base's **fault proof executor** (`base-proof-executor`,
`StatelessL2Builder`), not with its node. It was measured on a 4-vCPU cloud VM before
November 13, 2026, with the harness that built revm without the node's Keccak features.

This is the second version of this comparison. The first version (one laptop run) had the
biases listed in [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md): few runs, no confidence intervals,
7 recovery threads against 1, a faster needlefish build than base/base's, and no
attribution. This version follows that plan. It runs on a cloud VM rather than a dedicated
server; [What these numbers are not](#what-these-numbers-are-not) says what that costs.

### Summary

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
  unchanged contract code after each block. It is fixed since: needlefish's execution +
  roots is 1.23x faster on the 100-block window and 1.28x on the 1,000-block window
  ([code re-hash fix](#code-re-hash-fix)).
  The other tables in this document predate the fix.
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
  of the block and most of the 2.5 ms/block "state commit" phase above. It is fixed since
  (below); the numbers here describe the code as it was measured.
- **Sender recovery** is 15% of needlefish's block; base/base's (C libsecp256k1) does not
  reach 1.5% of its much longer block. It is the one execution phase where base/base is
  faster in absolute time (0.80 against 1.00 ms/block).

#### Code re-hash fix

The replayer (and the follower) now look a changed contract's code up by the account's
`code_hash`, which the evm already holds, and hash only code new to the store (in safe
builds, to check the hash). Measured with `reproduce.sh`'s method (`base replay bench`,
`ReleaseSafe` native, fresh process per run, cold and warm, `--recovery-threads 0`, one
pinned CPU, before and after interleaved over 30 rounds, 10 on the 1,000-block window with
no in-process repeat, `etc/bench/stats.zig`) but without cgroup isolation, on another 4-vCPU
cloud VM: compare before with after, not with the tables above. Every block matched its
header in every run.

| Workload | Phase | before ms/block | after ms/block | speedup, warm (95% CI) |
| --- | --- | ---: | ---: | ---: |
| 10-block fixture | execution | 9.32 | 9.29 | 1.00x (0.98-1.02) |
| 10-block fixture | execution + roots | 13.26 | 11.13 | 1.19x (1.16-1.22) |
| 10-block fixture | state commit (phase mean) | 3.33 | 1.25 | |
| 100-block window | execution | 4.71 | 4.72 | 1.00x (0.98-1.02) |
| 100-block window | execution + roots | 7.35 | 5.98 | 1.23x (1.21-1.25) |
| 100-block window | state commit (phase mean) | 2.19 | 0.84 | |
| 1,000-block window | execution | 4.56 | 4.47 | 1.02x (1.00-1.05) |
| 1,000-block window | execution + roots | 7.48 | 5.83 | 1.28x (1.26-1.31) |
| 1,000-block window | state commit (phase mean) | 2.45 | 0.90 | |

Times are median window time over blocks, warm; cold gives about the same ratios (1.20x,
1.24x and 1.26x).


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

### EVM vs evm2

needlefish's interpreter against [evm2](https://github.com/alloy-rs/evm2) (`37fb326b`) and
revm 43 on evm2's own fixture suite (`data/*.json` minus the precompile cases: 31 single-
transaction state tests, from 21k-gas transfers to snailtracer and burntpix). Both sides
run the same loop: one `transact` per iteration on a reused EVM, after an untimed state
reset, for 20 ms of warm-up and 20 ms timed per case and process
([etc/bench/evm2.sh](../etc/bench/evm2.sh)). A case counts only when every engine reports
the same gas used. Speedup is the ratio of median µs per transaction over fresh processes,
above 1 meaning the first engine is faster; the summary is the geometric mean over cases.

| pair | P0 (before) | P1 (register locals) | P2 (handler stores and checks) | P3 (keccak) | P4 (lookups, division) | P5 (ReleaseSafe checks) | P6 (secp256k1, code check) | P7 (code reads, CALLDATALOAD, inverse check) | P8 (division stalls, keccak theta) | P9 (division in registers) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| needlefish ReleaseSafe vs evm2 tail-call | 0.64x | 0.76x | 0.84x | 0.85x | 1.04x | 1.10x | 1.24x | 1.27x | 1.29x | 1.30x |
| needlefish ReleaseFast vs evm2 tail-call | 0.77x | 0.89x | 1.05x | 1.13x | 1.36x | 1.37x | 1.38x | 1.37x | 1.38x | 1.39x |
| needlefish ReleaseFast vs evm2 stable (packed) | 0.91x | 1.04x | 1.24x | 1.49x | 1.69x | 1.62x | 1.63x | 1.65x | 1.64x | 1.65x |
| needlefish ReleaseFast vs evm2 tail-call, both with keccak memo | - | - | - | 1.07x | 1.37x | 1.41x | 1.42x | 1.38x | 1.39x | 1.39x |
| needlefish ReleaseFast (no memo) vs evm2 tail-call + keccak memo | 0.70x | 0.81x | 0.96x | - | - | - | - | - | - | - |
| evm2 tail-call vs revm | 1.25x | 1.25x | 1.25x | 1.30x | 1.20x | 1.24x | 1.23x | 1.28x | 1.29x | 1.29x |

| case (ReleaseFast vs evm2 tail-call) | P0 µs | P1 µs | P2 µs | evm2 µs (P2 run) | P2 speedup | P3 speedup | P3 both memo | P4 speedup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| fibonacci-calldata | 63.8 | 42.0 | 23.7 | 26.7 | 1.13x | 1.05x | 1.17x | 1.16x |
| snailtracer | 80,352 | 63,842 | 51,852 | 47,711 | 0.92x | 0.74x | 0.65x | 1.06x |
| burntpix | 71,941 | 45,507 | 30,609 | 34,035 | 1.11x | 1.01x | 0.90x | 1.09x |
| uniswap_v3_pool | 25.1 | 21.6 | 17.8 | 16.3 | 0.91x | 0.79x | 0.74x | 1.07x |
| erc20_transfer | 13,230 | 12,822 | 11,979 | 6,119 | 0.51x | 0.92x | 0.73x | 1.11x |
| hash_10k | 8,383 | 8,206 | 7,372 | 3,404 | 0.46x | 0.97x | 0.91x | 0.93x |
| counter | 1.00 | 0.99 | 0.83 | 1.41 | 1.70x | 1.78x | 1.63x | 2.22x |

- *evm2 tail-call* is evm2's default on nightly Rust (`become` handlers with the
  `preserve_none` calling convention); *packed* is its stable-Rust dispatch. The *memo*
  build turns on alloy's process-global keccak cache, which evm2's own benchmark and reth
  enable. Up to P2 needlefish had no memo, and the keccak-bound cases (erc20_transfer,
  hash_10k) were where it trailed most. From P3 the memo-off pairs run `statetest
  --no-keccak-memo`, and *both with keccak memo* pairs needlefish's per-`Evm` memo with
  evm2's.
- needlefish wins every tiny transaction (counter, airdrop, eip2935, eip4788, fiat_token,
  push0_proxy, uniswap_v2_pair, usdc_proxy: 1.5-1.7x at P2), where per-transaction setup
  dominates.
- P1 keeps pc, gas and the stack in locals between opcodes that need nothing else. P2 writes
  every stack result with one 32-byte store, keeps pc and stack length 64-bit, charges gas
  with one subtract and a borrow branch, and checks only the stack bound an opcode can cross
  (see the evm lane). A tail-call dispatch backend like evm2's was built and measured for P2
  and ran 5-14% slower than the labeled `switch`, which already compiles to threaded
  dispatch in Zig; it was not kept.
- P3 hashes KECCAK256 with an AVX-512 Keccak-f (one lane per 128-bit register, about 2.4x
  std's permutation on a 64-byte input) and memoizes digests of inputs up to 64 bytes per
  `Evm`. Memo off, the keccak-bound cases move from about 0.5x to parity with evm2 (hash_10k
  0.46x -> 0.97x, erc20_transfer 0.51x -> 0.92x). The geometric mean moved by less (1.05x
  -> 1.13x), and the P2 -> P3 swing on snailtracer and uniswap_v3_pool (0.92x -> 0.74x,
  0.91x -> 0.79x) has no keccak in its hot loop and sits within those cases' intervals.
  The curve pools and uniswap_v3_pool still trailed at 0.78-0.88x.
- P4 hashes and compares account and slot map keys as words (the address had compiled to
  twenty byte loads per hash and compare) and divides EVM words with one `divq` per quotient
  digit on x86-64. Every compute and contract case is now at or above evm2 tail-call:
  curve 1.02-1.11x, uniswap_v3_pool 1.07x, snailtracer 1.06x, entry_point 1.01x; only
  hash_10k stays below (0.93x, 0.68-0.99). ReleaseSafe reaches parity (1.04x).
- P5 drops ReleaseSafe checks that cannot fire in the dispatch loop: the overflow check on
  `pc += 1` (pc stays inside the padded code; the `code[pc]` bounds check remains) and the
  stack index checks after each opcode's stack check, which is now two-sided with runtime
  safety so it proves `len <= 1024`. ReleaseSafe 1.04x -> 1.10x; ReleaseFast compiles to the
  same code. This 10-round run has tight per-case intervals and corrects the P4 picture:
  ReleaseFast still trails on entry_point_v0_7 (0.85x, 0.81-0.87), hash_10k (0.93x),
  curve_tricrypto2 (0.96x) and curve-stableswap-2pool (0.98x); ReleaseSafe trails on the
  contract-heavy cases (curve_tricrypto2 0.74x, entry_point 0.79x, aggregation_router 0.83x)
  and wins the compute ones (fibonacci 1.20x, factorial 1.06x, burntpix 1.00x).
- Base 10-block replay at ee94b4f against P2 (f819f64), both ReleaseSafe -Dcpu=native, run
  alternately in one session (3 rounds of 10 warm passes, 330/330 header matches each):
  5.16 ms to 4.28 ms per block (1.21x, 95% CI 1.12-1.26), every block faster (1.11-1.34x).
  EVM time is exec_ns - pre_ns. This session's absolute times are lower than the 2026-11-09
  measurement of the same pair (6.34 to 5.19 ms), so compare the ratio, not the milliseconds.
- P6 speeds up secp256k1 and the safe-build code check. ecrecover builds R's odd multiples
  affine on an isomorphic curve (libsecp256k1's global-z table), so every R digit is a
  mixed addition, and inlines the field multiply (50 -> 42 µs per recovery). Safe builds
  had byte-compared a cached code analysis with the caller's code on every frame,
  including each transaction's top-level call; they now compare once per code buffer.
  ReleaseSafe 1.10x -> 1.24x: the small transactions on large contracts gain most
  (fiat_token 0.93x -> 1.91x, seaport 0.88x -> 1.54x, univ2_router 0.84x -> 1.41x),
  curve_tricrypto2 0.74x -> 0.85x. ReleaseFast entry_point_v0_7 0.85x -> 0.96x. Still
  behind in ReleaseSafe: the curve pools (0.85-0.87x), entry_point (0.85x), hash_10k,
  universal_router, aggregation_router (0.92-0.93x); in ReleaseFast: hash_10k (0.90x),
  entry_point (0.96x), curve_tricrypto2 (0.97x). Profiles of the remaining ReleaseSafe gap
  show it spread over the dispatch loop and 256-bit division (1.14x and 1.20x their
  ReleaseFast cost on curve-stableswap) with no single dominant check.
- P7 targets the ReleaseSafe gap on contract-heavy cases without dropping a check that can
  fire. The dispatch loop read every opcode and PUSH immediate through a bounds check that
  the zero padding after the code already rules out; it now asserts the padding and JUMPDEST
  bitmap invariants once per frame and reads through pointers (331 -> 151 panic branches;
  ReleaseFast compiles to the same loop). CALLDATALOAD reads a word inside the calldata in
  place instead of through a padded copy that stalled on store forwarding. In safe builds
  safegcd checked every inverse with a wide `%`, which LLVM lowers to a bit-serial loop of
  about 70k instructions; the same check is now a Barrett product (ecrecover 47.9 -> 43.0 us
  in ReleaseSafe). Interleaved A/Bs against P6 in ReleaseSafe, 8 rounds each: 1.043x
  [1.036, 1.053], then 1.014x [1.007, 1.018]. In this 10-round run the ReleaseSafe gaps
  narrow to curve 0.93-0.96x (P6 0.85-0.87x) and entry_point 0.93x (0.85x);
  aggregation_router (1.05x) and universal_router (1.04x) are now ahead. Behind in
  ReleaseSafe: hash_10k 0.90x, snailtracer, erc20_transfer and entry_point 0.93x; in
  ReleaseFast: hash_10k 0.90x, erc20_transfer 0.93x, snailtracer 0.95x. evm2 itself ran
  differently on this VM (tail-call vs revm 1.28x, P6 1.23x), so compare columns as ratios
  from their own sessions. Base 10-block replay against P6 in one session: every header
  matches, EVM time 4.79 -> 4.72 ms per block (1.015x, 95% CI 1.000-1.033), and with
  inline sender recovery the recovery phase 1.198 -> 1.074 ms per block.
- P8 removes two store-forwarding stalls and matches keccak-asm's Keccak round. Division
  returned a 64-byte quotient-and-remainder through memory, which the DIV family's handlers
  reloaded with wide loads straddling the callee's narrower stores; word-sized operands now
  divide in registers, and wider ones write the stack slot from out of line with one 32-byte
  store (snailtracer 1.043x ReleaseFast, 1.030x ReleaseSafe against P7, 16 interleaved
  rounds). The AVX-512 Keccak round had compiled to 35 `vpternlogq` and 30 two-input xors,
  because LLVM reassociated theta's three-input xor; it now calls the ternary-logic
  intrinsic (60 `vpternlogq`, keccak-asm's loop), and messages under one block load straight
  into the lane registers: 64-byte hash 278 -> 259 ns (keccak-asm 249), hash_10k 1.112x and
  erc20_transfer 1.07-1.11x against the division build, 10 interleaved rounds. In this run
  hash_10k reaches 0.99x in both builds (P7 0.90x) and erc20_transfer 1.06x (0.93x);
  snailtracer is at parity (0.99x ReleaseSafe, 1.01x ReleaseFast). Still behind in
  ReleaseSafe: the curve pools 0.95-0.97x, entry_point 0.95x, uniswap_v3_pool 0.96x,
  onchain_lm_v2 and burntpix 0.97x; in ReleaseFast only onchain_lm_v2 (0.97x) is outside
  0.99-1.01x. Profiles put the remaining ReleaseSafe cost in TigerStyle asserts on the
  256-bit division and secp256k1 field paths (entry_point's ecrecover: point doubling 1.21x
  its ReleaseFast cost), not in the dispatch loop. Base 10-block replay against P7 in one
  session: every header and state root matches; EVM time 1.013x (95% CI 1.009-1.021) for the
  division change and 1.004x (1.002-1.006) more for keccak, block total with roots 1.03x.
- P9 keeps division results in registers until the stack slot: `div`, `rem`, `div_rem` and
  single-limb division inline into the out-of-line DIV/MOD/ADDMOD/MULMOD bodies, which end in
  one 32-byte store (P8 still passed results through stack temporaries copied with
  unforwardable wide loads). Against P8, two interleaved runs: curve_tricrypto2 1.055-1.075x
  ReleaseSafe and 1.045x ReleaseFast, curve-stableswap 1.03-1.06x, uniswap_v3_pool
  1.02-1.04x. In this run ReleaseSafe reaches 1.01x on curve-stableswap and 1.00x on
  curve_tricrypto2 (P8 0.95x, 0.96x). Behind in ReleaseSafe: entry_point 0.94x (secp256k1
  field asserts), onchain_lm_v2 and burntpix 0.96x, curve_3pool, factorial and
  fibonacci-calldata 0.97x; factorial varies 5% between processes of one binary, and 12
  processes each put its ReleaseSafe-only cost at 4%. Measured and not kept: a one-sided
  stack check in safe builds with unchecked stack indexing (one `lea` fewer per opcode, the
  ReleaseFast form) ran 0.985x (CI 0.982-0.989), onchain_lm_v2 0.957x; P5's two-sided check
  stays. Base replay: every header and state root matches, EVM time 1.001x. The orb paused
  several times during this run.
- hash_10k chains KECCAK256 over 32 fresh bytes, so no memo helps; evm2's keccak-asm runs
  the same AVX-512 lane-per-register permutation as needlefish's, within ~4%.
- P2 also skips clearing an empty transient-storage table in the untimed state reset (as each
  transaction start already did); measured alone, it moves the timed transaction 0-4%
  (warmer caches), mostly on the small cases.
- Measured 2026-11-08 on the 4-vCPU cloud VM, pinned to one CPU but not isolated; P0 is 3
  rounds, P1 and P2 5 rounds, P3 15 rounds, so per-case intervals are wide (printed by
  `stats.zig --cases`). During the P3 run the VM ran about 1.5-2x slower for both engines
  (evm2 snailtracer 48 -> 73 ms), so only same-run ratios are comparable across columns,
  which is why the case table gives P3 as speedups only. P4 is 10 rounds measured
  2026-11-09 with nothing else running; a P4 run under load from a parallel test suite read
  the curve pools at 0.68-0.76x, so compare only unloaded runs. P5 is 10 rounds measured
  2026-11-09 on an idle VM, as is P6. P7, P8 and P9 are 10 rounds each, measured 2026-11-11 on
  an idle VM (two physical cores with two hyperthreads each; runs pinned to one hyperthread
  while its sibling stayed idle).

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
when the `CacheDB` is filled, outside the timed region; needlefish analyzes the recorded code
into its process-lifetime analysis cache before each timed pass (since November 13, 2026;
before that it analyzed during execution). With `--node` the base/base harness runs the
node's execution path instead of `bench_execute_in_memory`
([Against the Base node and revm](#mainnet-blocks-against-the-nodes-execution-path)).

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
