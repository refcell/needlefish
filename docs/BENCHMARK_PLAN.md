# Benchmark accuracy plan

The numbers in [BENCHMARKS.md](BENCHMARKS.md) and the README come from one laptop run. They
show needlefish's replay executor beating base/base's stateless proof executor, but several
biases make the gap look larger than a fair comparison would, and nothing explains where the
time goes. This plan turns them into numbers someone can rely on. It is written for an agent
working on a dedicated Linux server.

Do the phases in order. Each phase ends with committed results, so a partial run still
improves the docs.

## What is wrong with the current numbers

| Bias | Effect | Fix (phase) |
| --- | --- | --- |
| Laptop, macOS, background security agents (~3 cores busy), no CPU isolation, no frequency control | Noise and unknown variance | Dedicated Linux server, isolated cores, fixed frequency (B0) |
| Few runs (1 cold + 10 warm), no confidence intervals, implementations run back to back, not interleaved | Medians without error bars; drift favors whichever ran first | 30+ interleaved runs, bootstrap CIs (B0, B1) |
| "Warm" means a second pass in the same process over the same decoded archive | Measures caches more than real block import | Report cold and warm with exact definitions; add a fresh-process, dropped-page-cache cold run (B1) |
| needlefish recovers senders on 7 threads; base/base recovers them inline on 1 | Part of the execution gap is parallelism, not speed | Run both at 1 thread, and both at N threads where possible (B1) |
| needlefish built `ReleaseFast` for the native CPU (no safety checks); base/base built with its `release` profile (thin LTO, 16 codegen units, generic CPU) | Build settings favor needlefish | Matrix: needlefish `ReleaseFast` and `ReleaseSafe`, base/base `release` and `maxperf`, both with and without native CPU tuning (B1) |
| base/base's proof executor re-hashes every trie node it holds on every block (no hash cache); needlefish caches hashes and re-hashes dirty nodes in parallel | The 5.8x "with roots" gap grows with the window length; it is a design difference in a proof-oriented executor | Report root time separately and per window length; add the node comparison (B1, B4) |
| Compared against `base-proof-executor`, which is built for fault proofs, not throughput | Not what a Base node does | Add a node-to-node comparison through the Engine API (B4) |
| Nobody profiled either side | No explanation of the execution gap | Attribution with `perf` and flame graphs (B2) |
| Only Mgas/s headlines | Hard to read | Report ms per block and the speedup ratio from the same totals (B5) |

## Rules

- Both sides must reproduce every block's canonical header (state root, receipts root, gas
  used, block hash) in every run, or the run does not count. Keep this check outside the
  timed region.
- Same input bytes for both sides, same machine, same session, interleaved runs.
- Pin every version: needlefish commit, base/base commit, Zig and Rust toolchains, kernel.
- Report every configuration you ran, including ones where base/base wins. No cherry
  picking; if a number gets worse after a fix, the worse number goes in the doc.
- The Rust harness stays outside this repository's build (it lives in a base/base checkout
  under `.cache/`, applied from `etc/bench/base-harness.patch`). needlefish keeps zero
  dependencies.
- Nothing machine-specific or personal in commits: no hostnames, usernames, home paths,
  IP addresses or endpoint keys. Describe hardware by model (CPU, RAM, disk, kernel).
- Public keyless RPC only for fetching archives; archives are cached under `.cache/`.

## Phase B0: environment

Goal: a quiet, repeatable machine, and a script that records its state.

- Linux, current LTS kernel, no desktop session, nothing else running. Record CPU model,
  core counts, RAM, disk model, kernel version.
- CPU frequency: set the `performance` governor and disable turbo/boost
  (`intel_pstate/no_turbo` or `cpufreq/boost`), so clock speed does not depend on
  temperature. Record the fixed frequency.
- Isolate cores for the benchmark (`isolcpus` or a cgroup cpuset) and pin each run with
  `taskset`. Keep SMT siblings of benchmark cores idle (or disable SMT) and say which.
- Pick one NUMA node and bind memory to it (`numactl --cpunodebind --membind`).
- Record `/proc/loadavg`, thermal readings and frequency before and after each batch, and
  discard batches where frequency moved.
- Add `etc/bench/env.sh` that prints this environment block; `reproduce.sh` includes it in
  its output.

## Phase B1: fair executor comparison

Goal: the existing stateless comparison, rerun without the known biases.

- needlefish: add `--recovery-threads N` to `base replay bench` and `base replay run`
  (0 = inline in the executor, today's default stays `min(cores - 1, 7)`). Results must not
  depend on N; add a test that asserts identical reports for N = 0 and N = 7.
- base/base harness: if sender recovery can be parallelized from the harness without
  touching the executor, add an N-thread mode; otherwise report base/base at 1 thread only
  and compare it with needlefish at 0 and at N threads.
- Build matrix (all four combinations go in the full table):
  - needlefish: `zig build -Doptimize=ReleaseFast` and `-Doptimize=ReleaseSafe`, each with
    the default native target and with a baseline target (`-Dcpu=baseline`).
  - base/base: `cargo build --profile release` and `--profile maxperf`, each with and without
    `RUSTFLAGS="-C target-cpu=native"`.
  - Headline: the most comparable pair, both native-tuned, needlefish `ReleaseSafe` vs
    base/base `maxperf`. State the pair in the README.
- Runs: for each configuration, 30+ runs in interleaved order (A B A B ...), each run a fresh
  process. Define:
  - *cold*: fresh process after `echo 3 > /proc/sys/vm/drop_caches`, first pass;
  - *warm*: fresh process, page cache warm, first pass;
  - *in-process repeat*: today's "warm" (second pass in the same process), reported but not
    the headline.
- Workloads: the committed 10-block fixture, the pinned 100-block window, and one or more
  1,000-block windows of recent mainnet blocks (fetch with `base replay fetch --count 1000`).
  Report the root phase per window length, so the effect of base/base's re-hashing over long
  windows is visible instead of baked into one number.
- Metrics per configuration: median, p90, p99 ms per block; total time for the window;
  Mgas/s from the same totals; 95% bootstrap confidence interval for the median and for the
  speedup ratio; peak RSS; instructions per block and cycles per block from `perf stat`.

## Phase B2: attribution

Goal: explain where each side spends its time, so the docs can say why one is faster.

- Profile both sides on the 100-block window with `perf record -g` (needlefish with frame
  pointers or DWARF unwinding; base/base with its `release-symbols` profile). Commit
  flame graph SVGs under `docs/assets/bench/` and summarize them.
- Break each block into phases on both sides, with the same boundaries: pre-block system
  calls, sender recovery, transaction execution (split interpreter vs state reads where the
  profile allows), post-block changes, receipts root, state root, header seal.
- Conclusion table in BENCHMARKS.md: for each phase, time on each side and the main reason
  for the difference (algorithm, parallelism, data structure, build setting, unknown).

## Phase B3: EVM only

Goal: isolate the interpreter from state access and trie work.

- Build a small harness on each side that executes the same transactions against the same
  fully in-memory state (a flat map of accounts, storage and code loaded from the archive's
  pre-state), single-threaded, senders pre-recovered, no root computation.
- needlefish side: a `base replay bench --evm-only` mode (or a bench target under
  `src/execution/evm`). base/base side: the harness drives revm directly over an in-memory
  database.
- Report ms per block and the ratio. Also run a few EVM micro workloads both sides already
  share (for example the public `evm-bench` style contracts) if they reproduce identically.

## Phase B4: node to node

Goal: compare real nodes with on-disk state, which is what "faster than a Base node" means.

- Generate a chain both nodes can import from genesis: run base/base's benchmark launcher
  (`etc/systems/src/benchmark_cli.rs`, fresh devnet workloads such as transfers, ERC-20 and
  the mainnet mix) or needlefish's `base load-test` against a devnet, and export the blocks
  (base/base `etc/systems/src/block_export.rs`). Prefill state (a large genesis alloc, for
  example 10M then 100M accounts and slots) so trie depth is closer to mainnet.
- Import the same blocks into a fresh base/base node (reth backend, its default storage) and a
  fresh needlefish node from the same genesis, driving both through the Engine API
  (`engine_newPayload` then `engine_forkchoiceUpdated` per block), on the same disk.
- Measure `newPayload` latency per block (median, p90, p99), total import time, disk bytes
  written, and peak RSS. Run with both nodes fully synced up to the start block, page cache
  cold and warm.
- Once needlefish can hold mainnet state (docs/SYNC_PLAN.md milestones M2 and M3), repeat the
  same import on real mainnet blocks from a common snapshot block. That is the comparison the
  README should eventually lead with.

## Phase B5: update the docs

- BENCHMARKS.md: replace the Results section with the B1 headline pair, the full matrix, the
  B2 attribution table, B3 and B4 results as they land, the environment block from B0, and
  exact reproduce commands. Keep the "What these numbers are not" section current.
- README "Benchmarks" section, kept short:
  - One sentence of caveats first: hardware, what is compared (executor vs executor, or node
    vs node), and which build pair.
  - Report time per block and the speedup, from the same totals, with the 95% interval. For
    example: "2.3 ms vs 13.5 ms per block (5.8x, 95% CI 5.5-6.1x)".
  - Say where base/base wins (memory today).
  - Do not attribute the difference to the language. Name the measured reasons from B2.
  - Link BENCHMARKS.md for everything else.
- `etc/bench/reproduce.sh` reproduces every number in the README on a fresh server.
- `zig build test && just tidy` before pushing, as for any change (AGENTS.md).

## Done when

- Every README number has a confidence interval, an exact configuration and a reproduce
  command, and was measured on the isolated server.
- The thread count and build settings are matched, or the mismatch is stated next to the
  number.
- BENCHMARKS.md explains the gap phase by phase with profiles, and states whether the
  interpreter itself is faster.
- At least one node-to-node result (B4) is published, even if only on synthetic state.
