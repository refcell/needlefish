# Lane: bench

Owns `docs/BENCHMARKS.md`, `docs/BENCHMARK_PLAN.md`, `docs/assets/bench/`, `etc/bench/`,
`bin/base/replay_bench.zig` (`base replay bench`), `bin/base/replay_evm.zig` (`--evm-only`),
and the README's Benchmarks section.

Goal: an honest, reproducible execution benchmark of needlefish against the Rust base/base
implementation on the same machine and the same real Base mainnet blocks, and a production
README.

## Checklist

- [x] `base replay bench <archive> [warm runs]`: one cold and N warm replays, one `BENCH`
      line per block (execution-only and whole-block time, gas, verified flag).
- [x] `Executor.phase_clock` / `last_execution_ns`: optional execution-phase timing in
      `execution/node/executor.zig` (null by default, no effect on behavior).
- [x] base/base harness (`etc/bench/base-harness.patch`) over `StatelessL2Builder`, reading
      the same `.nfrp` archive; every block's sealed header must equal the canonical one.
- [x] `etc/bench/reproduce.sh` and `etc/bench/summarize.sh`.
- [x] `docs/BENCHMARKS.md` and the README Benchmarks section; README productionized.
- [x] Plan B0: `etc/bench/env.sh` (environment block, per-round frequency check), cgroup
      isolation (`BENCH_ISOLATE=1`), pinned single-thread runs, NUMA binding.
- [x] Plan B1: `--recovery-threads N` (test: identical reports at 0 and 7), build matrix,
      interleaved fresh-process cold/warm runs, `etc/bench/stats.zig` (bootstrap CIs),
      1,000-block window. `summarize.sh` is replaced by `stats.zig`.
- [x] Plan B2: `Executor.Phases` and the same phases in the harness, `etc/bench/profile.sh`
      flame graphs.
- [x] Plan B3: `base replay bench --evm-only` and the harness's `--evm-only` over one
      recorded flat pre-state (`NFPS`).
- [x] Plan B4: node to node through the Engine API (`etc/bench/node-bench.sh`), on a
      10,000-account synthetic devnet chain. Mainnet-state import waits for SYNC_PLAN M2/M3.
- [x] Plan B5: BENCHMARKS.md and the README Benchmarks section rewritten from B1-B4.
- [ ] Rerun on a dedicated server (frequency control, PMU, `perf stat` instructions and
      cycles per block); this round ran on a 4-vCPU cloud VM.

## Decisions

- **Which base/base executor.** `base-proof-executor::StatelessL2Builder`. It is base/base's
  only block executor that runs over a witness instead of a full state database, so it is
  the only one that can execute the archive's pre-state. reth's node path (MDBX, parallel
  sparse-trie state root) needs a full Base state database and is out of scope. The
  benchmark doc says this plainly.
- **Same input file.** The Rust harness parses the needlefish archive (v1 and v2 frames)
  instead of re-fetching, so both sides execute byte-identical transactions over an
  identical witness. The parent header (base/base needs the full header) is the one extra
  input. It comes from public `eth_getBlockByNumber` and is checked against the archive's
  parent hash and state root.
- **Harness outside the build.** The Rust code lives in a base/base checkout under
  `.cache/` (or any `BENCH_RUST_DIR`). The repository carries only a patch file, applied by
  `reproduce.sh`. The repository build stays Zig-only with zero dependencies. The patch is
  the smallest change that makes the harness reproducible.
- **Patch scope (41 lines in base/base crates).** An opaque-branch collapse hook, a
  BLOCKHASH table hook, and phase timing plus a `trie_db()` accessor. None changes execution
  or root results, and every block is verified against its canonical header.
- **Witness-absent collapse siblings.** `TrieDB` collapses a branch on every delete. A later
  insert in the same block can re-expand it, so the sibling is needed only by reference.
  The harness treats such siblings as opaque branches. A wrong guess would change the state
  root and fail the block; none failed.
- **Post-state storage nodes.** `TrieDB` reopens storage tries by root hash each block. The
  harness feeds back the nodes `TrieDB` computed, between blocks and outside the timed
  region. This favors base/base, and the doc says so.
- **Phases.** Execution covers block start to the last transaction (system calls, sender
  recovery, transactions). The whole block runs through the resealed header hash. Cold is
  run 0 in a fresh process; warm runs reuse the decoded archive and start from fresh state.
- **Release profile.** Superseded by the plan's build matrix: base/base `release` and
  `maxperf`, each with and without `-C target-cpu=native`; needlefish ReleaseFast and
  ReleaseSafe, each native and `-Dcpu=baseline`. Headline pair: needlefish ReleaseSafe native
  vs base/base maxperf native.
- **Crypto backends (2026-11-06, plan B1).** The original harness built base/base's proof
  executor alone, which compiles pure-Rust k256 sender recovery and no `secp256k1`, `blst`,
  `c-kzg` precompile backends; the old doc wrongly said it used libsecp256k1. The harness
  now enables the backends `base-reth-node` builds with (alloy-consensus `secp256k1`; revm
  `secp256k1`, `blst`, `c-kzg`, `p256-aws-lc-rs`). This favors base/base and matches what a
  Base node runs.
- **Thread counts.** Headline configurations are single-threaded on both sides
  (`--recovery-threads 0`). needlefish's replay hashes the state root on one thread (only
  sender recovery has workers), so 0 recovery threads is fully single-threaded. The
  threaded configuration is reported next to it; base/base's harness has no threaded mode
  (recovery is inside `build_block`, which the harness cannot parallelize without
  changing the executor).
- **Cold and warm.** Every run is a fresh process. Cold drops the page cache first; warm
  does not; the old in-process "warm" (second pass) is reported as `repeat`. Archive loading
  is untimed, so cold mostly measures code page faults and first-touch costs.
- **EVM-only pre-state.** needlefish records the first value of every key the window reads
  during one normal replay and writes it as `NFPS`; both EVM-only harnesses load the same
  file. Every block must still match its gas used and receipts root. revm's bytecode is
  analyzed when the `CacheDB` is filled (untimed); needlefish analyzes at execution time.
- **Machine.** Runs on a 4-vCPU cloud VM (KVM, no PMU, no cpufreq control) rather than
  the dedicated server the plan asks for: no instruction or cycle counts, and frequency is
  whatever the host gives. Recorded in the doc; the plan's "measured on the isolated
  server" item stays open.
- **Machine state.** No other builds ran. Endpoint security agents could not be stopped
  (about 3 cores of load), which is recorded in the doc.
- **1,000-block window (2026-11-07).** Blocks 54048836..54049835. It first failed at
  54049206 (B-20 `permit` 100 gas short) and 54049777 (an account the B-20 factory created
  was not persisted); both were needlefish bugs, fixed in `execution/evm` with regression
  tests, and the window now reproduces every header. The trie pool reserved 65,536 nodes
  per block, more than an 8 GiB machine can map for 1,000 blocks; blocks past the first
  128 get 8,192. It runs the headline configurations only (10 rounds): base/base's state
  root grows with the window, so one base/base pass takes minutes.
- **Isolation.** `systemctl set-property AllowedCPUs=` (empty) does not widen a cpuset
  again, and the first runs confined only `system.slice`, `user.slice` and `init.scope`, not
  the sandbox agent's `amp.slice`. `isolate` now confines every top-level unit but
  `bench.slice` and restores the full CPU range on exit. The fixture, 100-block and EVM-only
  results predate this; BENCHMARKS.md says so.
- **B4 limits.** needlefish's node has fixed devnet-sized limits (65,536 state-trie
  accounts, 16,384 changed accounts per block, genesis included) and no flag to raise them,
  so the prefill is 10,000 accounts, not the plan's 10M and 100M. Import timing is curl's
  `time_total` per `newPayload`; disk is the allocated size (MDBX's map file is sparse).
- **Profiles.** needlefish's replayer re-adds every changed contract's code to the code
  store after each block, hashing up to 24 KB just to find it present (about 21% of replay
  time). Left in place so the published numbers describe the measured code; checking the
  account's code hash first would remove it.
- **README.** Removed Status, Performance, Releases, Testing, and Development. Added
  Benchmarks and a short Contributing pointer. `just release` now downloads Zig 0.17.1 into
  `.cache/zig` when it is not on `PATH`, so installation is clone plus `just release`.

## Log

- 2026-11-06: base/base harness verifies all 110 blocks (100-block window + fixture) in
  11 runs each. Results, methodology, reproduce script, and README pushed.
- 2026-11-07: second round on a 4-vCPU cloud VM: build matrix with 30 interleaved
  fresh-process rounds (fixture, 100-block window, EVM only), 1,000-block window (headline
  configurations), phase attribution and flame graphs, and the first node-to-node result.
  The 1,000-block window found two B-20 precompile bugs (fixed). BENCHMARKS.md and the
  README rewritten.
