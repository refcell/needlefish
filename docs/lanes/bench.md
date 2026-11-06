# Lane: bench

Owns `docs/BENCHMARKS.md`, `etc/bench/`, `bin/base/replay_bench.zig` (`base replay bench`),
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
- **Release profile.** base/base's default `release` profile, not `maxperf`, as requested.
- **Machine state.** No other builds ran. Endpoint security agents could not be stopped
  (about 3 cores of load), which is recorded in the doc.
- **README.** Removed Status, Performance, Releases, Testing, and Development. Added
  Benchmarks and a short Contributing pointer. `just release` now downloads Zig 0.17.1 into
  `.cache/zig` when it is not on `PATH`, so installation is clone plus `just release`.

## Log

- 2026-11-06: base/base harness verifies all 110 blocks (100-block window + fixture) in
  11 runs each. Results, methodology, reproduce script, and README pushed.
