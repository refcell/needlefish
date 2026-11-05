# Lane: dst-fuzz

Owns `src/testing/*`, `etc/ci/` (never `.github/workflows`: push is rejected), benchmark harness, perf work. Makes the whole system
provably robust.

## Backlog
- [ ] Simulator harness (`zig build sim -- seed`): cluster of simulated nodes (L1, sequencer, batcher, verifiers) on `SimIo`; fault injection (latency, drop, reorder, duplicate, partition, crash/restart, disk faults, clock skew); invariant checkers (verifier safe head == sequencer chain, no divergent state roots, monotonic heads, liveness after faults heal). Grows as components land — start with what exists, add components as lanes ship.
- [x] Swarm testing: randomized config per seed; `just sim-swarm N`; failing seeds minimized and added as regression tests.
- [x] Fuzz infrastructure: shared helpers over `std.testing.fuzz` + seeded deterministic fuzz runs in `zig build test`; a `just fuzz` corpus dir under `.cache/`.
- [ ] Audit every lane for missing fuzz targets and add them (rlp, tx decode, json, http, frames, batches, trie, evm).
- [x] CI: Linux + macOS, ReleaseSafe test run, simulator seeds, nightly-style longer swarm on push to main.
- [x] Bench harness in `bench_main.zig` (filterable, ns/op, throughput) and perf tracking file `docs/PERF.md`.
- [x] Tidy extensions: function length ≤ 70 lines check, assert density report.

## Notes for other lanes (from simulator findings)
- consensus (derivation): a durable checkpoint of (safe head, L1 cursor) must also name the
  hash of the L1 block it reflects, and per-L1-block records written later can be newer than
  the checkpoint after a lost write. Restore both from the checkpoint on restart.
- After restart, a rewind on an L1 reorg can land on a record whose safe head is above the
  restored unsafe head; take those blocks back from disk instead of clamping (clamping
  leaves a gap that derivation never fills).

## Decisions
- Cross-lane fuzz targets live in `src/testing/fuzz_targets.zig` (our lane) so we never
  edit other lanes' files to add them. They test properties (canonical round trip,
  model equivalence, tamper resistance), not just "does not crash".
- Swarm runs in-process (`simulator swarm FIRST COUNT`), ~1 ms/seed in ReleaseSafe.
  Failing seeds: `just sim-minimize SEED`, fix, then paste the printed entry into
  `sim/swarm.zig:regressions` (seed + full config, so it survives `Config.random` changes).
- `tidy` enforces fn length ≤ 70 via `etc/scripts/fn-length.awk` (relies on zig fmt
  indentation). Generic type constructors (`fn X(...) type {`) are exempt: they are struct
  definitions. Assert density is a report only (`just assert-density`), never a gate.
- Simulator v1 runs *model* nodes (`src/testing/sim/nodes.zig`) that follow the Base data
  flow (L1, sequencer gossip, batcher → L1, verifier derivation). Real components replace
  them as lanes land behind `utilities.io`; network, fault injector, and checkers stay.
- Fixed 10 ms simulator step; three PRNG streams (network, nodes, faults) derived from the
  seed so fault schedule changes do not perturb node randomness.
- Safety is checked on heads only: chains are hash-linked, so a head match implies the
  prefix matches.
- Fuzz bodies take `*std.testing.Smith`; `testing.fuzz.run` drives them both coverage-guided
  and from seeded `Prng` bytes on every `zig build test` (failure prints seed + iteration).

## Log
- 2026-11-05: simulator v1 (sim/network, model nodes, cluster, swarm config, safety +
  liveness checks; mutation-tested), `testing.fuzz` helpers (Smith seeded + coverage).
- 2026-11-05: tidy fn-length gate, `just assert-density`, build.zig split into helpers.
- 2026-11-05: swarm runner + greedy minimizer + regression seed list; batcher model
  interval fixed (minimizer showed fault-free liveness relied on resubmits); CI swarm/fuzz jobs.
- 2026-11-05: bench harness (calibrated, best-of-5, MB/s) over lane case tables; docs/PERF.md baseline.
- 2026-11-05: fuzz audit pass 1: tx canonical round trip (+network form), channel
  reassembly vs model, trie proof tamper + garbage. Uncovered list: re-audit as lanes land.
- 2026-11-05: sim clock skew (per-node offset, re-drawn on restart = clock jumps; network
  stays on global time); minimizer reduction for skew.
- 2026-11-05: sim L1 reorgs (hash-linked L1, follower rewind, per-L1-block safe/confirmed
  records). Swarm found 3 model bugs, all durable-state atomicity: checkpoint without its
  L1 hash; rewind above post-restart unsafe head; clamp leaving a gap. 10k seeds green.
