# Lane: dst-fuzz

Owns `src/testing/*`, `etc/ci/` (never `.github/workflows`: push is rejected), benchmark harness, perf work. Makes the whole system
provably robust.

## Backlog
- [ ] Simulator harness (`zig build sim -- seed`): cluster of simulated nodes (L1, sequencer, batcher, verifiers) on `SimIo`; fault injection (latency, drop, reorder, duplicate, partition, crash/restart, disk faults, clock skew); invariant checkers (verifier safe head == sequencer chain, no divergent state roots, monotonic heads, liveness after faults heal). Grows as components land — start with what exists, add components as lanes ship.
- [ ] Swarm testing: randomized config per seed; `just sim-swarm N`; failing seeds minimized and added as regression tests.
- [ ] Fuzz infrastructure: shared helpers over `std.testing.fuzz` + seeded deterministic fuzz runs in `zig build test`; a `just fuzz` corpus dir under `.cache/`.
- [ ] Audit every lane for missing fuzz targets and add them (rlp, tx decode, json, http, frames, batches, trie, evm).
- [ ] CI: Linux + macOS, ReleaseSafe test run, simulator seeds, nightly-style longer swarm on push to main.
- [ ] Bench harness in `bench_main.zig` (filterable, ns/op, throughput) and perf tracking file `docs/PERF.md`.
- [ ] Tidy extensions: function length ≤ 70 lines check, assert density report.

## Decisions

## Log
