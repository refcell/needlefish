# Lane: dst-fuzz

Owns `src/testing/*`, `etc/ci/` (never `.github/workflows`: push is rejected), benchmark harness, perf work. Makes the whole system
provably robust.

## Backlog
- [ ] Simulator harness (`zig build sim -- seed`): cluster of simulated nodes (L1, sequencer, batcher, verifiers) on `SimIo`; fault injection (latency, drop, reorder, duplicate, partition, crash/restart, disk faults, clock skew); invariant checkers (verifier safe head == sequencer chain, no divergent state roots, monotonic heads, liveness after faults heal). Grows as components land — start with what exists, add components as lanes ship.
- [x] Swarm testing: randomized config per seed; `just sim-swarm N`; failing seeds minimized and added as regression tests.
- [x] Fuzz infrastructure: shared helpers over `std.testing.fuzz` + seeded deterministic fuzz runs in `zig build test`; a `just fuzz` corpus dir under `.cache/`.
- [x] Sim: real L1 data path. Batcher model encodes through `batcher/channel` Manager
  (singular batches, zlib, frame tx data); verifiers and batcher decode with
  `consensus/protocol` (frames, Channel, decompress, BatchReader, SingleBatch).
- [x] Sim: verifiers derive through the real `derive` retrieval + frame queue over an
  L1 chain provider; attacker inbox-spam fault; negative test with the sender check off.
- [x] Sim: multi-frame channels spread over L1 blocks via the derive lane's channel bank
  (timeouts, frame loss, reorged frames) once `derive` lands it.
- [ ] Sim: swap model nodes for real components behind `utilities.io` SimIo as lanes land.
  - [x] Batcher: the real `batcher/service` (txmgr, channel manager, L2 source) runs
    against model state through JSON-RPC transports (`sim/real_batcher.zig`).
  - [x] Verifier derivation: the real consensus `Driver` (pipeline, engine task queue,
    startup discovery) as the first verifier's consensus client (`sim/real_verifier.zig`).
  - [ ] Sequencer: the real driver in sequencer mode producing the L2 chain.
- [x] Sim: drop the `real_verifier_fragile` fault gate once the derive lane fixes the
  reset loop at safe-head origin `genesis.l1 + 1` (see notes).
- [x] Sim: L1 transaction-loss faults: mempool evictions and reorgs that lose orphaned txs.
- [ ] Sim: enable both tx-loss faults for the real batcher (with crashes) once txmgr recovers
  nonce gaps (see notes); today they are drawn only where txmgr can survive them.
- [x] Fix `fuzz.zig` seeded Smith: narrow ints/bools/ranges/eos nearly always return the
  minimum (8 random bytes per value, out-of-range falls back to min); re-check targets.
- [x] Trim `fuzz_targets_p2p` disc-service target (2.7 s Debug; budget is ~1 s per test).
- [x] Sim: byzantine batcher modes beyond corruption (out-of-order and duplicate channels,
  oversize frames) once the channel bank exists.
- [ ] Fuzz the proof lane's decoders (preimage: done end-to-end; MPT and boot info
  pending) (preimage oracle wire format, hint parsing, MPT node
  decoding, boot info) as `src/proof` lands: round trips plus arbitrary-input robustness.
- [ ] Audit every lane for missing fuzz targets and add them (rlp, tx decode, json, http, frames, batches, trie, evm).
- [x] CI: Linux + macOS, ReleaseSafe test run, simulator seeds, nightly-style longer swarm on push to main.
- [x] Bench harness in `bench_main.zig` (filterable, ns/op, throughput) and perf tracking file `docs/PERF.md`.
- [x] Tidy extensions: function length ≤ 70 lines check, assert density report.

## Notes for other lanes (from simulator findings)
- derive (batch queue): a pipeline reset whose L2 safe head has L1 origin `genesis.l1 + 1`
  walks back to the L2 genesis (origin `genesis.l1`); the batch queue then holds
  `[genesis.l1, genesis.l1 + 1]` (the origin change is never "behind"), so
  `derive_next_batch` fails with `L1OriginMismatch` (reset) forever. base/base
  `batch_queue.rs` has the same edge. Repro: sim seed 48 with the gate removed; or a
  driver reset with safe head origin 1 and `genesis.l1.number = 0`.
- batcher (txmgr): a confirmed tx that a reorg orphans and L1 then drops leaves a nonce gap
  that nothing fills: `next_nonce` is cached forever and freed slots are never re-sent, so
  every later tx waits on L1 indefinitely. base/base resets its nonce cache on send timeout
  and requeues the frames; the service's safe-head stall reset should also reset txmgr
  (refetch the `latest` nonce, drop slots above it, requeue their frames).
- batcher (txmgr): a fresh txmgr (startup, restart) takes its first nonce from the
  `pending` tag, adopting mempool txs it does not track. If L1 then evicts one, nothing
  re-sends it and every later nonce waits forever. base/base's batcher uses the default
  `latest` tag (only infra jobs opt into pending); use `latest` and let the same-nonce
  resubmission replace what is pending.
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

- Sim L1 data path uses one frame per channel so decoding stays stateless per L1 tx and
  the follower keeps owning reorg rewinds; multi-frame waits for the real channel bank.
  L1 carries indices into an append-only tx pool (no rewrite, so stale messages stay
  valid). Cost: ~6.5 ms/seed ReleaseSafe (was 1-4 ms).

- Real batcher in the sim: answered synchronously from model state via `rpc.Transport`
  (no sockets), stepped every 2 s of local time; single-frame channels (input cap 1900
  bytes) because sim derivation is stateless per L1 tx. The model batcher stays as an L1
  observer for the confirmation checks. L1 enforces account nonces for its txs.
- L1 reorgs mine a same-height replacement branch at once and re-inject every orphaned tx
  (geth behaviour). The old model let L1 shrink and lose txs when the mempool was full,
  which produced nonce gaps no real L1 node causes; tx loss becomes its own fault class.

- Multi-frame channels: derivation replays the channel-timeout window (6 L1 blocks) from
  a fresh derive-lane ChannelBank at every L1 block, over durable copies of processed
  blocks. Equivalent to a persistent bank (older channels have timed out) except that a
  frame resubmitted after its channel's first frame left the window can complete a
  channel the real bank drops; accepted for now, since reorgs and restarts then need no
  bank snapshots. Granite is on (ready-channel selection). L1 includes up to 8 batcher
  txs per block, with a congestion knob (2..8) so frames spill across blocks; without it
  the window mutant (derive the newest block only) survived the swarm.

- Push loop: main lands ~1 commit/min while a full test run takes 2-3 min under load,
  so strict re-test-on-every-reject never wins. After a green full run, if upstream
  commits since the tested base touch none of our files nor build.zig/src/base.zig,
  rebase and push without another run (each upstream commit passed its author's run).

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
- 2026-11-05: pinned regression configs (`simulator regression SEED`), byzantine negative
  test (equivocating sequencer must trip checkers), coverage-guided fuzz over cluster configs.
- 2026-11-05: bls12-381 g1/g2 canonical-encoding fuzz; `just test-times` (per-test wall
  time); flagged 73 s p2p test to coordinator.
- 2026-11-05: sim runs real batcher/protocol codecs on the L1 data path; checker for
  undecodable batches; corrupt-batcher negative test (mutation-checked).
- 2026-11-05: fuzz target for the comptime RLP codec (canonical re-encoding of anything
  accepted, value round trip, mutated and raw input).
- 2026-11-05: asymmetric (one-way) link cuts in the sim network; half of partition
  faults are now random directed cuts. 5000 seeds green.
- 2026-11-05: sim verifiers derive via derive-lane Retrieval/FrameQueue (calldata source,
  sender filter); inbox-spam fault (swarm level); sender-check negative test.
- 2026-11-05: the real batcher service runs in the sim (`real_batcher=true`, half of
  swarm seeds); L1 enforces nonces and reorgs re-mine at once. 1000 seeds green. Found:
  txmgr cannot recover a lost nonce (noted for the batcher lane).
- 2026-11-05: seeded fuzz driver now emits skewed-small little-endian word inputs for half
  the iterations, so Smith values, bools, `eos` loops, and slices vary in normal
  `zig build test` runs (they were almost always the minimum). Full suite green.
- 2026-11-05: L1 tx-loss faults (mempool evictions, reorgs that lose orphaned txs) in the
  swarm; 3000 seeds green. Found: a fresh txmgr adopts `pending` nonces and cannot
  recover an evicted one (noted for the batcher lane).
- 2026-11-05: disc-service fuzz target trimmed to 32 seeded iterations (was 2.7 s).
- 2026-11-05: fuzz targets for tx field decoders (TxKind, HashList, AccessList,
  AuthorizationList: canonical re-encode, iterators walk the counted items) and legacy
  `v` decoding (inverts EIP-155 encoding). Seeded words now 3/4 of inputs with a wider
  small-value spread. Note: `-Dtest-filter` takes one substring; `a|b` matches nothing.
- 2026-11-05: model-based fuzz of the batcher channel manager (`fuzz_targets_batcher.zig`):
  random configs (zlib/brotli, frame sizes, target frames) under interleaved adds,
  reorged parents, L1 heads, closes, drains, and resets; every channel must decode
  to exactly the next accepted blocks, and a final drain must deliver them all.
  Mutation-checked; 200 ms Debug.
- 2026-11-05: multi-frame channels in the sim (frame size 256..2047 per seed, both
  batchers) reassembled through the derive lane's ChannelBank over a replayed timeout
  window; L1 congestion knob. 5000 seeds green; window mutant caught (7/300 seeds).
- 2026-11-05: model-based fuzz targets for the derive channel stages
  (`fuzz_targets_derive.zig`): ChannelBank (arrival order, pre/post-Granite selection,
  timeouts, size accounting, queue) and the Holocene ChannelAssembler against spec
  models; 4/4 model mutants caught. No derive bugs found.
- 2026-11-05: byzantine batcher fault (`byzantine_per_minute`): the batcher key posts
  replayed honest ranges as fresh channels with shuffled and duplicated frames,
  truncated channels, garbage, and oversize frames. The undecodable-batch check is
  waived for such seeds (head checks remain). 5000 seeds green.
- 2026-11-05: differential Engine API JSON fuzz (`fuzz_targets_engine.zig`): payloads
  V1-V4 both directions, payload attributes, payload status and forkchoice-updated
  between the consensus client and execution server codecs; 3/3 wire mutants caught.
- 2026-11-05: network fuzz targets (`fuzz_targets_net.zig`): HTTP parser (structured,
  chunking-invariant, limits), WebSocket frames, flashblocks. Found: `FlashblockId.parse`
  accepts `1_0` and rejects `+61`, unlike base/base `u64::from_str` (reported; skipped).
  Residual: chunked bodies over the limit are rejected only once complete.
- 2026-11-05: HTTP chunked weak spots closed (small fix in the io-net parser, reported):
  a malformed or over-long chunk-size line now fails as soon as it arrives, and declared
  chunk sizes over `body_size_max` fail at the crossing size line instead of after the
  whole body. Pinned by fuzz properties; both fail on the old parser.
- 2026-11-05: the real consensus driver runs as a verifier in the sim (`real_verifier`,
  drawn last in `Config.random`, half of seeds). L1 provider over the model L1, a
  deterministic engine whose block hash is the model sequencer's hash for the same
  parent and payload tx, startup discovery on restarts (engine chain durable). The model
  sequencer now picks real L1 origins (final L1 blocks, one epoch step per block) and
  the batches carry them; `codec.rollup` is a full config (genesis, block time 2, drift
  1800, window 3600 > any run, so deposit-only blocks never appear). Invariants: safe
  head is a sequencer block, every derived block has the sequencer's payload tx and L1
  origin, safe head monotonic except restarts/L1 reorgs, liveness to the confirmed head.
  2000 seeds green (ReleaseSafe); mutants caught: dropped user tx (104/200 seeds, all
  real-verifier ones), stored tx differs from the hashed one (per-block check).
- 2026-11-05: beacon API decoder fuzz (`fuzz_targets_sources.zig`): integers (decimal and
  QUANTITY among noise fields), blobs and sidecars (any field order, extra and missing
  fields), arbitrary bytes. Sidecar field-swap mutant caught.
- 2026-11-05: derive lane fixed the reset livelock (db0b967); dropped the
  `real_verifier_fragile` gate. Seed 48 and 2000 swarm seeds green.
- 2026-11-05: end-to-end preimage protocol fuzz (`fuzz_targets_proof.zig`): client and
  host over hint and oracle duplexes; hinted gets return keccak-verified values,
  unhinted gets fail framed, bad hints are acknowledged. The proof lane already fuzzes
  key, hint text/frames, pipe, and oracle requests per module. 2/2 mutants caught.
- 2026-11-05: model-based JSON-RPC router fuzz (`fuzz_targets_rpc.zig`): singles and
  batches of calls, notifications, null/string ids, unknown methods, bad params,
  failing and overflowing handlers, malformed objects; responses checked in order
  against a spec model; arbitrary bodies give empty or valid JSON. 2/2 mutants caught.
