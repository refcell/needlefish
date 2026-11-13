# Benchmark plan: node to node on Base mainnet state

The speedups in the README and [BENCHMARKS.md](BENCHMARKS.md) are accurate measurements of
the wrong comparison. This plan replaces them with one that answers the question people ask:
is a needlefish node faster than a base/base node at importing real Base mainnet blocks?
It is written for an agent working alone. Do the phases in order and push after each one, so
a partial run still leaves the docs more accurate than before.

## What is wrong with the current numbers

The headline compares needlefish's replay executor with base/base's `base-proof-executor`
(`StatelessL2Builder`). That executor exists to check fault proofs over a few blocks from a
witness. No Base node runs it to follow the chain.

| Claim (README, BENCHMARKS.md) | What it actually measures | Why it misleads |
| --- | --- | --- |
| "Up to 24x faster ... once state roots are included" (24.62x, 1,000 blocks) | The proof executor's `TrieDB` re-hashes every trie node it holds on every block. Its root time grows from 39 to 253 ms/block across the window; needlefish stays near 2.5 ms/block. | The gap is a property of a proof tool, not of base/base's node, and it grows with the window length (2.6x at 10 blocks, 7.6x at 100, 24.6x at 1,000). reth computes roots incrementally with a sparse trie. |
| 7.60x with roots, 100 blocks | Same effect, shorter window | Same |
| 1.6-1.9x on execution | Transactions over the witness's state reads | Mostly state access from a witness, which a node does not do. With state taken out, revm's interpreter is about 15% faster than needlefish's (0.85x). |
| `engine_newPayload` 4.00 ms vs `base-reth-node` 8.03 ms | A real node-to-node comparison | A 10,000-account synthetic devnet chain. Mainnet state is far larger (Base Sepolia alone is 37.7M accounts and 3.7B slots), so cache and disk behavior are untested. |
| Last week's 2.7x / 5.8x (one laptop run) | Same proof executor, plus the biases in [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) | Superseded |

What blocked a fair comparison before is gone: needlefish now imports Base's public reth
snapshot into a disk-mode database and follows mainnet with every block checked
([SYNC_PROGRESS.md](SYNC_PROGRESS.md), [MAINNET.md](MAINNET.md)). base/base's node runs
on that same snapshot directly. Both can start from one verified block.

## Goal

Both nodes start at the same mainnet block S from Base's same public snapshot. Each one
imports the same N consecutive real mainnet blocks (S+1 .. S+N) through the Engine API
(`engine_newPayloadV4`, then `engine_forkchoiceUpdatedV3`), driven by the same client on the
same machine. Each block must be accepted as VALID with the canonical block hash, or the run
does not count. Report the time per block and its distribution, with confidence intervals.
The Engine API is the common interface because it is how a consensus node drives either
client at the tip.

## Rules

- Same input bytes: one payload file, exported once, replayed into both nodes.
- Verification outside the timed region: both nodes must return VALID for every block, and
  afterwards each node's head hash and state root must equal the canonical block S+N.
  A run with any other status does not count; report it as a failure, not a number.
- One node at a time on the machine, with nothing else writing to the same disk. Earlier
  sync work showed that one heavy writer slows every fsync on the filesystem
  (SYNC_PROGRESS.md, Nov 12 18:10 ET), and that skews disk-bound blocks badly.
- Report each node's real default configuration, and every flag changed from it. Do not tune
  one side only. Where a setting clearly changes the answer (durability cadence, cache size),
  measure both at matching settings and also each at its own defaults.
- Interleave runs (A, B, A, B, ...) from a fresh copy of the datadir at S each time, so drift
  does not favor whichever runs first. 10+ runs per configuration; bootstrap 95% CIs with
  `etc/bench/stats.zig`.
- Publish what you find, including results where base/base wins. The README states only what
  this plan measured.

## Phase N0: correct the docs now

Do this first, in its own commit, before any new measurement:

1. README Highlights: replace "Fast. Up to 24x faster than base/base's executor..." with a
   claim the current data supports. Example: "Fast at the tip: executes Base mainnet's
   200 ms blocks with a median lag of about 22 ms", citing the Status section. Point at
   BENCHMARKS.md for executor numbers and say that a node-to-node mainnet comparison is in
   progress.
2. README Benchmarks section: title the table "needlefish's executor vs base/base's proof
   executor". Above it, state in one sentence that this tool is not base/base's node, and
   that the roots column grows with window length for that reason. Keep the numbers.
3. BENCHMARKS.md Summary: add the same note at the top, and link this plan.

## Phase N1: needlefish executes Engine API payloads

Today `base el-run` takes blocks only from devp2p and gossip. Its Engine API judges payloads
against blocks it has already executed and never executes one (`bin/base/el_engine.zig`
header). A fair comparison needs needlefish to import a block given to it through
`engine_newPayload`, as base/base does. The same change also lets `base consensus` drive
needlefish as a real execution client.

- Add an engine block source to el-run, for example a flag `--engine.execute`. With it,
  el-run does not dial peers or listen to gossip. When a `newPayload` arrives for head+1 and
  links to the head, el-run executes it on the runner's normal path, with every check
  (transactions root, gas, bloom, receipts root, state root, resealed hash). It answers
  VALID or INVALID with `latestValidHash`, and above head+1 it answers SYNCING. Payloads at or
  below the head keep today's judge behavior.
- Respond only after the block is committed to the in-memory state, as reth does. Durability
  stays on el-run's normal flush cadence; record the cadence in the results.
- Tests: a payload for head+1 executes and advances the head; a payload with a wrong state
  root answers INVALID and leaves the head alone; a gap answers SYNCING; a seeded fuzz over
  payload order. Run it on the Base Sepolia node first, as every el-run change does.

## Phase N2: the input

1. Pick S as the block of Base's newest public mainnet reth snapshot. base/base opens the
   extracted snapshot directly. needlefish imports it with `base snapshot-import --out`,
   which recomputes the state root. Both must report head S with the snapshot header's hash.
2. Export N = 10,000 consecutive blocks after S as Engine API payloads with
   `etc/bench/node-import.sh export` against a public RPC, and keep the file. Check that every
   payload has the fields that mainnet's current fork needs (withdrawals root, parent beacon
   block root, execution requests). Replaying the file into either node must give VALID for
   every block before any timing starts.
3. Reset between runs with reflink copies of each datadir at S (`cp --reflink=always` on
   btrfs or XFS), so a run costs seconds and no re-import.

## Phase N3: the runs

Configurations:

| Label | Node | Build | Settings |
| --- | --- | --- | --- |
| `nf-safe` | needlefish `el-run --engine.execute` | `ReleaseSafe`, native CPU (what the live nodes run) | defaults |
| `nf-fast` | same | `ReleaseFast`, native CPU (what `just release` ships) | defaults |
| `reth-maxperf` | `base-reth-node`, discovery off, no peers | `--profile maxperf`, native CPU | defaults (engine tree, state root task) |
| `reth-release` | same | `--profile release`, generic (what its Docker image ships) | defaults |
| `*-matched` | both | best build of each | same cache budget in GiB and comparable persistence cadence, flags recorded |

Workloads:

- **Catch-up throughput**: replay all N blocks back to back; newPayload then FCU per block.
  Report wall time for N blocks, Mgas/s, and newPayload latency p50, p90, p99 and max.
- **Tip pace**: replay the same blocks at their real 200 ms cadence. Report newPayload
  latency p50, p90, p99 and the share over 200 ms. This is the number that matters for
  following the chain.
- **Cold start**: the first 500 blocks after a restart with the page cache dropped.

Also record peak RSS, datadir size at S and at S+N, and bytes written per block for each node.

## Phase N4: attribution

For each side, split newPayload time into execution, state root, and commit or persistence
(needlefish already logs `exec split` per block; reth's engine tree reports timing metrics).
Add flame graphs with `etc/bench/profile.sh`. Explain every gap over 1.2x in either direction
in one sentence.

## Phase N5: publish

- BENCHMARKS.md: add a "Node to node on mainnet state" section at the top with the
  environment, the configurations, the table, and the CIs. Move the executor comparison below
  it and label it as a comparison with the proof executor.
- README: the Benchmarks section leads with the node-to-node table. The Highlights claim
  becomes whatever that table supports, including "comparable" or "slower" if that is the
  result.
- `etc/bench/node-mainnet.sh` reproduces every number from a machine with the two datadirs
  at S and the payload file.

## Machine

One Linux host with an NVMe drive that has room for both datadirs at S plus reflink working
space: about 1.14 TB for the extracted reth snapshot and about 2 TB for the needlefish
database ([MAINNET.md](MAINNET.md)), then growth over N blocks. The host also needs 64+ GiB
of RAM, CPU frequency control, and no other disk-heavy work during runs. A 4-vCPU cloud VM
is not enough to hold mainnet state in cache, so report the hardware with the results.
