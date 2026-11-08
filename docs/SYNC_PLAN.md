# Syncing Base mainnet: implementation plan

This plan takes needlefish from "re-executes recent Base mainnet blocks offline" to "a node
that syncs Base mainnet and stays at the tip", and defines how to prove it is syncing
correctly. It is written for agents and operators working on a dedicated Linux server.

Do every milestone on Base Sepolia (chain 84532) first, then on Base mainnet (chain 8453).
Sepolia state is much smaller, so every failure is cheaper to find there.

## Definition of done

A needlefish node on mainnet is "syncing" when all of these hold for 7 consecutive days:

1. It starts from a verified state (snapshot or genesis) and executes every block after it
   locally. For every block the state root, receipts root, logs bloom, gas used and block
   hash it computes equal the canonical header. One mismatch fails the run.
2. Its unsafe head is within 2 s of the chain tip, from gossip (median), and its safe and
   finalized heads track L1 derivation the way a reference node's do (see Verification).
3. Random state samples (`eth_getProof`, `eth_getBalance`, `eth_getStorageAt`,
   `eth_getCode`) at the head match an independent reference node.
4. It survives `kill -9`, restarts, L1 reorgs and a hardfork activation without manual
   repair, and its disk use grows at a steady, predictable rate.

## Where we are

Verified on `main`:

- Execution is correct on real mainnet blocks. `just replay` fetches the latest blocks and
  the state they touch from public RPC and re-executes them offline. 100 consecutive
  mainnet blocks (1747 transactions) reproduce every header field (docs/REPLAY.md).
- Execution side (`src/execution`): EVM with Base precompiles and fee rules, OP/Base block
  executor (`node/executor_op.zig`), Engine API v2-v4 with OP extensions (`engine`), payload
  building, txpool, JSON-RPC (`rpc`), state trie and ordered tries (`trie`), and a crash-safe
  storage engine with an LSM forest over a checksummed block grid, using io_uring on Linux
  and kqueue on macOS (`db`, `db/storage`).
- Consensus side (`src/consensus`): L1 RPC and beacon blob clients (`sources`), the full
  derivation pipeline including span batches, Holocene rules and 200 ms blocks (`derive`),
  engine driver with EL-sync handshake (`engine`), sequencer, safe-head DB (`safedb`),
  discv5, libp2p (noise, yamux, multistream, identify, ping) and gossipsub written from
  scratch, with Base mainnet and Sepolia boot nodes (`p2p`).
- Chain parameters: Base mainnet and Sepolia upgrade schedules
  (`src/consensus/protocol/rollup_config.zig`, `UpgradeConfig.base_mainnet`).
- Tooling: `base basectl sync-status` and `doctor`, `base snapshotter`, metrics and health
  endpoints.

Gaps that block a real sync:

- **State at mainnet scale.** The storage engine is proven at about 1M accounts. Parts of
  state still live in RAM (codes, flat tables serialized at checkpoints). Mainnet state has
  billions of entries and needs multiple TB. See trie-db "Disk state" phases 1e to 6.
- **State bootstrap.** There is no way yet to obtain mainnet state at a recent block:
  no snapshot import, no snap sync, and genesis sync is impractical (below).
- **Catch-up sync.** No staged sync pipeline yet (docs/lanes/sync-perf.md backlog).
- **Mainnet interop.** Derivation and p2p have only run against the local devnet and
  public spec vectors, never against real Base mainnet peers and L1 data.
- **Execution-layer p2p.** An eth/68 client exists (`bin/base/el_source.zig`, `el-peers`,
  `el-run`): discv4 peer discovery and header and body download from one peer, parent-linked
  and checked against each header's transactions root. Multi-peer backfill, snap/1 and
  serving do not exist yet.

## Hardware and external services

The server:

- Linux with io_uring enabled (kernel 5.1+ works, a current LTS kernel is recommended; the
  io_uring tests run on 6.8), x86-64 or arm64.
- 16+ cores, 64 GB RAM minimum (128 GB recommended for the state and trie caches).
- 8 TB+ NVMe for mainnet (state, history, snapshot staging), ideally on its own disk.
  Do not use network storage. Check current public Base snapshot sizes before buying.
- A stable connection with inbound TCP/UDP for p2p.

Services the node needs:

- **L1 execution RPC** (Ethereum mainnet or Sepolia): blocks, receipts, logs. Run your own
  L1 node pair (execution and consensus client) on the same network if you can. Public
  endpoints rate-limit hard.
- **L1 beacon API** for blob sidecars. Beacon nodes keep blobs for about 18 days (4096
  epochs), so derivation can only start from an L1 origin inside that window unless you
  also run a blob archiver.
- **A reference Base node** (any reth/op-node style node you trust, or a public RPC) only for
  comparison during verification. needlefish never trusts it for execution results.
- Never commit endpoint URLs that carry API keys. Pass them by flag or environment at run
  time.

## Why not sync from genesis

Genesis sync re-executes about 53M blocks. That needs all historical block bodies (through
devp2p, which needlefish lacks, or millions of RPC calls) and months of execution on one
machine with on-disk state, and old blob data is no longer on L1 beacon nodes, so it cannot
be re-derived from L1 either. Production clients bootstrap Base from snapshots for the same
reasons. Genesis sync stays useful only as a correctness test on a private devnet chain.

## Milestones

Each milestone lists what to build, where it lives, what to read in base/base, and the
check that proves it works. Milestones 1, 2 and 5 can start in parallel.

### M1. Validating follower (`base follow`)

A stateless node that follows the live tip and re-executes every block, using the replay
engine with state fetched on demand. It is the correctness oracle for every later
milestone and the first live demo.

- Build: a loop over `src/infra/replay` (fetch, import, run) that keeps the chained sparse
  state between blocks, so it only fetches proofs for keys it has not seen yet. Block source:
  L2 RPC polling first, then consensus gossip from M6. Batch proof requests and back off on
  rate limits. Report lag behind the tip.
- Reference: base/base `etc/systems/src/replay_cli.rs`, `block_export.rs`.
- Check: runs for 24 h on Sepolia and on mainnet with zero mismatches; prints blocks
  verified, lag, Mgas/s; exits non-zero with the first differing account or slot on a
  mismatch.

### M2. Disk state at mainnet scale

Finish the trie-db "Disk state" plan (docs/lanes/trie-db.md, phases 1e to 6).

- Build: codes on disk (1e); `State` reads through the trees and checkpoints stop
  serializing flat tables (2b); trie branch store keyed by (owner, path) with a sparse state
  root over it (3); `eth_getProof` and `debug_executionWitness` over the store (4); history
  as an (owner, path, block) tree with pruning (5); scale proof (6).
- Check:
  - Synthetic state of 100M entries, then 1B entries: open time, point read p50/p99,
    block commit p50/p99 and the root computation all stay inside a 200 ms block budget.
  - Crash recovery under random `kill -9` (DST seeds plus real process kills on the server).
  - RSS stays bounded and does not grow with state size.

### M3. State bootstrap from a snapshot

Get verified mainnet state at a recent block into the needlefish database.

- Option A (first): import a public Base node snapshot. Base publishes reth snapshots, and
  reth stores state in MDBX. Build a read-only MDBX reader plus decoders for the reth
  tables needlefish needs (plain account and storage state, bytecodes, headers, and canonical
  hashes for the last 256 blocks), stream them into the needlefish store, recompute the full
  state root, and require it to equal the snapshot block's header `stateRoot`.
- Option B (later): snap sync from peers. Requires devp2p (M8). Most work, no trusted file.
- Option C (test only): build a needlefish datadir snapshot from a Sepolia or devnet sync
  and restore it with `base snapshotter` (`src/infra/snapshotter`). This exercises the
  restore path without third-party formats.
- Reference: base/base `crates/infra/snapshotter` (`tip.rs`, `progress.rs`),
  `crates/execution/node/src/storage.rs`; the public reth database table definitions.
- Check: imported state root equals the header at the snapshot block. Spot-check 10,000
  random accounts and storage slots against the reference node at that block
  (`base state-check --db <path>`: accounts and slots read through the trie and from the flat
  records against `eth_getProof`, codes against `eth_getCode`, inside the endpoint's proof
  window).

### M4. Catch-up sync from the snapshot block to the tip

The staged pipeline from docs/lanes/sync-perf.md.

- Block source (decided 2026-11-07): catch-up blocks come from the execution-layer p2p
  network only (eth/68, multi-peer backfill owned by the p2p lane), never from RPC. The first
  block must name the verified snapshot head's hash as its parent and every later block its
  predecessor's; transactions are checked against each header's transactions root, and
  execution checks every other header field. RPC block fetching (`base import-run`) stays a
  short debugging tool, not the bridge to the tip.
- Build: staged driver with per-stage checkpoints, unwind on reorg and crash resume
  (`src/execution/sync`); headers and bodies stages from that devp2p block source;
  sender recovery on a worker pool; execution in batches with one commit per N blocks;
  Merkle stage that checks the state root at each batch end. Wire EL sync into the node:
  forkchoice to an unknown head answers `SYNCING`, runs the pipeline, then `VALID`.
- Reference: base/base `crates/consensus/engine/src/sync`, `crates/consensus/service`,
  `crates/execution/node`; the public reth stage order.
- Check: from the M3 snapshot block, reaches the tip and hands over to live following with
  every batch root equal to the header root. Sustained import throughput is well above the
  chain's gas rate (target 5x or more), so the node catches up after any downtime.

### M5. Consensus on mainnet (safe and finalized heads)

Run `base consensus` (verifier mode) against real L1 with the mainnet rollup config.

- Build: load the Base mainnet and Sepolia rollup configs (public superchain registry
  values: genesis L1 and L2 blocks, batch inbox, batcher address, system config, deposit
  contract, L1 system config contract) and check them against the hardcoded upgrade
  schedule. Start derivation from the L1 origin of the snapshot head (inside the blob
  window). Track system config changes from L1 logs.
- Reference: base/base `crates/consensus/{derive,engine,service}`, the OP Stack derivation
  spec.
- Check: for every safe L2 block needlefish derives, its hash equals the reference node's
  block at that height. Safe and finalized heads advance at the same cadence as the
  reference's `optimism_syncStatus`, within one batch submission interval. Run through at
  least one L1 reorg (or replay a recorded one).

### M6. Unsafe head from mainnet gossip

Join the Base mainnet consensus p2p network.

- Build: discovery from the mainnet boot nodes, gossipsub on the mainnet blocks topics,
  signature check against the unsafe block signer from the system config, insert gossiped
  payloads through the engine, request missing ranges when the gap exceeds the buffer.
- Reference: base/base `crates/consensus/{peers,disc,gossip}`, OP Stack rollup-node p2p
  spec.
- Check: 50+ stable peers; median unsafe-head lag under 2 s and p99 under 10 s over 24 h;
  every gossiped block that becomes safe matches the derived block (no unsafe reorgs that
  the reference does not also see).

### M7. Soak, operations and upgrades

- Build: systemd unit and config example, log rotation, metrics dashboards (head lag,
  blocks/s, Mgas/s, commit latency, disk growth, peer count), alerting on lag and on any
  verification mismatch, pruning policy for history.
- Check: the 7-day definition of done above, including deliberate `kill -9`, reboots, a
  full-disk warning drill, and an upgrade activation on Sepolia before it reaches mainnet.

### M8. Execution-layer p2p

- Build: RLPx (ECIES handshake, framing), devp2p Hello, eth/68 (status, block headers and
  bodies, transactions). Multi-peer header and body backfill is on the critical path: it is
  M4's only block source. snap/1 for state sync (enables M3 option B) and serving are
  optional.
- Check: interop with a reth peer on Sepolia: exchange status, download a header and body
  range, receive transaction gossip.

## Verification

Verification runs continuously, not only at the end. Every check compares against data
needlefish did not produce.

- **Per block (built in):** state root, receipts root, logs bloom, gas used and block hash
  equal the header. The node halts with a precise report (block, tx index, first differing
  account or slot) instead of continuing on a wrong state.
- **Head comparison:** a small checker polls needlefish and the reference node every few
  seconds and records, per height, both block hashes and the three heads (unsafe, safe,
  finalized). Any hash difference at a height both consider safe is a failure. Plot head
  lag over time.
- **State sampling:** every minute, pick random recent accounts and storage slots (from
  recent transactions) and compare `eth_getProof` results at the same block on both nodes.
- **Oracle replay:** keep the M1 follower running next to the full node for the first weeks.
  Two independent paths (stateless and stateful) must agree on every block.
- **Operator view:** `base basectl sync-status` and `doctor` on the server show heads, lag,
  peers and derivation progress. Expose the checker results as metrics.

## Suggested agent lanes

| Lane | Milestones | Owns |
| --- | --- | --- |
| follow | M1, verification checker | `src/infra/replay`, new `src/infra/follow` |
| trie-db | M2 | `src/execution/{db,trie}` |
| snapshot | M3 | new `src/execution/import`, `src/infra/snapshotter` |
| sync-perf | M4 | `src/execution/sync` |
| consensus | M5 | `src/consensus/{derive,engine,service,sources}` |
| p2p | M6, M8 (devp2p backfill for M4) | `src/consensus/p2p`, `src/execution/p2p`, `bin/base/el_*` |
| ops | M7 | `etc/`, `docs/`, `src/infra/basectl` |

Each lane keeps its backlog in `docs/lanes/<lane>.md` and follows AGENTS.md: zero
dependencies, TigerStyle, deterministic simulation tests for every state machine, and
`zig build test && just tidy` before every push.

## Order of work

Revised 2026-11-06 after the first live follower runs (below). The critical path is the
stateful node: it takes block bodies from execution-layer peers (devp2p), never state, and
never uses RPC for catch-up.

1. M3 on Sepolia: import the public state snapshot (state component only) and match its
   header state root.
2. M2 in parallel, first as far as the imported Sepolia state needs: `State` reads through
   the trees (2b), codes on disk (1e), branch store and sparse root (3). Proofs, history and
   the 1B-entry scale proof follow before mainnet.
3. M4 on Sepolia: staged catch-up from the snapshot block to the tip with blocks from
   devp2p peers (M8 multi-peer backfill), then stay there on peer and gossip blocks.
   Execution on disk state must keep up with what the peers deliver.
4. M5 and M6 on Sepolia: safe heads from L1, unsafe head from gossip.
5. The same on mainnet, then the M7 soak.
6. M8 beyond backfill (snap/1, serving) when wanted.

M1 (the stateless follower) is a bounded correctness oracle, not a gate. Measured on Base
Sepolia with keyless endpoints: 69 consecutive blocks verified with zero mismatches, but 5 to
30 s per block against 200 ms blocks, because every cold key costs an `eth_getProof` round
trip (about 5 items/s public) and keys are discovered over several sequential passes. It
falls behind by design, so it is used for fixture tests, short spot checks, and to re-execute
a block the stateful node disputes, never as soak evidence.

### Snapshot sizes (public, 2026-11-06)

Base lists modular snapshots at `https://chain.base.org/api/snapshots`; each manifest names
components with sizes and blake3 hashes. Only `state` (reth MDBX) is needed to bootstrap.

| Chain | Block | `state` compressed | `state` MDBX | Full archive |
| --- | --- | --- | --- | --- |
| Base Sepolia | 55006660 | 310 GB | 438 GB | 1.44 TB |
| Base mainnet | 53523727 | 762 GB | 1.14 TB | 5.2 TB |

So a state-only mainnet import fits in about 4 to 5 TB with staging, not the 8 TB this plan
first assumed for a full archive.

## Risks

- **Storage performance at scale** is the biggest unknown. Prove it with the M2 synthetic
  runs before importing real mainnet state.
- **Snapshot format drift.** reth's table layout changes between versions. Pin the snapshot
  version you import and check its version metadata.
- **Blob retention.** If the node is down for more than about 18 days, it can only re-derive
  safe heads with a blob archiver; unsafe sync via gossip and RPC still works.
- **Public RPC limits.** Use your own L1 and reference nodes for anything beyond M1 demos.
- **Upgrades.** Base ships hardforks on a schedule. Track base/base releases and test each
  activation on Sepolia first.
