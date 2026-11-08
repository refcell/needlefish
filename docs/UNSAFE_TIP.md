# Unsafe tip from p2p (Base Sepolia demo)

Goal: stay at the Base Sepolia unsafe tip and execute consecutive blocks on local state.
Blocks arrive from the consensus p2p network, with no public RPC in the steady-state
ingestion path. Safe and finalized heads (derivation) are out of scope.

Acceptance: 30 minutes of consecutive, locally executed blocks. Every block's state root,
receipts root, logs bloom, gas used and block hash must equal its header, and tip lag is
measured. Skipping a block or re-anchoring counts as failure.

The demo has two halves, which are proven separately and then joined:

1. **Reception (this doc, p2p lane).** Real discv5 discovery and libp2p gossipsub on
   Sepolia, envelope decoding, sequencer signature check, block hash recomputation, and
   parent-hash continuity. `base unsafe-watch` does this with no RPC at all.
2. **Execution (snapshot and sync lanes).** Local state imported from the public snapshot,
   advanced block by block. Gossip blocks are fed in only once that state reaches the live
   window (see "Snapshot to tip").

Receiving a valid gossip block is not evidence that it executed. The watcher reports
reception only.

## `base unsafe-watch`

    base unsafe-watch [--chain base-sepolia|base-mainnet] [--duration <seconds>] [--quiet]
                      [--p2p.* ...]

- Seeds discovery from the chain's public boot ENRs (base/base `boot.rs`) and dials every
  Sepolia record (`opstack` ENR key with chain id 84532).
- Subscribes to the block topic that is live now: `/optimism/84532/3/blocks` (v4). Older
  topics retire after 60 s, as in base/base.
- Each accepted block was validated by the gossip handler, with base/base parity. The
  checks are timestamp window, signature recovery against the unsafe block signer,
  block-hash recomputation from the payload, v3/v4 field rules, the Denim 200 ms schedule,
  and the seen-hash limits. The watcher then recovers the signer itself and links the
  block to its parent hash.
- It prints one `block` line per block (number, hash, parent, tx count, gas, lag, signer,
  link) and a `status` line every 10 s. The link is one of `first`, `ok`, `gap`, `reorg`
  or `stale`.
- Lag is local wall-clock time minus the block's scheduled time
  (`RollupConfig.l2_block_timestamp_ms`, the 200 ms Denim schedule).

### Signer source

The unsafe block signer comes from the built-in public chain config
(`common/chains`). For Sepolia that is `0xb830b99c95Ea32300039624Cb567d324D4b1D83C`, the
value of the L1 SystemConfig `unsafeBlockSigner` slot. Override it with
`--p2p.unsafe.block.signer`.

base/base reads the slot from L1 at startup. `base consensus` does the same through
`SignerWatcher` and polls it, but that needs an L1 RPC. The watcher does not use L1 RPC.
The check fails closed: after a rotation, new blocks are rejected as `invalid_signer`
(visible in the `failed:` counters). A block with the wrong signer is never accepted.

### Measured (2026-11-06, behind NAT, no inbound reachability)

- Discovery: discv5 handshakes complete over UDP through NAT. The Sepolia population we
  can see is small: about 6 to 30 records with the `opstack` key at a time, among many
  records from other networks.
- Connections: noise, yamux, identify and meshsub all interoperate with base/base nodes
  (agent `base`). Many peers accept the TCP connection and then send a yamux go-away
  within milliseconds; they are at their connection limit (base/base `peers.hi` 30).
  Peers that keep us but do not need mesh peers PRUNE our GRAFT (backoff 60 s). Because
  rust-libp2p keeps a connection alive only while it is in the mesh, those peers then
  close the idle link after about 60 s.
- Blocks: once the watcher reaches a peer that grafts it, blocks stream at the chain's
  rate. One run got 159 blocks in about 32 s from one peer: 158 `ok` links, no gaps, no
  signer mismatches, no validation failures, average lag 82 ms, maximum 910 ms.
- Cross-check: a scratch rust-libp2p gossipsub client (outside the repo, base/base
  message-id function), given the same peer list, saw the same thing. Only one of eight
  peers forwarded blocks, and it was the same peer. So the scarcity is the network's
  topology, not our stack.
- Because a node behind NAT gets no inbound peers, the watcher re-dials every known
  Sepolia record every 10 s (`--p2p.redial.known-interval`, off by default as in
  base/base). It takes a peer's slot as soon as one frees. The gater's redial limits
  still apply.

## Snapshot to tip

Gossip only carries the live window. Blocks older than 60 s are rejected
(`block_age_max_seconds`), and the router's message cache covers 3 heartbeats (1.5 s)
for IWANT. Gossip cannot fill any historical range.

The public Sepolia state snapshot is at block 55006660. The tip was 55306938 at
2026-11-06 12:01 ET, so the snapshot is about 300k blocks (about 16.7 h at 5 blocks/s)
behind, and the gap grows by 5 blocks/s. To join live gossip, the executor must:

1. catch up from the snapshot block to the oldest gossip block still buffered, faster
   than 5 blocks/s; and
2. then execute each gossip block in order, starting from the buffered one whose parent
   is the last executed block.

Peer-based ways to fetch the catch-up range and any missing block:

- **Consensus p2p req/resp: not available.** op-node's `/opstack/req/payload_by_number`
  is deliberately absent from base/base (`service/tests/actors/network/p2p.rs` asserts it
  is not advertised), and no Sepolia peer we identified advertises it. Their identify
  protocols are meshsub 1.0 to 1.2, floodsub, identify, identify push and ping.
- **Execution p2p (devp2p eth/68 `GetBlockHeaders` / `GetBlockBodies`): the catch-up
  path, no RPC.** `src/execution/p2p` implements discv4, RLPx (EIP-8 ECIES handshake,
  frames, MACs) and the eth/68 messages a fetcher needs. Every fetched header's parent
  hash is checked against the block before it, and every body's transactions root (and
  empty ommers) against its header. All peers found are reth 2.5.2 with base v1.5.x, fork
  id `0xc6757f44`.
  - Finding peers: the execution bootnodes in `common/chains` refuse TCP but answer
    discv4 UDP; discv5 shows no Base execution nodes. `base el-peers` crawls discv4 from
    the bootnodes and from known Base nodes, asks every bonded node for its ENR, and keeps
    nodes whose fork id (the `opel` key Base nodes read first, else `eth`) matches. The
    discv4 table is shared with every Ethereum-family network, so finds are rare: a
    30-minute crawl (32k nodes, 15.5k records) found 7. Seeding later crawls from known peers
    raised the known Base Sepolia peers to 14; one is usually full (disconnect reason 4,
    too many peers).
  - Download rate (2026-11-07, blocks checked and linked, not executed): one peer at a
    time measured 47 to 1,607 blocks/s, and one peer moved between 64 and 832 blocks/s
    across runs, so per-peer rate is largely peer-side load. The multi-peer pool
    (`el_pool.zig`, below) fetched 321,793 blocks from 55006661 in 90 s from five peers:
    3,575 blocks/s average, 3,756 peak, 700 times the chain's 5 blocks/s. With 14 peers
    a later run fetched 221,185 blocks in 75 s (about 2,920 blocks/s, 13 peers at 115 to
    1,125 blocks/s each).
  - Earlier single-peer figures (3 to 9 blocks/s, 2026-11-06) were one peer, one batch
    at a time, measured while a 26-connection 310 GB snapshot download shared the host's
    link; the same peers later served 211 to 832 blocks/s on an idle link. Our side was
    not the limit: the receive queue stayed empty, CPU near zero, RTT 22 to 36 ms. Asking
    for 1,024 headers per batch was 7 times slower than 128 on one peer, so segments are
    128 blocks.
  - Some ranges are large: a 128-block segment can hold over 20 MiB of bodies.
  - Fetched blocks are bound only by their own parent links; execution headers carry no
    sequencer signature, so a lying peer could serve a self-consistent fake chain. They
    are bound to a trusted hash at the bottom (the database head, i.e. the verified
    snapshot), and executing them checks each header's outputs against our own state,
    but not that the sequencer produced them. Signed gossip blocks bind the top.
- **RPC catch-up: not used.** The project owner ruled RPC out for catch-up as well as for
  steady state (SYNC_PLAN M4/M8).

During steady state, a block missed by gossip (a link of `gap`) can only be recovered by
the same fetch path. The demo counts it as a failure; it does not skip or re-anchor.

### Block sources

- `bin/base/el_source.zig`, `Source`: one peer. `next` hands out ascending blocks as
  header RLP, hash and EIP-2718 transactions, checked as above, and returns false at the
  peer's head; it reconnects with backoff. Verified: 512 blocks from 55006661 bound to the
  hash of 55006660 (the snapshot block), and a wrong parent hash rejected.
- `bin/base/el_pool.zig`, `Pool`: every peer at once, one thread and connection each.
  Workers pull 128-block segments from a window of 24 ahead of the consumer, so fast
  peers take more; a segment held over 2 s is also fetched by an idle peer (hedging). The
  consumer hands blocks out in order and checks the parent link across segments: a
  segment that does not link is refetched and its peer cooled down. Failing peers cool
  down 1 to 60 s, peers that answer short (behind) 15 s. The pool stops 256 blocks short
  of the tip, estimated from the block schedule. When execution is the limit, the window
  is full and workers idle without reading their sockets; peers then dropped them for
  unanswered pings (disconnect reason 11, 8 drops in 180 s behind a 110 blocks/s
  consumer). An idle connection now makes a one-header request every 10 s, which answers
  pending pings: the same run had no reason-11 drops.
- `bin/base/el_feed.zig`, `Feed`: the pool until it stops short of the tip, then a
  `Source` on the fastest peer's open connection (lent from its worker: peers refuse
  quick reconnects); back to the pool if the follower fails or falls 512 blocks behind.
  Measured without a database: 36k blocks behind to following in about 10 s (catch-up
  at 3,150 to 4,236 blocks/s), then 524 consecutive tip blocks at 42 ms average lag.

### Executing peer blocks: `base el-run`

`base el-run --db <path> --peers <file>` opens a disk-mode database (written by
`snapshot-import --out`) and feeds `Feed.next` into `execution.import.run`'s
`Runner.execute`, starting at the database head + 1 with the head's hash as the required
parent. The runner refuses any block that is not the head's child and commits a block
only when every recomputed header field matches, so the head advances by exactly one
executed block at a time; the first failure exits 1 with nothing skipped. Each block's
line carries its tip lag; lag statistics count from when the follower reaches the tip.
The 10 s summary shows the head's distance behind the schedule, blocks downloaded, and
milliseconds per block in each runner phase, so download and execution rates are separate.
With download at thousands of blocks per second, execution sets the catch-up rate. The
peer file is re-read every minute; `base el-peers --peers <file>` grows it. With
`--duration 1800` at the tip this is the demo's acceptance run.

### Following the tip from an execution peer

Behind NAT, gossip delivery is intermittent: one run received 159 consecutive blocks, and
later runs of 15 minutes and 2 hours received none (no block-carrying peer gave us a mesh
slot). An execution peer does not depend on that. `base el-fetch --from tip --follow`
asks the peer for the next block number every 100 ms. Measured against a Base Sepolia
reth node for 30 minutes: 9,002 consecutive linked blocks (55686214 to 55695215, the
chain's full 5 blocks/s), each body checked against its header, 0 gaps, 0 reconnects.
Tip lag (arrival minus the block's scheduled time) per block: average 793 ms, median
356 ms, p90 1.5 s, p99 10.6 s, max 19.9 s; the tail is the peer stalling, then catching
up in a burst. An earlier 180 s run averaged 251 ms.

The cost is trust. Execution headers are not signed, so this source proves continuity
and body integrity, not that the sequencer produced the blocks. Local execution then
proves the header outputs follow from our state. Tying the chain to the sequencer needs a
signed gossip block at the same height (whenever gossip delivers one, its hash must be on
the followed chain) or the snapshot hash at the bottom of the range. Checked offline: the
159 sequencer-signed gossip blocks one `unsafe-watch` run received (55318947 to
55319105) match the blocks the execution peer serves at those heights (the run logged
64-bit hash prefixes; compared with `el-fetch --verbose`).

### Acceptance run (2026-11-08): met

One `base el-run --peers` process, devp2p only (no RPC), on the disk database imported
from the 55006660 snapshot, started at head 55006985:

- Catch-up: the pool (13 usable peers) delivered 988,416 blocks; execution averaged about
  95 blocks/s early and 78 blocks/s overall, against the chain's 5 blocks/s. The feed
  switched to following the tip once (at 55995402, on a lent pool connection) and reached
  the tip at 55995774, about 2.9 h after the start.
- At the tip: 11,657 consecutive executed blocks (55995774 to 56007430) over 38.9 min,
  every one committed with all header checks equal (state root, receipts root, bloom, gas,
  transactions root, withdrawals root, resealed hash). Tip lag (commit time minus the
  block's scheduled time): average 59 ms, median 54 ms, p90 105 ms, p99 295 ms, max
  680 ms; no block over 1 s. Execution per block: average 6.1 ms, median 4 ms, p99 22 ms.
- Whole run: 1,000,445 consecutive executed blocks (55006986 to 56007430), 0 gaps, 0
  mismatches, 0 refusals, no restart or re-anchor. Execution headers are unsigned, so the
  trust anchor is the snapshot block: every block is parent-linked back to it and every
  state root was recomputed locally.
- Per-block phases (ms) over the run: transactions 1.75, commit 3.06, prefetch 1.09,
  room (checkpoint and compaction waits) 4.31, everything else under 0.1.

## Integration contract (to the executor)

The p2p side hands the executor, in block-number order, payloads that are signed,
hash-checked and parent-linked. Each one is the block header (re-encoded from the
payload, its hash equal to `block_hash`), the raw EIP-2718 transactions, and
`parent_beacon_block_root`. The executor executes block N+1 on top of N, then checks
state root, receipts root, logs bloom, gas used and block hash against that header.
