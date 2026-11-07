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
- **Execution p2p (devp2p eth/68 `GetBlockHeaders` / `GetBlockBodies`): works, one peer
  is too slow.** `src/execution/p2p` implements RLPx (EIP-8 ECIES handshake, frames,
  MACs) and the eth/68 messages a fetcher needs; `base el-fetch --enode <enode> --from N
  --count K` connects, exchanges Hello and Status (mirroring the peer's fork id), and
  fetches headers then bodies. It checks each header's parent hash against the one
  before and each body's transactions root (and empty ommers) against its header. Run
  live against a Base Sepolia reth node (base v1.5.4, fork id `0xc6757f44`): blocks
  55006661 onward, parent-linked, every body matching, from the snapshot's next block.
  Limits found:
  - Peers are scarce. The execution bootnodes in `common/chains` refused TCP when tried,
    and discv5 showed no Base execution nodes. `base el-peers` crawls discv4 from those
    bootnodes (they answer UDP), asks each bonded node for its ENR, and keeps the nodes
    whose fork id (the `opel` ENR key that Base nodes advertise and read first, else
    `eth`) is Base Sepolia's `0xc6757f44`. The discv4 table is shared with every
    Ethereum-family network: crawls of 20,000 to 32,000 nodes and 2,400 to 3,000 records
    found 0 or 1 Base Sepolia node each, and no `opel` entries at all. Two distinct
    Base Sepolia reth nodes found so far.
  - Bandwidth differs by peer. One serves bodies at about 25 KB/s (3 to 4 blocks/s;
    geth's own eth/68 client sees the same rate from it, and headers return in 0.3 s, so
    the limit is the peer, not our stack). The other serves 8 to 9 blocks/s. The chain
    makes 5 blocks/s, so one good peer can follow the tip, but closing a 300k-block
    snapshot gap at a net 3 to 4 blocks/s takes a day: catch-up stays on RPC (M4) unless
    many more peers turn up. Pipelining body requests (16 hashes each, all in flight)
    does not raise a slow peer's rate.
  - A session ended with disconnect reason 11 (timeout) after 512 blocks. Likely cause
    (not confirmed): at 25 KB/s, the peer's Ping waits behind tens of seconds of queued
    body data, so our Pong is late. The fetcher must keep less in flight per peer, and
    reconnect and resume from its last linked block.
  - Fetched blocks are bound only by their own parent links; execution headers carry no
    sequencer signature, so a lying peer could serve a self-consistent fake chain. They
    must still be bound to a trusted hash: the snapshot block's hash at the bottom, and a
    sequencer-signed gossip block at the top. Executing them locally checks each header's
    outputs against our own state, but not that the sequencer produced them.
- **RPC catch-up: bounded, one-time.** This is what the sync lane plans for M4: trusted
  L2 RPC blocks, validated by the hash chain back from the target head. It sits outside
  the steady-state path, but it is rate limited. At 100 blocks per request, 300k blocks
  is 3,000 requests.

During steady state, a block missed by gossip (a link of `gap`) can only be recovered by
the same fetch path. The demo counts it as a failure; it does not skip or re-anchor.

### Block source API

`bin/base/el_source.zig` is the devp2p block source behind `el-fetch`: `Source.init`
connects (retrying with backoff) from a block number or the peer's head, optionally
binding the first block to a known parent hash; `Source.next` hands out ascending blocks
as header RLP, hash and EIP-2718 transactions, checked as above, and returns false at the
peer's head. It is shaped to plug into the catch-up stage's block-source interface.
Verified: 512 blocks from 55006661 bound to the hash of 55006660 (the snapshot block), and
a wrong parent hash rejected.

### Executing peer blocks: `base el-run`

`base el-run --db <path> --enode <enode>` opens a disk-mode database (written by
`snapshot-import --out`, possibly advanced by `import-run`) and feeds `Source.next` into
`execution.import.run`'s `Runner.execute`, starting at the database head + 1 with the
head's hash as the required parent. The runner refuses any block that is not the head's
child and commits a block only when every recomputed header field matches, so the head
advances by exactly one executed block at a time; the first failure exits 1 with nothing
skipped. Each block's line carries its tip lag; lag statistics count from the first time
the source reaches the peer's head. With `--duration 1800` this is the demo's acceptance
run. Planned order: catch up from the snapshot with `import-run` (RPC, one time), then
stay at the tip with `el-run` (no RPC).

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

## Integration contract (to the executor)

The p2p side hands the executor, in block-number order, payloads that are signed,
hash-checked and parent-linked. Each one is the block header (re-encoded from the
payload, its hash equal to `block_hash`), the raw EIP-2718 transactions, and
`parent_beacon_block_root`. The executor executes block N+1 on top of N, then checks
state root, receipts root, logs bloom, gas used and block hash against that header.
