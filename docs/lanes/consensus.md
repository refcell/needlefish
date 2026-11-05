# Lane: consensus

Owns `src/consensus/*` and `bin/consensus`. Reference: base/base `crates/consensus/*`
(kona-derived), OP Stack derivation spec.

## Backlog
- [ ] `protocol`: (split below) rollup config, system config (+ updates from L1 logs), L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian formats), user deposits from TransactionDeposited logs, frames, channels, singular + span batches, batch validity rules (Holocene strict ordering), block info.
  - [x] frames (zero-copy codec, payload parser), channels, `BlockInfo`/`L2BlockInfo`
  - [ ] local RLP decoder (until primitives lane lands one) + singular batches
  - [ ] span batches (bitlists, tx data decoding) + batch reader (zlib, brotli)
  - [ ] rollup config + hardfork activation, system config + L1 log updates
  - [ ] L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian), user deposits
  - [ ] batch validity rules (singular, span, Holocene)
- [ ] `sources`: L1 RPC client (blocks, receipts, by number/hash), beacon blob client, L2 engine client (JWT) — all over `utilities.rpc`/`http`.
- [ ] `derive`: pipeline stages (L1 traversal, retrieval calldata/blobs, frame queue, channel bank/assembler, channel reader with zlib+brotli decompression (own implementations or std.compress), batch stream/queue, attributes queue), resets, Holocene semantics. Fuzz all decoders.
- [ ] `engine`: engine task queue (insert unsafe, consolidate, build, finalize), forkchoice state tracking, safe/finalized promotion.
- [ ] `sequencer`: build L2 blocks at block time, sequencer drift, L1 origin selection, conductor-free single sequencer.
- [ ] `rpc`: optimism_* (outputAtBlock, syncStatus, rollupConfig), admin_*.
- [ ] `safedb`: L1→safe head mapping persisted.
- [ ] `p2p` (stub first): unsafe block gossip later in its own lane.
- [ ] `bin/consensus`: sequencer + verifier modes, flags like base/base.

## Decisions
- Frame `is_last` byte other than 0/1 is rejected (OP Stack spec / op-node), stricter
  than base/base's `== 1`.
- Decoded frames borrow the input (zero-copy); channels copy frame data into allocator-owned
  memory because L1 payloads are transient. Total bytes are bounded by the channel bank.
- Zig 0.17 has no array `**` operator: use `@splat`.

## Log
- 2026-11-05: protocol frames, channels, block info with seeded + std fuzz tests.
