# Lane: consensus

Owns `src/consensus/*` and `bin/consensus`. Reference: base/base `crates/consensus/*`
(kona-derived), OP Stack derivation spec.

## Backlog
- [ ] `protocol`: (split below) rollup config, system config (+ updates from L1 logs), L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian formats), user deposits from TransactionDeposited logs, frames, channels, singular + span batches, batch validity rules (Holocene strict ordering), block info.
  - [x] frames (zero-copy codec, payload parser), channels, `BlockInfo`/`L2BlockInfo`
  - [ ] local RLP decoder (until primitives lane lands one) + singular batches
  - [ ] span batches (bitlists, tx data decoding) + batch reader (zlib, brotli)
  - [x] rollup config + hardfork activation, system config + L1 log updates
  - [x] user deposits (TransactionDeposited logs), deposit tx encoding, source hashes
  - [ ] L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian)
  - [ ] batch validity rules (singular, span, Holocene)
- [ ] `sources`: L1 RPC client (blocks, receipts, by number/hash), beacon blob client, L2 engine client (JWT) — all over `utilities.rpc`/`http`.
- [ ] `derive`: pipeline stages (L1 traversal, retrieval calldata/blobs, frame queue, channel bank/assembler, channel reader with zlib+brotli decompression (own implementations or std.compress), batch stream/queue, attributes queue), resets, Holocene semantics. Fuzz all decoders.
- [ ] `engine`: engine task queue (insert unsafe, consolidate, build, finalize), forkchoice state tracking, safe/finalized promotion.
- [ ] `sequencer`: build L2 blocks at block time, sequencer drift, L1 origin selection, conductor-free single sequencer.
- [ ] `rpc`: optimism_* (outputAtBlock, syncStatus, rollupConfig), admin_*.
- [ ] `safedb`: L1→safe head mapping persisted.
- [ ] `p2p` (stub first): real implementation is owned by the p2p lane in `src/consensus/p2p/` (see p2p.md); consume its `p2p.Service`.
- [ ] `bin/consensus`: sequencer + verifier modes, flags like base/base.

## Decisions
- Frame `is_last` byte other than 0/1 is rejected (OP Stack spec / op-node), stricter
  than base/base's `== 1`.
- Decoded frames borrow the input (zero-copy); channels copy frame data into allocator-owned
  memory because L1 payloads are transient. Total bytes are bounded by the channel bank.
- `RollupConfig`, `SystemConfig` live in `src/consensus/protocol` (upstream: `common/genesis`)
  because this lane's backlog owns them; JSON (serde) parsing comes with `bin/consensus`.
  Execution-only Base features (Beryl/Cobalt/Everest/Zenith precompiles) are omitted from
  `Feature`; the runtime upgrade override registry is not ported yet.
- `DepositTx` lives in `protocol/deposits.zig` until the primitives lane lands OP deposit
  tx types; switch to theirs then.
- Invalid system config logs are skipped (base/base collects them as non-fatal errors).
- Zig 0.17 has no array `**` operator: use `@splat`.

## Log
- 2026-11-05: user deposits, deposit tx 2718 encoding (base/base vectors), source hashes.
- 2026-11-05: rollup config (upgrades, features, Denim schedule), system config updates.
- 2026-11-05: protocol frames, channels, block info with seeded + std fuzz tests.
