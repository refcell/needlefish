# Lane: consensus

Owns `src/consensus/*` and `bin/consensus`. Reference: base/base `crates/consensus/*`
(kona-derived), OP Stack derivation spec.

## Backlog
- [x] `protocol`: (split below) rollup config, system config (+ updates from L1 logs), L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian formats), user deposits from TransactionDeposited logs, frames, channels, singular + span batches, batch validity rules (Holocene strict ordering), block info.
  - [x] frames (zero-copy codec, payload parser), channels, `BlockInfo`/`L2BlockInfo`
  - [x] singular batches (codec + validity rules), batch drop reasons (uses `common/rlp`)
  - [x] span batches (bitlists, tx data decoding) + batch reader (zlib, brotli)
  - [ ] span batch EIP-8130 tx data: `common/consensus/eip8130.zig` now decodes/encodes 0x79
    (`TxEip8130`, `Signed`), so `error.Eip8130Unsupported` can be replaced.
  - [x] rollup config + hardfork activation, system config + L1 log updates
  - [x] user deposits (TransactionDeposited logs), deposit tx encoding, source hashes
  - [x] L1 info deposit tx (Bedrock/Ecotone/Isthmus/Jovian), blob base fee schedule
  - [x] batch validity rules (singular, span, Holocene)
- [ ] `sources`: L1 RPC client (blocks, receipts, by number/hash), beacon blob client, L2 engine client (JWT) — all over `utilities.rpc`/`http`.
- [ ] `derive`: (split below) pipeline stages (L1 traversal, retrieval calldata/blobs, frame queue, channel bank/assembler, channel reader with zlib+brotli decompression (own implementations or std.compress), batch stream/queue, attributes queue), resets, Holocene semantics. Fuzz all decoders.
  - [x] blob codec, error kinds, provider contracts, L1 traversal
  - [x] data sources (calldata, blobs), L1 retrieval, frame queue (Holocene pruning)
  - [x] channel bank / assembler / provider (Holocene switch)
  - [ ] channel reader (decode owned batches)
  - [ ] batch stream, batch queue, batch validator
  - [x] stateful attributes builder, network upgrade txs (Ecotone/Fjord/Isthmus/Jovian)
  - [ ] attributes queue, pipeline core (step, reset, signals)
- [ ] `engine`: engine task queue (insert unsafe, consolidate, build, finalize), forkchoice state tracking, safe/finalized promotion.
- [ ] `sequencer`: build L2 blocks at block time, sequencer drift, L1 origin selection, conductor-free single sequencer.
- [ ] `rpc`: optimism_* (outputAtBlock, syncStatus, rollupConfig), admin_*.
- [x] `safedb`: L1→safe head mapping (in-memory sorted, bounded; 80-byte records for persistence).
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

- Derivation stages are plain structs whose methods take the previous stage and the
  providers as `anytype`; providers never block and return `error.NotAvailable`
  (temporary) while a fetch is in flight. Error kind (temporary/reset/critical) is a pure
  function of the Zig error (`derive/errors.zig`).
- L1 transactions reach the data sources with a recovered `from`; providers over an
  untrusted RPC must recover the sender themselves.
- Span batches: EIP-8130 txs decode but cannot be expanded yet (`error.Eip8130Unsupported`)
  until `common/consensus` has 8130 decoding. Overflow returns errors where base/base wraps.
- Brotli: own RFC 7932 decoder, static dictionary committed (CRC checked vs RFC).
- Attributes builder errors: `BlockMismatch` → `L1OriginMismatch`, `BlockMismatchEpochReset`
  → `EpochParentMismatch`, `BrokenTimeInvariant` → `BadTimestamp` (all reset); deposit decode
  failures → `BadEncoding` (critical); BaseTime/overflow → `AttributesBuilder` (critical).
  Upgrade deployment bytecode is embedded hex copied verbatim from base/base and decoded
  when an activation block is built. `PayloadAttributes` reuses the execution lane's
  `Withdrawal` and converts to its engine type with `engine()`.

- Decoded batches own an arena (`OwnedBatch`) holding a copy of their bytes, so they outlive
  the channel's decompressed buffer.

## Log
- 2026-11-05: safedb: safe head updates, reset semantics, lookup, record codec, fuzz.
- 2026-11-05: derive: channel bank (Granite ready selection, size prune), assembler, provider.
- 2026-11-05: derive: calldata/blob data source, L1 retrieval, frame queue + Holocene prune.
- 2026-11-05: stateful attributes builder (Denim BaseTime/gas scaling), upgrade txs.
- 2026-11-05: derive: blob codec, error kinds, provider contracts, L1 traversal.
- 2026-11-05: span batches (codec, tx data, derive, validity), brotli decoder, batch reader.
- 2026-11-05: singular batch codec + validity (Holocene, Denim same-second, Jovian).
- 2026-11-05: L1 info deposit (4 formats, base/base vectors), fork selection, blob fee.
- 2026-11-05: user deposits, deposit tx 2718 encoding (base/base vectors), source hashes.
- 2026-11-05: rollup config (upgrades, features, Denim schedule), system config updates.
- 2026-11-05: protocol frames, channels, block info with seeded + std fuzz tests.
