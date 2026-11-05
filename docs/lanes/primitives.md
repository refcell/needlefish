# Lane: primitives

Owns `src/common/{primitives,rlp,consensus,genesis,chains,flz,l1_fees}`.
Reference: base/base `crates/common/*`, alloy-primitives, alloy-consensus, op-alloy.

## Backlog
- [x] `primitives`: `Address`, `B256`, `U256` helpers (Zig native `u256`), `Bloom`, hex encode/decode (fast, SIMD), checksum (EIP-55), `Bytes` view types. Fuzz hex round-trip.
- [x] `rlp`: zero-alloc encoder into caller buffer + streaming decoder over slices, length precompute, strict canonical decoding. Fuzz decode/encode round trip, ethereum RLP vectors.
- [x] `consensus` tx types: legacy (EIP-155), 2930, 1559, 4844 (blob), 7702 (set code), OP deposit (0x7E). Signing hash, tx hash, encode/decode (network + EIP-2718), sender recovery (std fallback behind `Recoverer`).
- [x] EIP-4844 pooled/network form with sidecar (blobs, commitments, proofs; EIP-7594 wrapper version), EIP-2718 pooled tx decoding for txpool/RPC.
- [ ] EIP-8130 (0x79, account abstraction, Everest) transaction type as in base/base.
- [x] Switch `Recoverer` default to `common.crypto` ecrecover once the crypto lane lands it.
- [x] Headers, blocks, receipts (incl. OP deposit receipt fields), logs, bloom calculation, withdrawals, requests hash.
- [x] `chains`: Base mainnet/sepolia + devnet chain configs and hardfork activation schedule (Bedrock → Canyon → Delta → Ecotone → Fjord → Granite → Holocene → Isthmus → Jovian and any Base-specific forks in base/base).
- [x] `genesis`: genesis JSON parse/write (std.json allowed or own), alloc handling, genesis block/header + state root via trie lane interface.
- [x] L1 fee calculation (`l1-fees`: Bedrock, Ecotone, Fjord FastLZ `flz`, operator fee, DA footprint).
- [ ] Benchmarks: rlp encode/decode, tx hash, sender recovery throughput.

## Decisions
- Fixed-size types are `extern struct { bytes: [N]u8 }` (`Address`, `B256`, `Bloom`) so they have
  methods and a stable layout; 256-bit integers are native `u256`.
- RLP decoding is strict canonical and zero copy; list-valued tx fields (access lists,
  authorization lists, blob hashes) keep their validated RLP payload and expose iterators, so
  decoding a transaction never allocates. Decoded values borrow the input buffer.
- RLP `Encoder` has a sink mode; tx hashes and signing hashes stream into keccak, no scratch.
- Generic `rlp.codec` reflects over struct fields; depth follows type nesting, not data.
- Sender recovery and signing delegate to `common.crypto.secp256k1` (std fallback removed once
  it landed); hot paths take a `Recoverer` fn pointer. `sign` returns
  `UnrepresentableSignature` for recovery id bit 1 (R.x >= n), which Ethereum cannot encode.
- EIP-1559 base fee and blob gas math live in `execution/chainspec` (node lane landed them
  first); this lane does not duplicate them.
- Receipts support EIP-658 status only (no pre-Byzantium state root): every chain we run is
  post-merge.
- Tx/receipt/withdrawal roots call the trie lane's `ordered_trie_root` with caller scratch.
- `chains` holds canonical per-chain data only (identity, timing, upgrade timestamps, genesis
  anchors, L1 contracts, bootnodes, L1 fork schedules). `RollupConfig`/`Upgrade` enums live in
  `consensus/protocol` and `ChainSpec` in `execution/chainspec`; they can derive from `chains`.
- base/base `common/flz` and `common/l1-fees` map to `src/common/flz` and `src/common/l1_fees`
  (added to this lane). The fork gate is a local `l1_fees.Rules` enum; callers map upgrades.
- genesis: base/base `dev.json` `stateRoot` is stale (22 accounts, root of an older set);
  the dev test pins our root. Verified locally that Base mainnet/Sepolia/Zeronet genesis
  JSON (9 MB each, not committed) reproduce the genesis hashes in `chains`. Genesis JSON
  writing stays with batcher `devnet/genesis.zig` (its only producer).
- Pooled blob txs (`consensus/sidecar.zig`): blobs/commitments/proofs are zero-copy fixed-item
  lists; `validate` checks counts and versioned hashes only. KZG blob/cell proof verification
  waits on the crypto lane (only point evaluation exists); txpool must call it once it lands.
- Curated public ethereum/tests RLP vectors are committed under `src/common/rlp/testdata/`.

## Log
- 2026-11-05: primitives (hex, Address/B256/Bloom, u256, EIP-55/1191), fuzz + seeded fuzz.
- 2026-11-05: rlp encoder/decoder/codec; all ethereum/tests valid+invalid RLP vectors pass.
- 2026-11-05: consensus tx types + envelope, signatures, recovery; EIP-155 and Base deposit vectors.
- 2026-11-05: header/receipts/logs/withdrawals/block/body, roots, EIP-7685; mainnet genesis + Cancun/Prague block vectors.
- 2026-11-05: chains (mainnet/sepolia/zeronet/devnet, L1 mainnet/sepolia/holesky/hoodi/devnet).
- 2026-11-05: flz (FastLZ length, base/base vectors) and l1_fees (Bedrock..Jovian, operator fee).
- 2026-11-05: genesis (JSON, alloc, state/storage roots, fork-aware header incl. Isthmus).
- 2026-11-05: signatures now use crypto lane secp256k1 (ecrecover, constant-time sign).
- 2026-11-05: pooled EIP-4844 network form (v0 sidecar, EIP-7594 v1 cell proofs), `PooledTx`.
