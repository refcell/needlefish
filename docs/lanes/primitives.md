# Lane: primitives

Owns `src/common/{primitives,rlp,consensus,genesis,chains}`.
Reference: base/base `crates/common/*`, alloy-primitives, alloy-consensus, op-alloy.

## Backlog
- [x] `primitives`: `Address`, `B256`, `U256` helpers (Zig native `u256`), `Bloom`, hex encode/decode (fast, SIMD), checksum (EIP-55), `Bytes` view types. Fuzz hex round-trip.
- [x] `rlp`: zero-alloc encoder into caller buffer + streaming decoder over slices, length precompute, strict canonical decoding. Fuzz decode/encode round trip, ethereum RLP vectors.
- [x] `consensus` tx types: legacy (EIP-155), 2930, 1559, 4844 (blob), 7702 (set code), OP deposit (0x7E). Signing hash, tx hash, encode/decode (network + EIP-2718), sender recovery (std fallback behind `Recoverer`).
- [ ] EIP-4844 pooled/network form with sidecar (blobs, commitments, proofs; EIP-7594 wrapper version), EIP-2718 pooled tx decoding for txpool/RPC.
- [ ] EIP-8130 (0x79, account abstraction, Everest) transaction type as in base/base.
- [ ] Switch `Recoverer` default to `common.crypto` ecrecover once the crypto lane lands it.
- [ ] Headers, blocks, receipts (incl. OP deposit receipt fields), logs, bloom calculation, withdrawals, requests hash.
- [ ] `chains`: Base mainnet/sepolia + devnet chain configs and hardfork activation schedule (Bedrock → Canyon → Delta → Ecotone → Fjord → Granite → Holocene → Isthmus → Jovian and any Base-specific forks in base/base).
- [ ] `genesis`: genesis JSON parse/write (std.json allowed or own), alloc handling, genesis block/header + state root via trie lane interface.
- [ ] L1 fee calculation (`l1-fees`: Bedrock, Ecotone, Fjord FastLZ `flz`, operator fee, DA footprint).
- [ ] Benchmarks: rlp encode/decode, tx hash, sender recovery throughput.

## Decisions
- Fixed-size types are `extern struct { bytes: [N]u8 }` (`Address`, `B256`, `Bloom`) so they have
  methods and a stable layout; 256-bit integers are native `u256`.
- RLP decoding is strict canonical and zero copy; list-valued tx fields (access lists,
  authorization lists, blob hashes) keep their validated RLP payload and expose iterators, so
  decoding a transaction never allocates. Decoded values borrow the input buffer.
- RLP `Encoder` has a sink mode; tx hashes and signing hashes stream into keccak, no scratch.
- Generic `rlp.codec` reflects over struct fields; depth follows type nesting, not data.
- Sender recovery and the dev signer (RFC 6979, not constant time) use `std.crypto.ecc.Secp256k1`
  as a fallback until the crypto lane ships ecrecover; hot paths take a `Recoverer` fn pointer.
- EIP-1559 base fee and blob gas math live in `execution/chainspec` (node lane landed them
  first); this lane does not duplicate them.
- Curated public ethereum/tests RLP vectors are committed under `src/common/rlp/testdata/`.

## Log
- 2026-11-05: primitives (hex, Address/B256/Bloom, u256, EIP-55/1191), fuzz + seeded fuzz.
- 2026-11-05: rlp encoder/decoder/codec; all ethereum/tests valid+invalid RLP vectors pass.
- 2026-11-05: consensus tx types + envelope, signatures, recovery; EIP-155 and Base deposit vectors.
