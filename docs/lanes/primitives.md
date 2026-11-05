# Lane: primitives

Owns `src/common/{primitives,rlp,consensus,genesis,chains}`.
Reference: base/base `crates/common/*`, alloy-primitives, alloy-consensus, op-alloy.

## Backlog
- [ ] `primitives`: `Address`, `B256`, `U256` helpers (Zig native `u256`), `Bloom`, hex encode/decode (fast, SIMD), checksum (EIP-55), `Bytes` view types. Fuzz hex round-trip.
- [ ] `rlp`: zero-alloc encoder into caller buffer + streaming decoder over slices, length precompute, strict canonical decoding. Fuzz decode/encode round trip, ethereum RLP vectors.
- [ ] `consensus` tx types: legacy (EIP-155), 2930, 1559, 4844 (blob), 7702 (set code), OP deposit (0x7E). Signing hash, tx hash, encode/decode (network + EIP-2718), sender recovery via `common.crypto`.
- [ ] Headers, blocks, receipts (incl. OP deposit receipt fields), logs, bloom calculation, withdrawals, requests hash.
- [ ] `chains`: Base mainnet/sepolia + devnet chain configs and hardfork activation schedule (Bedrock → Canyon → Delta → Ecotone → Fjord → Granite → Holocene → Isthmus → Jovian and any Base-specific forks in base/base).
- [ ] `genesis`: genesis JSON parse/write (std.json allowed or own), alloc handling, genesis block/header + state root via trie lane interface.
- [ ] EIP-1559 base fee calc incl. OP params (elasticity/denominator, Holocene extra-data encoding), blob gas / excess blob gas, L1 fee calculation (`l1-fees`: Bedrock, Ecotone, Fjord FastLZ `flz`, operator fee, DA footprint).
- [ ] Benchmarks: rlp encode/decode, tx hash, sender recovery throughput.

## Decisions

## Log
