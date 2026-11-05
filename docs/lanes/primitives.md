# Lane: primitives

Owns `src/common/{primitives,rlp,consensus,genesis,chains,flz,l1_fees}`.
Reference: base/base `crates/common/*`, alloy-primitives, alloy-consensus, op-alloy.

## Backlog
- [x] `primitives`: `Address`, `B256`, `U256` helpers (Zig native `u256`), `Bloom`, hex encode/decode (fast, SIMD), checksum (EIP-55), `Bytes` view types. Fuzz hex round-trip.
- [x] `rlp`: zero-alloc encoder into caller buffer + streaming decoder over slices, length precompute, strict canonical decoding. Fuzz decode/encode round trip, ethereum RLP vectors.
- [x] `consensus` tx types: legacy (EIP-155), 2930, 1559, 4844 (blob), 7702 (set code), OP deposit (0x7E). Signing hash, tx hash, encode/decode (network + EIP-2718), sender recovery (std fallback behind `Recoverer`).
- [x] EIP-4844 pooled/network form with sidecar (blobs, commitments, proofs; EIP-7594 wrapper version), EIP-2718 pooled tx decoding for txpool/RPC.
- [x] EIP-8130 (0x79, account abstraction, Everest) transaction type as in base/base.
- [x] Switch `Recoverer` default to `common.crypto` ecrecover once the crypto lane lands it.
- [x] Headers, blocks, receipts (incl. OP deposit receipt fields), logs, bloom calculation, withdrawals, requests hash.
- [x] `chains`: Base mainnet/sepolia + devnet chain configs and hardfork activation schedule (Bedrock → Canyon → Delta → Ecotone → Fjord → Granite → Holocene → Isthmus → Jovian and any Base-specific forks in base/base).
- [x] `genesis`: genesis JSON parse/write (std.json allowed or own), alloc handling, genesis block/header + state root via trie lane interface.
- [x] L1 fee calculation (`l1-fees`: Bedrock, Ecotone, Fjord FastLZ `flz`, operator fee, DA footprint).
- [x] Benchmarks: rlp encode/decode, tx hash, sender recovery throughput.
- [x] Predeploy, system and upgrade-deployer addresses (`predeploys.rs`).
- [x] Denim BaseTime metadata deposit (`base_time.rs`): calldata, deposit, validation.
- [x] `rpc_types`: JSON-RPC forms of logs, transactions (deposit, 0x79), receipts (L1 fee,
  phaseStatuses), headers and blocks, streamed to `std.Io.Writer`.
- [x] `flashblocks`: payload/base/delta/metadata types, JSON or brotli message decode
  (5 MiB cap), JSON writer, `FlashblockId`.
- [x] `rpc_types/request`: TransactionRequest (incl. 0x79 scalar fields) and EIP-1898 block
  ids from a parsed `std.json.Value`.
- [x] `rpc_types/request`: 0x79 `accountChanges`/`calls` in requests (round-trip the writer).
- [x] `signer`: `eth_signTransaction` request body, response parse, content + signer checks.

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
- EIP-8130 (`consensus/eip8130*.zig`) mirrors base/base encoding, signing hashes (0x79 sender,
  0x7a payer, 0x7901 replay id), raw-k1 recovery (low s), static/timestamp/structural checks.
  base/base ships no golden vectors; tests pin a hand-checked byte layout. `Envelope` and
  `Receipt` (`committed_phases`) carry 0x79; span batches, txpool and the node executor reject
  it (tiny edits in their lanes) until span-batch 8130 data and AA execution are ported.
- `.cache/push.sh` reruns the full suite after a race only when the new upstream commits touch
  `src/common/` or build files; otherwise it compiles and tidies (disjoint merge).
- Curated public ethereum/tests RLP vectors are committed under `src/common/rlp/testdata/`.
- rpc_types writes JSON directly (no DOM); callers pass block/position context. Addresses
  are EIP-55 checksummed like reth; `l1FeeScalar` is a caller-formatted decimal string.
- flashblocks parse with `std.json` into a per-message arena (the feed is not a hot
  consensus path) and reuse the consensus lane's brotli decoder.
- `Sidecar.verify_kzg` batch-verifies v0 blob proofs via `crypto.kzg.blob`; v1 cell proofs
  return `CellProofsUnsupported` until the crypto lane ships cells. Tests are ReleaseSafe-only.
- `bundles` (base/base metering tooling) is not ported: nothing in base/base consumes it.

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
- 2026-11-05: EIP-8130 tx type (encode/decode, hashes, sender/payer recovery, validation).
- 2026-11-05: 0x79 wired into `TxType`/`Envelope`/`Receipt`; other lanes reject it for now.
- 2026-11-05: benchmarks (`common/consensus/bench.zig`, results in docs/PERF.md).
- 2026-11-05: predeploys and Denim BaseTime metadata deposit.
- 2026-11-05: rpc_types JSON writers (alloy field names; checksummed addresses).
- 2026-11-05: flashblocks types and message decoding.
- 2026-11-05: blob sidecar KZG verification (v0).
- 2026-11-05: rpc_types request parsing (TransactionRequest, BlockId).
- 2026-11-05: 0x79 accountChanges/calls request parsing.
- 2026-11-05: remote signer codecs (`common/signer`).
