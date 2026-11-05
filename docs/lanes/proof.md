# Lane: proof

Owns `src/proof/*` (submodules `preimage`, `mpt`, `executor`, `driver`, `program`,
`client`, `host`, `rpc`, `contracts`, `proposer`, `challenger`) and the `proof`,
`proposer` and `challenger` subcommands of `bin/base`. Reference: base/base
`crates/proof/{preimage,mpt,executor,driver,proof,client,host,rpc,primitives,contracts,
proposer,challenge}` (~35k lines). TEE (`tee/`), ZK (`zk/`), `prover-service` and
`worker` are out of scope for now; add them to the backlog only after the items below.

Reuse, do not duplicate: RLP/types from `src/common`, keccak/secp256k1 from
`src/common/crypto`, the EVM from `src/execution/evm`, trie hashing from
`src/execution/trie`, derivation from `src/consensus/derive`, JSON-RPC client from
`src/utilities/rpc`. Small additive edits in those lanes are fine (a `pub`, an
interface hook). All file, pipe and socket IO goes through `src/utilities/io` so the
program can run against an in-memory oracle in tests and the cluster simulator.

## Backlog
- [ ] `proof/preimage`: `PreimageKey` (types: local, keccak256, global generic,
  sha256, blob, precompile), hint encoding, oracle/hint reader-writer over a bidirectional
  channel (port `key.rs`, `hint.rs`, `oracle.rs`, `native_channel.rs`). In-memory pipe
  channel for tests; seeded + `std.testing.fuzz` round trips of keys and frames.
- [ ] `proof/mpt`: oracle-backed trie node (blinded/leaf/extension/branch), lazy open,
  get/insert/delete with root recomputation, list walker for tx/receipt tries (port
  `node.rs`, `list_walker.rs`). Differential test against `src/execution/trie` roots;
  fuzz insert/delete sequences.
- [ ] `proof/executor`: stateless L2 block executor over an oracle-backed state DB
  (trie DB with account/storage/code fetch via hints), building header + receipts and
  checking the output root (port `executor/src/{builder,db}`). Test: re-execute a block
  built by the node lane from a witness and match its state root.
- [ ] `proof/program` boot info + caching oracle + L1/L2 chain providers over the
  oracle (port `proof/src/{boot,caching_oracle,l1,l2,hint,sync}.rs`), feeding the
  consensus lane's derivation pipeline.
- [ ] `proof/driver` + `proof/client`: prologue / derive-and-execute loop to the claimed
  L2 block / epilogue that compares the computed output root with the claim (port
  `driver/src/*`, `client/src/*`). End-to-end test with an in-memory recorded oracle.
- [ ] `proof/host`: KV stores (mem, disk via io, split, boot), online backend that
  serves hints by fetching from L1/L2/beacon RPC and records preimages, offline backend
  that replays them, server loop over the preimage channel (port `host/src/*`).
- [ ] `bin/base proof`: run host + client in one process (native mode) against devnet
  RPCs for a given L2 block; record a witness file and replay it offline.
- [ ] `proof/rpc` + `proof/contracts`: typed L1/L2/rollup clients with caching, ABI
  bindings for DisputeGameFactory, AnchorStateRegistry, DelayedWETH (port `rpc/`,
  `contracts/`). ABI encode/decode fuzz tests.
- [ ] `proof/proposer`: output-root proposal pipeline (targets, intervals, collector,
  submitter via the batcher's txmgr), `bin/base proposer`, DST test with L1 reorgs.
- [ ] `proof/challenger`: scanner of dispute games, validator that recomputes output
  roots, bond claiming, `bin/base challenger` (port `challenge/src/*`), DST test.

## Decisions

## Log
