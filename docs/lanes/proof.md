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
- [x] `proof/preimage`: `PreimageKey` (types: local, keccak256, global generic,
  sha256, blob, precompile), hint encoding, oracle/hint reader-writer over a bidirectional
  channel (port `key.rs`, `hint.rs`, `oracle.rs`, `native_channel.rs`). In-memory pipe
  channel for tests; seeded + `std.testing.fuzz` round trips of keys and frames.
- [x] `proof/mpt`: oracle-backed trie node (blinded/leaf/extension/branch), lazy open,
  get/insert/delete with root recomputation, list walker for tx/receipt tries (port
  `node.rs`, `list_walker.rs`). Differential test against `src/execution/trie` roots;
  fuzz insert/delete sequences.
- [x] `proof/executor`: stateless L2 block executor over an oracle-backed state DB
  (trie DB with account/storage/code fetch via hints), building header + receipts and
  checking the output root (port `executor/src/{builder,db}`). Test: re-execute a block
  built by the node lane from a witness and match its state root.
- [x] `proof/program` boot info + caching oracle + L1/L2 chain providers over the
  oracle (port `proof/src/{boot,caching_oracle,l1,l2,hint,sync}.rs`), feeding the
  consensus lane's derivation pipeline.
- [x] `proof/driver` + `proof/client`: prologue / derive-and-execute loop to the claimed
  L2 block / epilogue that compares the computed output root with the claim (port
  `driver/src/*`, `client/src/*`). End-to-end test with an in-memory recorded oracle.
- [ ] `proof/e2e`: record a real oracle (sim or devnet: L1 with batcher frames, L2 blocks
  and witnesses) and run the client through derive + execute of several blocks, checking
  the claimed output root; include a Holocene deposit-only retry case. (The current client
  test covers boot, safe head, providers, pipeline reset and L1 exhaustion only.)
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
- Preimage protocol is synchronous (no async runtime). In-memory `Duplex` endpoints run a
  `Pump` (one host server step) when a client read would block, so client and host
  interleave deterministically on one thread. Channel writes are all-or-nothing over a
  list of parts so a full pipe never tears a frame. An fd-backed channel for split
  client/host processes comes with `proof/host`.
- Oracle reader drains the payload on `BufferTooSmall`/`BufferLengthMismatch` (Rust
  leaves the stream unframed). Preimages above 16 MiB and hints above 64 KiB are
  rejected; the hint host still acknowledges so the client never deadlocks.
- Generic `<type> 0x<hex>` hint text parse/encode lives in `preimage/hint.zig`; the typed
  `HintType` enum lands with `proof/program`.
- `proof/mpt` does not port the Rust `TrieNode` tree: `execution/trie/sparse.zig`
  (`SparseTrie`) already is a lazily-opened, blinded-subtrie trie with exact root
  recomputation. `proof/mpt` adds `OracleResolver` (keccak preimages via the oracle,
  hash-verified, cached in a fixed arena), a lenient generic node decoder, and the list
  walker. The walker decodes each leaf key back to its index (canonical, unique,
  contiguous `0..n`) instead of relying on DFS order plus the Rust index-0 swap.
- `proof/executor` reuses the node's block executor (new `executor.Backend` hook,
  `Executor.init_backend`) over the trie-db lane's `SparseState` (new `Fallback` hook
  for nodes/codes/block hashes, `account_storage_root`). The oracle fallback fetches
  codes and headers after `l2-code` / `l2-block-header` hints and walks BLOCKHASH from
  the parent hash through keccak-verified headers (never trusts witness headers). Header
  assembly mirrors the node's `Chain.child_header`/`seal`; the e2e test rebuilds
  node-built L2 blocks and must match their hashes, so drift is caught. Per-account
  `l2-account-proof` hints are not sent: the `l2-payload-witness` hint prefetches all.
- Boot: optional local keys the host lacks are served as empty preimages (the oracle
  wire has no not-found). Outside the devnet the host's rollup config must match the
  built-in chain config's identity fields (chain ids, genesis, inbox, deposit/system
  config contracts, block time); upgrade timestamps come from the host. The L1 fork
  config comes from `chains.l1_by_chain_id` (local key 7 is not read).
- Program providers: derivation's `ProviderError` has no fatal member, so oracle
  failures return `NotFound` and set the provider's `failure`; the program driver aborts
  when it is set after a pipeline step. The L1 provider recovers senders only for
  transactions to the batch inbox (`recover_to`); others keep a zero `from`.
- L2 provider: by-number lookups walk headers back from a head the program advances
  with `set_head`; blocks the program built are kept in a 64-entry ring (`remember`)
  so block info / system config never depend on the host knowing a block the program
  derived differently. Full safe blocks (span batch checks) still come from the oracle.
- No separate caching oracle: `OracleResolver` caches every hash-verified keccak read
  (headers, trie nodes) and in-process reads are cheap; blob elements are read once.
  The driver empties the providers' resolver between steps when it is half full.
- Client: claimed block below the safe head is `InvalidClaimedBlock`; equal returns the
  agreed root (trace extension); otherwise derive until the target or L1 exhaustion and
  compare the tip's output root with the claim. Intermediate output roots (boot key 9)
  are loaded but not yet checked.
- Host handler: chain data comes from a `Source` vtable (map-backed in tests; RPC later),
  checked against the requested hash before storing. Precompile, account-proof and
  starting-output hints are rejected: the Zig program runs precompiles natively and
  gets state from the payload witness plus `l2-state-node`/`l2-code`.
- Push retries: the full suite runs once; after a rejected push, rebase and run a
  compile check plus `-Dtest-filter=proof` (main moves every ~80 s, faster than the
  ~3 min suite; upstream commits were green on main). Pushes go from a separate local
  worktree so development continues meanwhile.

## Log
- 2026-11-05: host: hint handler over a chain `Source` (headers, list tries, blobs,
  code/state nodes, payload witness); providers served from an empty store in tests.
- 2026-11-05: host: preimage `Store` (keccak, ordered list tries via the new trie
  `NodeSink` hook on the hash builder, boot local keys).
- 2026-11-05: `proof/program`, `proof/driver`, `proof/client` landed (sync, driver loop
  with deposit-only retry, client prologue/epilogue, e2e over L1 exhaustion).
- 2026-11-05: program: L1 blob provider (field-element reassembly, KZG check) and L2
  chain provider (deposit-derived block info and system config).
- 2026-11-05: program: typed hints and the oracle-backed L1 chain provider (headers,
  by-number walk, ordered-trie transactions/receipts); shared `test_oracle.zig`.
- 2026-11-05: `proof/program` started: `boot.zig` (local keys 1-11, trust checks).
- 2026-11-05: `proof/executor` landed (stateless builder, oracle fallback, output root;
  e2e rebuild of node-built L2 blocks over the in-process oracle).
- 2026-11-05: `proof/mpt` landed (oracle resolver, node decode, list walker, differential
  tests vs `execution/trie`). The differential fuzz found a `SparseTrie` crash (branch
  collapsing into a witness extension with an unloaded child); fixed in `sparse.zig`.
- 2026-11-05: `proof/preimage` landed (key, channel/duplex, oracle, hint + fuzz).
