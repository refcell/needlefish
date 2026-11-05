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
- [x] `proof/e2e`: node-built L2 blocks (derived attributes + user transfers), batcher
  frames signed to the inbox on L1, everything served through the host handler from an
  empty store; the client derives + executes to the claim and matches the node's output
  root (`client/e2e_test.zig`).
- [x] `proof/e2e-2`: extend the e2e: epoch change across L1 blocks, span batches, blob
  batches (l1-blob through the host), a Holocene deposit-only retry (invalid user tx in a
  batch).
- [x] `proof/e2e-3`: e2e intermediate output roots (boot key 9); a host witness for the
  attempted payload, so a deposit-only retry can follow valid user txs that read state.
- [x] `proof/host`: bounded store + boot keys, hint handler over a `Source`, canonical
  archive, offline replay, JSON-RPC source, beacon blobs (`beacon_blobs.zig` over the
  consensus `BlobProvider`; `proof run --l1-beacon`). No fd mode (see Decisions).
- [x] `bin/base proof`: `replay <archive>` (offline) and `run` (native mode against
  L1/L2 execution RPCs; boot values from `--agreed`/`--claimed` headers, output roots
  from state root + withdrawals root; `--out` records the archive).
- [x] `proof/devnet-proof`: `etc/proof/devnet-proof.sh [blocks]` proves the verifier's
  safe head on the running devnet, replays the archive, and checks a wrong claim fails.
  First live run: agreed 100 -> claimed 140 holds (791 preimages, 40 s).
- [x] `proof/host-speed`: the cost was re-served hints (2191 calls for 367 preimages on
  10 blocks), not IO: the handler skips hints it already served. 40 blocks: 40 s -> 1.2 s
  (506 calls).
- [x] `proof/contracts`: ABI codec (static words + `bytes`, strict decode) and call/return
  codecs for DisputeGameFactory (packed extraData, game lookup key, createWithInitData),
  AnchorStateRegistry, DelayedWETH; fuzzed.
- [x] `proof/rpc`: blocking `Endpoint` (pump-driven `rpc.Client`, bounded steps, per-call
  arena) shared with the host source; typed execution calls (block number, raw headers by
  number/tag/hash, `eth_call`, balance) and rollup calls (`optimism_syncStatus`,
  `optimism_outputAtBlock`); canned-server SimIo test.
- [x] `proof/proposer`: pure logic + pipeline state machine (intervals, targets, recovery
  walk, dispatcher, collector/submitter) over injected chain/prover/submitter interfaces,
  in-memory fakes, DST with prover faults and L1 reorgs (`src/proof/proposer/`).
- [x] `proof/proposer-adapters`: `Chain` over `src/proof/rpc` (`proposer/rpc_chain.zig`:
  rollup `syncStatus` / `outputAtBlock`, `getAnchorRoot`+`anchorGame` pinned to one L1
  block, factory `gameCount`/`games`/`gameImpls`, verifier `version` +
  `intervalsForStartingBlock` with the legacy getters below 0.3.0). The `Prover` client
  comes with `proof/prover-service`.
- [x] `proof/proposer-txmgr`: `Submitter` over JSON-RPC (`proposer/tx_submitter.zig`):
  init bond from `initBonds`, `eth_estimateGas`, EIP-1559 signing via `batcher/txdata`,
  receipt polling, revert classification (data selector, selector text, error name) of
  estimation errors and replayed failed receipts; dropped after N empty polls.
- [x] `bin/base proposer`: `proposer/config.zig` (base/base `cli.rs`/`config.rs` flags,
  defaults, validation; fuzzed), dry-run submitter, `--prover-rpc native` (in-process
  native prover over the L1/L2 endpoints), JSON-RPC submitter from `--private-key`,
  pipeline ticked by the IO clock (`--ticks-max` for smoke runs). Dry-run smoke on the
  devnet (no factory deployed there, so nothing to propose).
- [x] `proposer` provers: `--prover-rpc <url>` through the prover-service
  `ProposerProver`, `--l1-beacon` blob reads for the native prover (shared with
  `proof run` in `bin/base/beacon.zig`).
- [ ] `proposer` health/metrics/admin endpoints (base/base `health_addr`, `admin_addr`).
- [x] `proof/challenger` (core): AggregateVerifier codecs; scanner/classification,
  output-root validator, TEE/ZK dispute attempt state machine with ZK fallback, proof
  manager, bond resolve/unlock/withdraw, anchor updater, `Driver.tick(now)` over
  injected vtables; seeded simulation against an in-memory world.
- [x] `proof/challenger` network adapters: `ChainView` over `src/proof/rpc`
  (`challenger/rpc_chain.zig`: factory `gameCount`/`gameAtIndex`/`games`/`gameImpls`,
  AggregateVerifier getters with per-proxy version-gated intervals, `getAnchorRoot` +
  `anchorGame` pinned to one L1 block, registry preflight/finality, DelayedWETH
  `delay`/`withdrawals`, L1 block number from a hash-checked raw header, L2 raw headers).
- [ ] `proof/challenger` prover client: `Prover` over the prover-service JSON-RPC with the
  `base/challenger/proof-session/v2` session ids, once `proof/prover-service` defines the
  protocol on main.
- [x] `proof/challenger` submission: shared `src/proof/submission/` (`Sender`: estimate,
  EIP-1559 signing with value via `batcher/txdata`, broadcast, receipt polling, failed
  receipt replay, revert data from `Endpoint.last_error`; `classify` through
  `aggregate_verifier.classify_revert`, selector text and error names). The proposer's
  `TxSubmitter` and the challenger's `challenger/tx_submitter.zig` sit on it.
- [ ] `proof/submission` fee bumping: resubmit a stuck transaction at the same nonce with
  bumped fees (base/base `TxManager`); today a dropped transaction is retried by the
  caller with a fresh nonce.
- [ ] `bin/base challenger`: CLI/config wiring, real IO loop calling `Driver.tick`.
- [x] `proof/witness`: recording fetcher (base/base `host/src/recording.rs`): the witness
  holds exactly the preimages the client read; `native.run(.., witness)`; `proof run
  --out` writes it; e2e replays the witness alone with hints ignored.
- [x] `proof/e2e-fuzz`: seeded random e2e scenarios (1..6 blocks, epoch split, batch and
  data kind, invalid last-block tx, interval, right or wrong claim) proven against the
  node, with intermediate roots checked; 12 seeds in `zig build test`.
- [x] `proof/prover-service`: port `prover-service` + `worker` (proof request JSON-RPC
  contract, job lifecycle) with the native host as the in-process prover backend
  (`src/proof/prover_service/`: protocol + strict codec, bounded job store, router
  service, requester/worker clients, proposer `Prover`, worker tick, native backend).
- [ ] `proof/prover-service-bin`: `base prover-service` / `base prover-worker` commands
  (HTTP listen, flags) and the proposer wired to `ProposerProver`.
- [ ] `proof/prover-service-native-e2e`: native backend proving a real range end to end
  (SimIo node RPC + `RpcSource`), proof bytes replayed with `base proof replay`.

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
  compare the tip's output root with the claim.
- Intermediate output roots (boot key 9): in base/base only the TEE/ZK provers use them
  (`execute_with_intermediates` + `IntermediateRootSampler`, committed in the proof
  journal); the fault-proof client never checks them. The Zig client samples them the
  same way when `Options.intermediate` is set (`program/intermediate_roots.zig`, bounded
  at 8192 roots); an empty or non-dividing range reports an error from `finish` and does
  not affect the claim. Boot checks the schedule block (key 11) is at or above the claim,
  and the claim at or above L2 genesis. Proposer (key 8) is loaded only. Not ported:
  `ScheduleId::pin` (no journal consumer yet) and the boot's Zenith/Everest/zero-time
  rejections.
- Attempted-payload witness: a deposit-only retry after valid user txs needs the witness
  of executing the attempted attributes (the transfers read state the deposit-only block
  does not). The e2e source serves it for attributes with user txs (built on the node as
  a side block of the valid prefix, `debug_executePayload` style); the RPC source still
  asks for the canonical child's witness, so such a block fails there with a missing
  preimage (sound, not complete).
- Host handler: chain data comes from a `Source` vtable (map-backed in tests; RPC later),
  checked against the requested hash before storing. Precompile, account-proof and
  starting-output hints are rejected: the Zig program runs precompiles natively and
  gets state from the payload witness plus `l2-state-node`/`l2-code`.
- Offline replay uses one canonical archive file (`host/archive.zig`, "NFPA": sorted
  keys, LE lengths, strict decoder) instead of a disk KV store; the CLI reads and writes
  it through `utilities.io`.
- RPC source: raw `debug_getRaw*` encodings (no JSON re-encoding); the payload witness is
  `debug_executionWitness(parent + 1)` of the canonical child (base/base calls
  `debug_executePayload`, which the needlefish node lacks); on a dishonest chain the client
  fails with a missing preimage instead of proving a wrong state. Blobs and single
  preimages are `NotFound` until the beacon client exists.
- Holocene deposit-only retry only on block-validity errors (invalid tx, block/blob gas
  exceeded, unsupported type), as base/base; resource bounds, missing preimages and hint
  failures fail the proof, since a retry would replace a valid block with a wrong one.
- Custom chains (base/base `BootInfo`): an unknown L2 chain id takes the host's rollup
  config as is, and an unknown L1 its config from boot key 7 (geth chain config JSON);
  the execution spec comes from the rollup config (OP cascade, `chain_op_config`, genesis
  gas limit). Known chains keep the identity check.
- Host has no separate-process fd mode: base/base `crates/proof/host` runs its
  `PreimageServer` in-process over channels only (`start_server(hint, preimage)`); so does
  `host.native.run`. A pipe transport can be added if a FPVM target needs it.
- Proposer (port of base/base `crates/proof/proposer`): one tick-driven state machine
  (`Pipeline.tick(now_ns)`, once per poll interval) instead of two async loops; the
  dispatcher and collector share one recovery cache and a restart clears it, both cursors
  and the dispatch ring. Dispatch runs at most `proofs_in_flight_max` targets ahead
  (fixed ring, base/base is unbounded); a recovered state on the dispatched path keeps the
  ring, any other resets it. Recovery walks at most `walk_steps_max` games per tick.
- Proposer submission is asynchronous (one creation in flight, polled per tick; the game
  is then looked up by key up to 3 times, as base/base's `lookup_recent_game`). A game that
  already exists for the key is adopted as the parent: base/base also attaches its TEE
  proof to it (`verify_proposal_proof`), which is left out with the TEE/ZK proof formats,
  the prover-service retry-exhausted reset, the admin start/stop API, metrics and the
  L1-head check of an existing game. Failure mapping follows `submission_error_action`:
  invalid signer / parent / L1 origin discard and re-prove, other failures restart with the
  proof kept, a submit timeout restarts (recovery finds a late landing).
- Proposer recovery skips rereading the factory while the finalized head is below the
  cached next target (base/base `try_recover_and_plan`), so an L1 reorg of the newest games
  is noticed only once the finalized head passes the next target (or a submission fails);
  the DST keeps the finalized head growing after its last reorg for that reason.
- Proposer proof L1 head is the rollup node's `finalized_l1`, rejected (tick retried) when
  below the finalized L2 head's L1 origin (`SyncStatus.finalized_l2_origin`), as base/base
  `select_l1_head`.
- Proposer native prover (`proposer/native_prover.zig`): an in-process `Prover` that runs
  `host.native.run` per request and returns the recorded witness archive as `initData`
  with the sampled intermediate roots; it stands in for base/base's TEE/ZK prover service
  so `base proposer` runs end to end. Requests are proven synchronously in `request` (a
  tick blocks for the proof); at most 8 sessions.
- `base proposer` with the native prover sends the witness archive as `initData`
  (calldata cap raised to 4 MiB): L1 nodes cap transactions near 128 KiB, so this mode is
  for local chains; real deployments use a prover service with compact proofs.
- Proposer submitter is its own small JSON-RPC sender, not the batcher `TxManager`: the
  batcher's manager is built around inbox payloads (fixed `to`, no value, no gas
  estimation, no revert data), while a game creation needs the bond as value and the
  revert selector. No fee bumping: a dropped creation fails, and the pipeline's restart
  re-proposes at a fresh nonce (base/base's `TxManager` resubmits in place).
- Challenger (port of `crates/proof/challenge/src`): pure state machines over three
  injected vtables (`chain.ChainView` reads, `Prover` request/poll, `Submitter`
  send/status); `Driver.tick(now_ns)` is the only entry point. Ported: `scanner.rs`
  (`GameCategory`, anchor index search in 1024-game backward batches, fully nullified
  games filtered first), `validator.rs` (roots from raw L2 headers via
  `host/native.output_of`; header-hash/account-proof checks not needed since the header
  is hashed locally), `dispute_attempt.rs` (TEE first, ZK fallback after the TEE submit
  retry limit, reprove on timeout/failure), `proof_manager.rs` (3 retries; slot table of
  64 attempts and a 1024-entry FIFO ignore list instead of 10 000), `bond.rs`,
  `anchor.rs`, `config.rs`, and `contracts/aggregate_verifier.rs` (codecs, known reverts,
  fork-aware interval gate). base/base awaits each transaction inline; here transactions
  are queued and polled, and a game with a pending transaction is never sent another, so
  steps are never duplicated. Not ported: metrics, `attempt_reporter`, `service`, `cli`,
  admin RPC, and the network adapters (backlog items above).
- Challenger simulation (`challenger/sim_test.zig`): proposer with fraudulent siblings,
  an attacker filing fraudulent ZK challenges against honest games, external resolvers,
  and seeded prover/read/tx faults and latencies. The fake verifier counts disputes of
  valid roots, so the invariants (never dispute a valid game, every invalid game disputed
  once per bad proof, honest games win, bounded queues, bonds withdrawn exactly once)
  are checked by the world, not by the driver under test. 4 seeds (~6 s debug).
- Push retries: the full suite runs once; after a rejected push, rebase and run a
  compile check plus `-Dtest-filter=proof` (main moves every ~80 s, faster than the
  ~3 min suite; upstream commits were green on main). Pushes go from a separate local
  worktree so development continues meanwhile.
- Challenger network adapters: every failed read (transport, JSON-RPC error, revert,
  decode) maps to `ChainUnavailable`; only `debug_getRawHeader` by number answering
  `NotFound` (null or an RPC error) maps to `BlockNotAvailable`. `l1_block_number` reads
  `debug_getRawHeader` by hash and checks keccak(raw) against the hash before decoding.
  Interval pairs are returned unchecked (callers already validate them). The challenger
  `Prover` adapter waits for the prover-service protocol (not invented here).
- `src/proof/submission/` holds the generic `Sender` (failures carry the JSON-RPC phase:
  estimate, broadcast, replay) and one classifier for both tools. The proposer maps
  `AlreadyProven`/`InvalidProof` to a plain revert (it never sees them); the challenger
  maps an unknown revert to `execution_reverted` at estimation, `tx_reverted` on replay,
  `other` at broadcast; dropped and transport failures are `other`. Challenger
  transactions carry no value. The classifier keeps the whole-name match for every error
  (base/base uses substring matching for all but `InvalidProof`).

## Log
- 2026-11-05: `base proposer --prover-rpc <url>` and `--l1-beacon`.
- 2026-11-05: `base proposer` (native prover, dry-run, JSON-RPC submitter).
- 2026-11-05: proposer native prover (witness archive as initData), e2e replayed.
- 2026-11-05: proposer checks the proof L1 head against the finalized L2 origin.
- 2026-11-05: proposer config (flags + validation) and dry-run submitter.
- Prover service job store is a bounded in-memory table (fixed `jobs_max`, per-job proof
  and root buffers allocated at init) instead of Postgres: same lifecycle (queued ->
  claimed with lease and heartbeat -> succeeded/failed/cancelled), claim order (start
  block, then creation), reclaim of expired leases up to the retry budget, idempotent
  `proveBlockRange` keyed by session id, and the same error codes and messages. Jobs do
  not survive a restart. Time comes from an injected `Clock`; expiry runs per request.
- Prover service leaves out: `deleteProofsByTeeSigner` (needs the TEE signer registry),
  `ExecutionStats`, metrics, the status poller (backends here finish inside `start`, so
  there is no external session to poll), and the SP1 cluster/network and Nitro enclave
  backends. Worker runs one job at a time (base/base's default) as a `tick` state machine;
  base/base's async retry/backoff is the caller's tick loop.
- Prover worker native backend proves `compressed` range requests with the native host
  and returns the recorded witness archive as the proof bytes: not succinct, but anyone
  can re-check the claim with `base proof replay`. TEE requests are `Unsupported` there
  (the worker abandons them); the proposer side still speaks the TEE result shape
  (`ProposerProver` turns an AWS Nitro result into the 130-byte `initData`).
- `proof/rpc` `Endpoint` params gained a `raw_json` variant so the prover clients send
  codec-encoded request objects as the single param.

## Log
- 2026-11-05: `proof/prover-service`: protocol/codec, bounded job store, JSON-RPC
  service, clients, proposer `Prover`, worker tick, native backend, SimIo e2e.
- 2026-11-05: `proof/proposer-txmgr`: proposer tx submitter with revert classification.
- 2026-11-05: `proof/proposer-adapters`: RPC `Chain` for the proposer, canned-RPC tests.
- 2026-11-05: `proof/proposer` first slice: intervals, recovery walk, dispatcher/collector
  pipeline over injected interfaces, fakes, ported recovery tests, DST with L1 reorgs.
- 2026-11-05: `proof/e2e-fuzz`: e2e block count is per scenario; 12 random seeds pass.
- 2026-11-05: `proof/witness`: recorded witness replays alone (e2e + live devnet).
- 2026-11-05: `proof/e2e-3` landed: intermediate output roots sampled at boot key 9 (e2e:
  every block, the full range, a non-dividing interval, the trace extension); boot rejects
  a schedule block below the claim; a deposit-only retry after valid transfers proven from
  the attempted payload's witness (and failing without it).
- 2026-11-05: host beacon blobs: blocking adapter over the consensus blob provider;
  `proof run --l1-beacon`; devnet script passes the beacon.
- 2026-11-05: `proof/rpc`: blocking endpoint + typed L1/L2/rollup calls; host source on it.
- 2026-11-05: `proof/contracts`: ABI codec and dispute-game contract call codecs.
- 2026-11-05: host: served-hint dedupe; live 40-block proof 40 s -> 1.2 s.
- 2026-11-05: custom chains in boot/client; first live devnet proof holds and replays.
- 2026-11-05: `base proof run`: native mode over RPC, records a replayable archive.
- 2026-11-05: driver: deposit-only retry limited to block-validity errors (soundness).
- 2026-11-05: host: RPC-backed source over the node's debug endpoints (SimIo HTTP test).
- 2026-11-05: `base proof replay <archive>`: offline client run over a recorded archive.
- 2026-11-05: host: canonical preimage archive for record/replay (strict decoder, fuzz).
- 2026-11-05: `proof/e2e-2` landed: e2e scenarios for an epoch change, span batches
  (also across the epoch change), blob-carried frames (real KZG commitment, host
  `l1-blob`), and a Holocene deposit-only retry (fee cap below base fee, rejected
  before state reads; the fixture serves one witness per parent, the node's
  deposit-only block's, so the invalid tx goes first in its batch).
- 2026-11-05: `proof/e2e` landed: real derive + execute of 3 L2 blocks through the host.
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
- 2026-11-05: `proof/challenger` core landed (AggregateVerifier codecs, scanner,
  validator, dispute attempts with ZK fallback, bonds, anchor updater, driver, seeded
  simulation). Network adapters, txmgr submission and `bin/base challenger` remain.
- 2026-11-05: `proof/challenger` network adapters and submission landed (`rpc_chain.zig`
  ChainView, shared `src/proof/submission/` sender + classifier under the proposer and
  challenger submitters). Prover client and fee bumping remain.
