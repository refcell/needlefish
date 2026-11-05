# Lane: node

Owns `src/execution/{chainspec,txpool,payload,engine,rpc,node}` and `bin/node`.
Reference: base/base `crates/execution/*`, `bin/node`, op-reth.

## Backlog
- [x] `node/chain`: Engine backend (import, forkchoice, reorg via rollback, builder, pool).
- [x] `node/executor`: L1 + L2 block execution over evm + StateDb (deposits, L1 fees, DA footprint).
  (evm lane, 2026-11-05: OP support is on main. Set `BlockEnv.op = .{ .upgrade = ... }`, pass
  `TxEnv{ .tx_type = .deposit, .mint, .is_system_transaction }` for 0x7e and
  `TxEnv.envelope` (EIP-2718 bytes) for L1 fees; run `evm.op.apply_transition` for the Canyon
  CREATE2 deployer / Everest nonce manager on their activation blocks.)
- [x] `node/state_db`: evm Database over StateTrie + code store + block hash ring; commit of a block's evm State.
- [x] `engine/block`: payload → header, tx/withdrawals roots, requests hash, versioned hashes, block hash check.
- [x] `txpool/validate`: raw tx → pool descriptor (pooled blob form, chain id, EIP-2, intrinsic gas + EIP-7623 floor, init code, sidecar hashes, sender recovery).
- [x] `txpool/validate`: verify blob proofs with `common.consensus.sidecar.Sidecar.verify_kzg`
  (v0 sidecars; needs a long-lived `KzgVerifier`, ~1.1 MiB, from the primitives lane).
- [x] txpool: pass a `consensus.sidecar.CellVerifier` (`kzg.cells.Settings.init_verifier`) in
  `KzgVerifier.cells` so v1 (EIP-7594) sidecars are verified instead of skipped.
- [ ] txpool/evm: admit 0x79 using `common.consensus.eip8130_gas.compute` (intrinsic gas,
  `Input.worst_case` for admission/estimation, `max_payer_auth_cost` for block reservation).
- [x] Blob sidecar KZG proof verification once crypto exposes it; sidecar storage for the beacon blob API.
- [x] `chainspec`: per-chain fork activation, gas limits, base fee params; L1 mode (plain Ethereum, Cancun+/Prague+) and L2 mode (Base/OP).
- [x] Block executor (L1 + L2/OP): apply txs through evm + state provider, receipts, gas/bloom, state root via trie, block validation (header checks, base fee, blob gas, OP rules).
- [x] `txpool`: pending/queued per sender, nonce gaps, price ordering, replacement, bounded size, eviction; deposit txs never pooled.
- [x] `payload`: (attributes, payload ID, validation, extra data done) payload builder (from attributes: forced txs + pool txs, noTxPool, gasLimit, eip1559Params, minBaseFee), async build with getPayload.
- [x] `engine`: Engine API v2–v4 (+OP extensions): forkchoiceUpdated, newPayload, getPayload, JWT auth, exchangeCapabilities.
- [x] `rpc`: eth_* (chainId, blockNumber, getBalance, getCode, getStorageAt, getTransactionCount, call, estimateGas, sendRawTransaction, getBlockBy*, getTransactionBy*, getTransactionReceipt, getLogs, feeHistory, gasPrice, maxPriorityFeePerGas, getProof), net_*, web3_*, debug basics, optimism-specific methods used by op tooling.
- [x] `bin/node`: CLI flags like base/base node; `--dev-l1` mode = standalone L1 dev chain that auto-mines every `--block-time` seconds and serves a minimal beacon blob sidecar API (`/eth/v1/beacon/blob_sidecars/{slot}`, genesis, spec) so the devnet needs no external L1.
- [x] Persistence + restart, reorg handling via forkchoice.
- [ ] Performance: parallel sender recovery, prefetching, pipelined execution; gigagas/s target.
- [x] rpc: tooling methods: block tx counts, tx by block+index, uncle stubs, eth_accounts,
  web3_sha3, txpool_status.
- [x] rpc: filters (eth_newFilter/newBlockFilter/newPendingTransactionFilter,
  getFilterChanges/getFilterLogs, uninstallFilter) with bounded slots and expiry.
- [x] rpc: historical state (balance/code/storage/nonce/getProof at older blocks)
  through the trie-db history window (`db.history.Store`), `--proofs-history`.
- [x] rpc: eth_call / estimateGas at older blocks (`node.HistoryDatabase`, an evm
  `Database` over `Chain.proof_at`, read-only).
- [x] rpc: `debug_executionWitness` (proof hosts) from `db.witness` (landed by the trie-db lane: `node/witness.zig`).
- [x] txpool_content / txpool_contentFrom / txpool_inspect.

## Decisions
- chainspec is self-contained (no dependency on `common/chains`, which has not landed):
  presets copy the public base/base `ChainConfig` timestamps. When `common/chains` lands,
  build `ChainSpec` from it instead of duplicating.
- Every chain starts post-merge (Paris at genesis, London base fee at genesis).
- L2 Ethereum forks are implied by Base upgrades (Shanghai=Canyon, Cancun=Ecotone,
  Prague=Isthmus, Osaka=Azul); L2 has no blob params (OP rejects blob txs).
- `--dev-l1` default schedule: Shanghai+Cancun+Prague at genesis, Osaka off, because Osaka
  requires EIP-7594 cell-proof sidecars from the batcher.
- Fork-order validation skips unscheduled forks (mainnet leaves Pectra blob schedule unset).
- Block executor deferred until rlp/evm/trie/crypto land; txpool, payload scheduling,
  engine and rpc plumbing go first behind small interfaces.
- txpool takes a decoded `Tx` descriptor + sender `Account` from the caller (decode,
  signature recovery and state reads live in the RPC/validation layer). Raw bytes live in
  a fixed size-class slab (default ~22 MiB, largest class 1.25 MiB for 9-blob txs).
  Pending = contiguous nonces from account nonce with cumulative cost <= balance.
  Eviction when full: worst sender tail (queued first, then lowest fee cap).
- Payload IDs follow op-geth (sha256, first byte = Engine API version); L1 mode uses
  the plain alloy derivation. Subsecond blocks (Denim) are not handled yet.
- Engine handlers are transport agnostic: `Engine(Backend)` owns forkchoice + a 256-entry
  invalid-block cache; Backend executes/stores/builds. Attribute errors map like reth:
  version/fork mismatch → -38005, other attribute errors → -38003, and the forkchoice
  update is applied before attributes are checked.

## Log
- 2026-11-05: perf: execution now runs behind sender recovery (`senders.Pipeline`: workers claim 8-tx batches in order and publish per-batch done flags; the executor waits per transaction and recovers unclaimed batches itself instead of idling). Interleaved A/B of ReleaseFast bench binaries on a loaded host (load 14-25 on 14 cores): 500-transfer block median 6.2 ms vs 7.5 ms before (9 runs each). Next perf targets: commit/trie root (~2 ms of the remaining main-thread time) and spawn cost (a resident pool needs std.Io-free sync; still deferred).
- 2026-11-05: eth_call/estimateGas at older blocks: `Executor.simulate_on` swaps the evm database for a `HistoryDatabase` (proof per account/slot read; code from the head code store; BLOCKHASH from the head ring, valid for canonical ancestors). The block is resolved before the call object is parsed so historical call data stays clear of the proof buffers at the scratch tail. Context matches the head path (block N+1 on N's state) for consistency between `latest` and explicit numbers.
- 2026-11-05: txpool_content/contentFrom/inspect (reth shapes: EIP-55 sender keys sorted ascending like reth's BTreeMap, decimal nonce keys; inspect gas price is the fee cap). Pool gained a read API (`sorted_senders`, `sender_transactions`); the sorted index list lives at the tail of the RPC scratch. Oversized listings fail with the router's response-size error rather than truncating.
- 2026-11-05: historical state via `--proofs-history[.window N]` (base/base flag names; off by default, window 256). Decisions: the window is in memory only (rebuilt at the restored head after restart, as `db.history` documents); `Chain.sync_history` commits head+1, unwinds on a move back into the window, and resets the window on any other move (cross-branch reorg, durable multi-block move, full store), counted in `history_resets`; RPC serves a block only when it is canonical and the window's root at its number equals the header's, so a stale branch is never answered. Sizing: every live trie node plus `window * history_versions_per_block` (1024) versions; dense branches a quarter. Code reads use the head code store (content addressed, never deleted).
- 2026-11-05: merged with the trie-db lane's durable history (`Database` `Config.history`, `Journal.proof`): `Chain.proof_at` is the one historical entry point (journal window on durable nodes, the chain-level window otherwise); `--proofs-history` sets `limits.durable.history` when `--datadir` is given and the in-memory chain window otherwise. State reads (balance/nonce/code/storage) and eth_getProof share it via `rpc/state_view.zig`.
- 2026-11-05: batcher-devnet lane added `GET /eth/v1/beacon/blobs/{slot}?versioned_hashes=...` to the dev L1 beacon (4983c5f); the consensus blob provider uses it by default. Keep this endpoint when restructuring `node/beacon.zig`.
- 2026-11-05: polling filters (`rpc/filters.zig`): 64 slots, LRU eviction instead of reth's 5-minute idle expiry (deterministic, no clock in the rpc layer); log/block filters report canonical blocks after the head at creation (geth/reth); pending filters see hashes accepted by eth_sendRawTransaction (1024-entry ring; the node has no tx gossip yet).
- 2026-11-05: tooling RPC methods (`rpc/eth_more.zig`); backlog extended with filters, historical state, execution witness, txpool content.
- 2026-11-05: RSS finding: `std.mem.Allocator.alloc` memsets every allocation with `undefined` (0xAA) in Debug/ReleaseSafe, so every configured upper bound is resident at startup (ReleaseSafe dev L1 node 766 MiB vs 55 MiB ReleaseFast; devnet builds ReleaseSafe). Added `utilities/lazy_alloc` (rawAlloc/rawFree, no fill; pages commit on first write) and moved the node lane's large buffers (executor scratch, block stores, chain staging/build, StateDb undo ring, rpc scratch, engine API space, txpool slabs, KZG memory) plus the shared http server buffers onto it (~250 MiB fewer resident bytes). Remaining eager reservations live in trie-db (`db.State` tables, database staging/queue) and evm (`State` caches, frame stacks); those lanes can adopt the same helper. RSS samples on macOS are noisy (0xAA pages compress under pressure); compare allocations, not one `ps` reading.
- 2026-11-05: perf step 2: recovery threads claim 8-tx batches from an atomic counter (static chunks left the caller waiting on slow cores); evm lane integration fix: `State.begin_transaction` skips clearing an empty transient map (the clear memsets metadata for all 1<<18 slots every tx). 500-transfer block: 4.4-5.3 ms (noisy machine), sequential 16.7 ms. Remaining main-thread cost: state commit + trie root (~60%), EVM transact (~30%). Next idea: pipeline execution behind recovery.
- 2026-11-05: perf step 1, sender recovery. `zig build bench -Doptimize=ReleaseFast -- node:` (500 transfers, M-series laptop): sequential 17.8 ms/block (588 Mgas/s), of which recovery is 14.8 ms; with 7 recovery threads 5.26 ms (2.0 Ggas/s). `execute_block` recovers senders up front on scoped threads (`node/senders.zig`, spawn+join per block, >= 32 txs; deterministic: pure function, same result for any thread count); the builder reuses the pool's admission-time sender. `base node` uses min(cores-1, 7) threads; library/test default is 0 (inline). Decision: scoped threads instead of a resident pool, because std sync primitives need a `std.Io` and spawn cost (~tens of us) is noise next to the work it parallelizes.
- 2026-11-05: v1 (EIP-7594) blob sidecars are now KZG-verified on submission: the service's KzgMemory carries verifier-only cell settings (`kzg.cells.Settings.init_verifier`; FK20 columns untouched, so no RSS for them). A verifier without cell state still accepts v1 sidecars unchecked (tests, embedders).
- 2026-11-05: `base node --datadir DIR` persists state and chain in `DIR/node.db` (journal + A/B checkpoints, io_storage over the node's IO) and resumes from it after a restart or crash; storage callbacks run from a 2 ms IO timer. Integration addition in the trie-db lane (additive): `IoStorage.process()` = `tick()` without the re-entrant `io.tick` (calling `tick` from an IO callback corrupted the kqueue completed queue). devnet.sh unchanged: cold `up` already wipes the datadirs, so a stale chain is never reopened (and would be refused: format id carries the genesis hash).
- 2026-11-05: durable node state (`node/durable.zig`): the trie-db `db.database` owns the State, StateDb executes on it (`init_shared`), the chain journals each stored block right after execution and moves state on reorgs via database head moves (stored changesets, no re-execution). Restart restores the canonical retained blocks into the BlockStore (`Chain.restore`). Integration addition in the trie-db lane (additive): `Database.commit_applied` (insert + head move for a block whose changeset the caller already applied, one block_and_head entry; replay goes through the normal path). Decisions: the format id carries the genesis hash prefix (a datadir from another chain is refused); side branches are not restored after a restart (only the canonical retained chain); checkpoints are requested once the journal is half full.
- 2026-11-05: incident: a local smoke test ran `pkill -f "base node"` and also killed another lane's running devnet ELs (`.devnet/`). Rule for this lane: smoke tests kill their own PIDs only, never by pattern.
- 2026-11-05: StateDb now wraps the trie-db lane's `db.State` (flat tables for EVM reads + StateTrie for roots/proofs); commits go through `db.Overlay` into a `db.Changeset`, and the last blocks' encoded changesets sit in a bounded byte ring for rollback (replaces the bespoke undo journal). Step 1 of persistence: the same changesets are what `db.database` journals.
- 2026-11-05: debug_getRawHeader/Block/Receipts/Transaction; block params accept a bare 32-byte hash (geth BlockNumberOrHash). Decision: the rpc item is complete; every `optimism_*` method op tooling calls (syncStatus, outputAtBlock, rollupConfig, safeHeadAtL1Block, version) is served by the rollup node (consensus lane), and the only EL-side OP method in use, miner_setMaxDASize, is implemented.
- 2026-11-05: eth_getProof (EIP-1186) from the trie lane's prove_account/prove_storage, head state only (same rule as other state calls), proof buffers carved from the bounded RPC scratch, storage keys capped at 256 per request; keys accepted as up-to-32-byte hex or minimal quantities like geth.
- 2026-11-05: miner_setMaxDASize (batcher DA throttle) on the HTTP RPC; the L2 builder skips pool txs whose FastLZ-estimated size (base/base estimated_da_size) exceeds the per-tx limit or the cumulative per-block limit; deposits/forced txs are never limited. L2 build+import through the engine covered by a chain test (fixture now takes a spec).
- 2026-11-05: blob tx KZG proof verification on eth_sendRawTransaction (txpool.validate.verify_blob_proofs + long-lived verifier in the service, L1 mode). Decision: EIP-7594 cell proofs accepted unverified until the crypto lane exposes cell verification (Osaka off on the dev chain). KZG test is release-only, like the crypto lane's.
- 2026-11-05: executor OP mode: BlockEnv.op from the upgrade schedule, deposits (mint, deposit nonce/receipt version), Regolith deposit gas accounting, Jovian DA footprint as blob gas used, Canyon create2 deployer (base/base timestamp-2 heuristic) and Everest nonce-manager transitions, no EIP-7685 requests on L2, L2 envelopes passed for L1 fees. Decision: Denim BaseTime predeploy transition skipped (not in the evm's Transition set yet).
- 2026-11-05: Engine API JSON (rpc/engine_json + rpc/engine): fcU V1-3, newPayload V1-4, getPayload V1-4 (OP envelope with parentBeaconBlockRoot), exchangeCapabilities, getClientVersionV1; authrpc also serves eth_*. JWT-checked authrpc server in Service; `--authrpc.port/--authrpc.jwtsecret` in `base node`. Builder/follower JSON agreement test. Raised the rpc Router comptime branch quota (io-net lane, integration fix).
- 2026-11-05: `base node` binary (flags per etc/devnet/devnet.sh): --dev-l1 mines and serves beacon API; smoke-tested with curl. Decisions: state in memory, --datadir created but unused; devnet-sized default limits (~485 MB RSS ReleaseSafe); past slots since genesis are mined back-to-back at startup.
- 2026-11-05: node/service: Service(IO) owns the whole node, eth HTTP server, dev-L1 slot miner (one block per slot through the Engine API, head=safe=finalized) and beacon API; blob sidecars captured from the pool before FCU prunes them. SimIo e2e tests.
- 2026-11-05: ChainSpec from genesis config, genesis loader into StateDb; test proves our L1/L2 genesis hashes equal the devnet rollup.json anchors. Decision: blobSchedule not parsed yet, standard Cancun/Prague params used.
- 2026-11-05: eth/net/web3 JSON-RPC (`src/execution/rpc/eth.zig`): values, state (head only), blocks, txs, receipts, sendRawTransaction, call/estimateGas (executor simulate), getLogs, feeHistory (zero rewards). Chain tx-hash index (bounded ring). Shared node test fixture.
- 2026-11-05: chain backend for Engine(Chain): payload import (header checks, execution, root checks, rollback on mismatch), forkchoice canonicalization with state moves (undo rollback + re-execution, depth 256), payload builder (attributes txs + txpool, blob sidecars stripped), pool pruning. Decisions: reorged-out txs are not re-injected into the pool; L1 gas limit stays at the parent's when building.
- 2026-11-05: executor split into begin/apply/finish (builder can skip bad txs); bounded block store ring; engine InsertResult/forkchoice gain `syncing` for unreachable state.
- 2026-11-05: state db undo journal (bounded ring, per-block rollback) for root mismatches and reorgs. Decision: a storage wipe of pre-existing storage (impossible post-Cancun/EIP-7610) drops undo history instead of logging every slot.
- 2026-11-05: L1 block executor (system calls, withdrawals, Prague requests, receipts, bloom, state root); OP deposits pending evm OP support.
- 2026-11-05: node state db (evm backend, block commit to state trie).
- 2026-11-05: engine payload well-formedness (block hash verification).
- 2026-11-05: txpool stateless validation over common/consensus envelopes.
- 2026-11-05: engine types, method/fork versioning, Engine(Backend) handlers, fuzz.
- 2026-11-05: payload attributes, op-geth-parity payload IDs, version/fork validation.
- 2026-11-05: txpool (fixed-capacity pool, slab, replacement, eviction, select, fuzz).
- 2026-11-05: chainspec (fork schedule, EIP-1559 + Holocene/Jovian extra data, blob params).
- 2026-11-05 (crypto lane): cell verification is on main: `crypto.kzg.cells.verify_cell_kzg_proof_batch` with `cells.Settings.init_verifier` (1 ms init, no FK20 tables) and `cells.VerifyStorage(n)` scratch; 128 cells verify in ~12 ms. Once `consensus.Sidecar.verify_kzg` stops returning `CellProofsUnsupported` (see primitives.md note), `txpool.validate.verify_blob_proofs` can drop its accept-unverified branch.
