# Lane: node

Owns `src/execution/{chainspec,txpool,payload,engine,rpc,node}` and `bin/node`.
Reference: base/base `crates/execution/*`, `bin/node`, op-reth.

## Backlog
- [x] `node/executor`: L1 block execution over evm + StateDb (deposit txs/L1 fees: pending).
- [x] `node/state_db`: evm Database over StateTrie + code store + block hash ring; commit of a block's evm State.
- [x] `engine/block`: payload → header, tx/withdrawals roots, requests hash, versioned hashes, block hash check.
- [x] `txpool/validate`: raw tx → pool descriptor (pooled blob form, chain id, EIP-2, intrinsic gas + EIP-7623 floor, init code, sidecar hashes, sender recovery).
- [ ] `txpool/validate`: verify blob proofs with `common.consensus.sidecar.Sidecar.verify_kzg`
  (v0 sidecars; needs a long-lived `KzgVerifier`, ~1.1 MiB, from the primitives lane).
- [ ] Blob sidecar KZG proof verification once crypto exposes it; sidecar storage for the beacon blob API.
- [x] `chainspec`: per-chain fork activation, gas limits, base fee params; L1 mode (plain Ethereum, Cancun+/Prague+) and L2 mode (Base/OP).
- [ ] Block executor: apply txs through evm + state provider, receipts, gas/bloom, state root via trie, block validation (header checks, base fee, blob gas, OP rules).
- [x] `txpool`: pending/queued per sender, nonce gaps, price ordering, replacement, bounded size, eviction; deposit txs never pooled.
- [ ] `payload`: (attributes, payload ID, validation, extra data done) payload builder (from attributes: forced txs + pool txs, noTxPool, gasLimit, eip1559Params, minBaseFee), async build with getPayload.
- [ ] `engine`: (handlers/versioning/forkchoice rules done; JSON + JWT wiring pending io-net) Engine API v2–v4 (+OP extensions): forkchoiceUpdated, newPayload, getPayload, JWT auth, exchangeCapabilities.
- [ ] `rpc`: eth_* (chainId, blockNumber, getBalance, getCode, getStorageAt, getTransactionCount, call, estimateGas, sendRawTransaction, getBlockBy*, getTransactionBy*, getTransactionReceipt, getLogs, feeHistory, gasPrice, maxPriorityFeePerGas, getProof), net_*, web3_*, debug basics, optimism-specific methods used by op tooling.
- [ ] `bin/node`: CLI flags like base/base node; `--dev-l1` mode = standalone L1 dev chain that auto-mines every `--block-time` seconds and serves a minimal beacon blob sidecar API (`/eth/v1/beacon/blob_sidecars/{slot}`, genesis, spec) so the devnet needs no external L1.
- [ ] Persistence + restart, reorg handling via forkchoice.
- [ ] Performance: parallel sender recovery, prefetching, pipelined execution; gigagas/s target.

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
