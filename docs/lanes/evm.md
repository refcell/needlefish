# Lane: evm

Owns `src/execution/evm`. Reference: revm, op-revm, base/base `crates/execution/evm`,
`crates/common/evm*`, `crates/common/precompiles`.

## Backlog
- [x] Core interpreter: stack (fixed 1024), memory (bounded, expansion gas), bytecode analysis (jumpdest bitmap, cached), dispatch via tail-call/computed-goto style switch; all opcodes through Cancun/Prague/Osaka (PUSH0, MCOPY, TLOAD/TSTORE, BLOBHASH, BLOBBASEFEE, CLZ...).
- [x] Gas schedule per fork, warm/cold access lists (EIP-2929), refunds (EIP-3529), SSTORE net metering (EIP-2200), call gas 63/64, init-code limits (EIP-3860).
- [x] `Host`/state interface (account, storage, code, block hashes, logs, journal with revert checkpoints) — define here as a small Zig interface; trie-db lane implements the backend. Include an in-memory backend for tests.
- [x] CALL/CALLCODE/DELEGATECALL/STATICCALL/CREATE/CREATE2/SELFDESTRUCT (EIP-6780) with explicit frame stack (no recursion), max depth 1024.
- [x] Transaction-level execution: intrinsic gas, nonce/balance checks, EIP-1559 fee handling, blob txs, EIP-7702 authorizations, access lists, coinbase/base-fee payments.
- [x] OP-stack semantics: deposit tx processing (mint, no fee, gas accounting by fork, failed-deposit nonce bump), L1 cost charging to L1FeeVault, BaseFeeVault/SequencerFeeVault, operator fee (Isthmus), Base-specific changes in base/base.
- [x] Base fork changes: RIP-7212 P256VERIFY at Fjord (3450 gas) until Osaka pricing (Azul);
  Canyon CREATE2-deployer and Everest nonce-manager transitions (`op.apply_transition`).
- [x] BN254 pairing input caps (Granite 112687, Jovian 81984 bytes) and BLS MSM/pairing caps
  (Isthmus/Jovian).
- [x] Native precompile framework (`native.zig`) and Cobalt tx-context 0x8130..aa02 and 2D
  nonce manager 0x8130..aa01 getters.
- [x] Beryl ActivationRegistry 0x8453..01 (Cobalt value gate and state-backed admin).
- [x] Beryl PolicyRegistry V1 0x8453..02 (`native_policy.zig`, alloy-compatible decoder in
  `native_abi.zig`).
- [x] PolicyRegistry V2 (Cobalt: composite policies, children arrays with tail cleanup) and
  V3 (Denim: inverted policy ids).
- [x] Base native precompiles (Beryl+: B20 factory, B20 tokens). Breakdown (base/base
  `crates/common/precompiles/src`, non-test lines): common core storage/accounting/ops
  (~1k), factory (~1k: dispatch, variant address derivation, logic v1), Asset V1/V2/V3
  (~3.5k), Stablecoin V1/V2/V3 (~2.5k), dynamic lookup (`lookup.rs`, 0xb2-prefixed
  addresses, marker-code check from Cobalt). Order: core + factory + Asset V1 first.
  Files: `native_b20.zig` (core storage at ERC-7201 `base.b20`: name 0, symbol 1, URI 2,
  supply 3, balances 4, allowances 5, roles 6, role admins 7, admin count 8, packed transfer
  policy ids 9 (sender/receiver/executor u64 lanes), mint receiver policy 10, paused 11,
  supply cap 12 (max 2^128-1), permit nonces 13, seize policy ids 14; role/policy/pause ops,
  metered keccak), `native_b20_asset.zig`, `native_b20_stablecoin.zig`,
  `native_b20_factory.zig` (0xB20F00..00), lookup of 0xb2 addresses in `native.lookup`.
  Done (Beryl surface complete): core (`native_b20.zig`), tokens (`native_b20_token.zig`:
  IB20 V1 for both variants, variant from the address; asset extension incl. permit,
  eip712Domain, announce with privileged internal calls; stablecoin `currency()`, fixed 6
  decimals, root `base.b20.stablecoin` 0x35827975..6200), factory (`native_b20_factory.zig`
  at 0xB20F00..00, warmed from Beryl: createB20 for both variants, getB20Address, isB20,
  isB20Initialized). V2 (Cobalt) and V3 (Denim) done: `Version` picks the table surface
  (entries carry `since`), V3 logic (token address is an invalid receiver for transfer/
  transferFrom/mint/seize; executor policy always checked, sender skipped when caller ==
  from and the executor and sender ids match) is gated on the upgrade in `native_b20`.
  The factory stays V1 on every fork (base `FactoryVersions`). Base's B-20 lookup has no
  marker check; uninitialized tokens revert empty inside the precompile (as here).
  V2 (Cobalt) delta, from base logic/v2.rs: common adds SEIZE_ROLE, SEIZE_EXEMPT_POLICY,
  SEIZE_RECEIVER_POLICY, seizeWithMemo (pause feature SEIZE=3, enum max 3; ensure seizable =
  fails seize-exempt policy; seize-receiver policy on `to`; from==to InvalidReceiver; Memo
  then Seized(caller,from,to,amount)), AccountNotSeizable; policyId/updatePolicy accept seize
  scopes; transfer/transferFrom check zero addresses first then read the packed transfer
  policy ids once (one SLOAD of slot 9); permit/domainSeparator use metered keccak (30+6/word
  each) plus 3000 recovery gas. Asset adds pending UI multiplier (slot 4: u128 multiplier,
  u64 effective-at at byte 16), MAX_UI_MULTIPLIER 2^128-1, uiMultiplier/newUIMultiplier/
  effectiveAt/balanceOfUI/totalSupplyUI/toUIAmount/fromUIAmount, updateUIMultiplier,
  cancelUIMultiplierUpdate, supportsInterface (ERC-165 + ERC-8056 ids), effective
  multiplier (matured pending wins) in scaling, updateMultiplier clears pending and emits
  UIMultiplierUpdateCancelled (if live) + MultiplierUpdated + UIMultiplierUpdated.
  Decisions: token init checks and factory account reads are metered like base
  `with_account_info` (100, +2500 cold); an unset multiplier reads as WAD; permit V1 uses
  unmetered hashing and no 3000-gas recovery charge, rejects high s (k256); factory init
  call failures that are panics, decode errors, unknown selectors, or empty reverts become
  InitCallFailed(index), custom errors propagate (`Context.revert_custom`).
  Also EIP-8130 (Everest, type 0x79: tx-context transient slots, nonce increments).
- [x] Precompile dispatch wired to `common.crypto` with per-fork sets and gas: all of
  0x01-0x11 and P256VERIFY (0x100).
  (crypto lane, 2026-11-05: all now on main: `crypto.bn254.precompile_bn254_{add,mul,pairing}`,
  `crypto.kzg.precompile_point_evaluation`, `crypto.bls12_381.precompile.{run,gas}` with an
  `Address` enum for 0x0b-0x11. Every error = precompile failure, all gas consumed.)
- [x] ethereum/tests GeneralStateTests runner (`just vectors`), pass rate tracked in this file.
  Run: `just vectors`, extract `fixtures_general_state_tests.tgz` into `.cache/vectors/state`, then
  `zig build statetest -Doptimize=ReleaseSafe -- .cache/vectors/state/GeneralStateTests`.
  2026-11-05: 37724 / 37724 (100%), Cancun + Prague fixtures (EEST GeneralStateTests).
- [x] (from crypto lane) Pre-Osaka MODEXP with modulus > 1024 bytes: routed to
  `precompile_modexp_run_with_scratch` with an EVM-owned scratch arena sized by
  `Config.modexp_modulus_bytes_max` (576 KiB default covers ~1e9-gas transactions).
- [x] Differential fuzzing harness (random bytecode, seeded) + `std.testing.fuzz` targets.
  `evm_fuzz.zig`: random programs as transactions on every fork; oracles are interpreter
  asserts, determinism, gas bounds, no ether creation, and revert atomicity. 300k-iteration
  ReleaseSafe soak clean. The GeneralStateTests are the differential check against the
  reference clients (zero dependencies rules out linking another EVM).
- [x] Performance: micro benchmarks (`evm/bench.zig`, results in docs/PERF.md).
- [x] EIP-8130 execution (Everest, type 0x79). The tx type, structure checks, and intrinsic
  gas live in `src/common/consensus/eip8130*.zig` (common lane); the EVM side mirrors base
  `crates/execution/eip8130/src` (~8k non-test lines) and `crates/common/evm2/src`
  (`everest.rs`, `transaction.rs`, `handler.rs`). Order: (1) AccountConfiguration storage
  (`account_config.rs`: actor configs, policies) as `eip8130_config.zig`; (2) authenticator
  verification (`verify.rs`); (3) config-change authorization (`authorize.rs`); (4) the
  account-changes apply step (`apply.rs`: authorize/revoke/create, CREATE2 address,
  delegation indicator, `IAccountConfiguration` logs); (5) validate/fee/payer/dispatch
  (`validate.rs`, `fee.rs`, `dispatch.rs`) and nonce-manager integration; (6) wire 0x79
  into `transaction.zig` from Everest with receipts.
  Done: (1) `eip8130_config.zig` (packed ActorConfig/AccountState words, slot derivation,
  journaled unmetered `Store`); (2)+(3) `eip8130_auth.zig` (scopes, resolved actors,
  k1/P-256/WebAuthn/delegate dispatch with the canonical-ABI WebAuthn guard and low-s
  P-256, one-hop delegation without recursion, sender/payer `verify`, config-change
  `authorize_changes` with channel sequences and the changes digest); (4)
  `eip8130_apply.zig`; (5) `eip8130_tx.zig` + `eip8130_nonce.zig` (journaled 2D nonce
  manager, expiring-nonce replay ring); (6) `eip8130_execute.zig` mirrors base
  `crates/common/evm/src/eip8130.rs`: pre-call pipeline, payer pre-charge with L1/operator
  fees, atomic call phases from one gas pool with the policy gate, settlement to the four
  recipients, `Executed.committed_phases` for the receipt. Keystore (full config changes and
  non-k1 actors) turns on at Zenith; Everest runs `authorize_without_keystore`.
  `eip8130_simulate.zig` covers `eth_call`/`eth_estimateGas` (unsigned, from the request's
  `from`; estimate binary-searches the call pool for EIP-150 forwarding).
  End-to-end tests cover self-pay, open-payer sponsorship, phase rollback, rejections, 2D
  nonces, and a Zenith config change authorizing an actor that then signs.
  Left: the node lane must map consensus 0x79
  envelopes to `TxEnv{ .tx_type = .eip8130, .eip8130 = &signed, .envelope = raw }` and
  wire RPC estimation to `eip8130_simulate.simulate`.
- [x] Performance: snailtracer contract workload (`just vectors` fetches revm's public fixture;
  `evm: snailtracer` in `zig build bench`, ~50 ms / 166M gas, docs/PERF.md).
- [x] Performance: profile snailtracer (interpreter loop ~80%, memory ops ~15%, keccak ~2%;
  docs/PERF.md).
- [x] Performance: erc20/storage path — `StorageKeyContext` (limb fold + fmix64 hash,
  wide-integer compare) for `State.slots`/`transient`: storage loop 12.7 -> 11.0 us, erc20
  1.44 -> 1.41 us (same-load A/B). Kept `std.HashMapUnmanaged` (not a custom flat table) so
  other lanes' `iterator`/`count`/`clearRetainingCapacity` uses are unchanged. The db
  lane's overlay `SlotKey` map still uses `AutoContext` and could adopt the same context.
- [x] Performance: `CallRequest` carries the target and code accounts the interpreter already
  loaded, so `start_call` skips both lookups: call loop 19.9 -> 17.9 us (interleaved A/B
  against origin/main in a scratch worktree).
- [x] Fuzz: differential fuzz of CALL-family plumbing (`call_fuzz.zig`: CALL/CALLCODE/
  DELEGATECALL/STATICCALL caller, value, and address; revert data; output window;
  RETURNDATASIZE; RETURNDATACOPY including the out-of-bounds halt) against a two-contract
  model.
- [x] Performance: keccak256 — investigated, no change: the crypto lane's Keccak-f already
  matches std (~146 vs ~139 ns per 32 B, docs/PERF.md) and has a 2-lane NEON batch path; the
  EVM loop's ~185 ns per 64 B is that hash plus memory pricing. Left to the crypto lane.
- [x] Performance: precompiles and native singletons are warm by predicate
  (`State.static_warm`, consulted only on a stale stamp) instead of `state.access` loading
  and journaling ~20 accounts per transaction (nf-node profile: `warm_addresses` ~5% and
  `State.load` ~8% of a 500-transfer block).
- [ ] Replay focus (owner, priority over the rest): audit EVM-side fee accounting at Base
  mainnet 53715983+ (Denim): L1 info deposit, L1 data fee, operator fee, DA footprint fee,
  fee vault credits, BaseTime deposit, 7702/system calls. Act first on nf-replay repros.
  Audit 1 (vs base/base `handler.rs` `reward_beneficiary`, `l1block.rs`): matches. The tip
  and base-fee vault use post-refund, post-7623-floor gas; the operator vault gets
  charge(gas_used) and the caller is refunded charge(limit) - charge(gas_used) (Jovian x100
  multiplier, no /1e6); the L1 fee is FastLZ-based and exempt for empty/0x7e envelopes;
  deposits pay nothing. BaseTime's `ensure_predeploy` has no caller upstream (the proxy
  arrives through upgrade deposits: consensus lane). The DA footprint feeds the header's
  blob_gas_used, not per-tx fees (executor/builder lanes). System calls live in
  `node/executor.zig`; `begin_transaction` now clears `static_warm`, so they start cold.
- [ ] Tracer hook for nf-node's debug_trace* (callTracer): `Evm.tracer: ?*const Tracer` with
  enter(kind, from, to, value, gas, input) / exit(gas_used, output, status) / log; null is
  zero cost.
- [ ] Fuzz: SSTORE gas and refund state machine (EIP-2200/2929/3529: original, current,
  new values; warm/cold; stipend check) against a table-driven reference model.
- [ ] Fuzz: CREATE/CREATE2 address derivation, init-code limits (EIP-3860), collision
  rules, and code-deposit gas against a model.
- [ ] Performance: a block-sized transaction bench (1000 mixed transfers and erc20 calls
  through `transaction.transact` without per-tx state reset) to profile the tx envelope.
- [x] Performance: account map — `start_call` reuses the parent frame's account for the
  caller and the target account when it is also the code account: call loop 23.5 ->
  ~18.6-22.2 us (noisy, load ~25). A fold+fmix64 hash context for `State.accounts`
  measured no gain and was dropped (twice now; the map itself is not the cost).
- [x] Performance: memmove in the storage loop: gone with `StorageKeyContext` (it was the
  auto context copying keys). What remains is `slot_for` + key compare at ~26 ns per access,
  about one cache miss into the 2^18-entry slot table that static allocation pre-sizes; not
  worth a locality hash that would favor sequential slots over real keccak layouts.
- [x] Fuzz: differential fuzz of memory/copy opcodes (`memory_fuzz.zig`: MSTORE/MSTORE8/
  MLOAD/MCOPY/CALLDATACOPY/CALLDATALOAD/CODECOPY against a byte-array model, final bytes and
  MSIZE). RETURNDATACOPY needs a callee and is covered by the state tests.
- [x] Performance: the interpreter runs on the frame in place instead of a local copy:
  call loop 27.0 -> 23.6 us, snailtracer 21.6 -> 21.0 ms, arithmetic unchanged (same-load
  A/B). Call-loop profile before: interpreter 35%, account-map lookup ~25%, frame
  push/resume ~20%; a u160-compare account-map context measured no gain and was dropped.
- [x] Fuzz: differential opcode fuzz of the arithmetic family (`arith_fuzz.zig`) (DIV/SDIV/MOD/SMOD/ADDMOD/
  MULMOD/EXP/SIGNEXTEND/shifts) through the interpreter against reference formulas.
- [x] Performance: compare with revm on the same machine (snailtracer: revm 31-46 ms,
  needlefish 27 ms after the `uint.zig` division rewrite; docs/PERF.md).

## Decisions
- EIP-8130 pre-call reads warm the accounts and slots they touch (base's gas-free journal
  provider loads through the journal), so later calls see them warm. Code installs from
  account changes are journaled (`State.replace_code` for delegation indicators) so a
  rejected transaction discards them.
- Push loop under load: main takes about one commit a minute while a full `zig build test`
  takes ~10 minutes on the shared machine, so a retest after every rejected push never wins.
  The loop runs the full test and tidy once on the rebased tree; after a rejection it
  rebases again and pushes without retesting only when no incoming commit touches a file
  our commits change (otherwise it retests). EVM work lives in its own files, so the
  untested merge carries no semantic overlap.
- OP Stack: `BlockEnv.op` (rules from `common.l1_fees`) switches on OP semantics; null is plain
  Ethereum. L1Block params are read from state per non-deposit tx (`op.load_params`), so the
  L1 attributes deposit at the top of the block is visible. Deposits always use the Regolith
  model (Base launched with Regolith active, as base/base notes); pre-Regolith gas rules are
  not implemented. `TxEnv.envelope` carries the EIP-2718 bytes for the L1 fee.
- revm architecture: `State` (journaled cache, `state.zig`) over a `Database` vtable that the
  trie-db lane implements; `MemoryDatabase` backs tests. The interpreter talks to the concrete
  `State` (no vtable on the hot path).
- Interpreter is instantiated per fork (`comptime fork`) with labeled-switch threaded dispatch
  (`continue :dispatch`); stack bounds and static gas are comptime per opcode.
- Static allocation: frames, 1025 stacks, shared memory, analysis arena, return buffer, journal,
  logs, code store and state maps are sized at init. Exceeding a state/journal limit is
  `error.StateFull` (fatal block error, never silent divergence). Memory growth past
  `memory_bytes_max` halts as out-of-gas (unreachable under realistic gas limits).
- Warmth and EIP-2200 "original" values are stamped with a tx id (O(1) tx start). Storage
  wipes bump a per-account `storage_epoch`; stale slots re-read from db (epoch 0) or as zero.
- Berlin+ static gas for BALANCE/EXT*/SLOAD/CALL* is the warm cost; cold adds the difference.
- Failed CALL pre-checks (depth, balance) return the full child gas including the stipend
  (geth/revm behavior). CREATE collisions consume the child gas.
- EIP-7610: `AccountInfo.has_storage` (backends set it when the storage root is non-empty)
  makes CREATE onto an address with storage a collision.
- Memory cap is consensus-relevant only beyond realistic gas: default 64 MiB covers 30M-gas
  txs; the state-test runner reserves 1.5 GiB (virtual) for 1 MB x 1024-depth fixtures. The
  node should size `memory_bytes_max` from its max tx gas.
- Precompiles call `common.crypto` (ecrecover, sha256, ripemd160, modexp, blake2f, p256).
- Precompiles not yet implemented fail the call (tracked under the precompile item).
- Native precompiles meter state access with the Osaka schedule regardless of fork (base/base
  passes `GasParams::default()`); they run against the journal and are warmed at tx start
  when their upgrade is active. Malformed calls to known selectors revert with the bare
  selector from Cobalt and with selector + alloy's decoder message before (overrun and
  tuple type-check texts reproduced). Only implemented singletons are warmed; PolicyRegistry
  and B20Factory join the warm set when they land. The activation admin comes from
  `op.Context.activation_admin` (chain config). `__initialize` keeps existing code.
- PolicyRegistry composite evaluation is iterative: write-time validation keeps children to
  (possibly inverted) plain lists, so a child that is itself composite is never recursed
  into (it evaluates as unauthorized, unreachable through the ABI).

## Log
- 2026-11-05: 64-bit-limb big-endian word loads (MLOAD/MSTORE/PUSH/CALLDATALOAD):
  snailtracer 27.1 -> 21.8 ms.
- 2026-11-05: `zig build test` (and `check`) now compiles the statetest runner.
- 2026-11-05: u256 DIV/MOD family via Knuth D (`uint.zig`): snailtracer 50.5 -> 27.1 ms,
  ahead of revm on the same machine. Embedded EEST 7702 fixture guards the statetest runner
  (it stopped compiling after a trie error-set change; `zig build test` did not build it).
- 2026-11-05: EEST v5.4.0 state tests 44039/44039 (Frontier through Osaka) and
  GeneralStateTests 37724/37724. The runner now parses `authorizationList` (authority
  recovered locally, low-s), and a 7702 delegation to a precompile or native runs empty code
  (revm semantics). Run: `zig build statetest -Doptimize=ReleaseSafe --
  .cache/vectors/eest/fixtures/state_tests`.
- 2026-11-05: snailtracer bench (fetched public fixture) and EIP-8130 simulation.
- 2026-11-05: EIP-8130 execution: nonce manager storage, journaled code installs, the
  enshrined executor (`eip8130_execute.zig`), end-to-end tests and an executor fuzz.
- 2026-11-05: B-20 core, Asset/Stablecoin V1 tokens, and factory native precompiles.
- 2026-11-05: native string/bytes storage (`native_storage.zig`) with Cobalt tail cleanup.
- 2026-11-05: PolicyRegistry V2/V3 (composite and inverted policies).
- 2026-11-05: Beryl PolicyRegistry V1 and the native ABI decoder.
- 2026-11-05: Beryl ActivationRegistry native precompile.
- 2026-11-05: native precompile framework; Cobalt TxContext and NonceManager getters.
- 2026-11-05: pre-Osaka wide-modulus MODEXP via startup-sized scratch (`precompiles.Buffers`).
- 2026-11-05: EVM micro benchmarks: 0.74 ns/instruction, 117 ns/call frame, 0.70 us/tx.
- 2026-11-05: bn254, KZG, BLS12-381 precompiles wired with Base caps; state tests 100%
  (37724 / 37724). `op.Upgrade` carries the full Base upgrade ladder.
- 2026-11-05: interpreter fuzz harness (`evm_fuzz.zig`), 300k-iteration soak clean.
- 2026-11-05: RIP-7212 P256VERIFY under OP Fjord; Canyon/Everest irregular transitions.
- 2026-11-05: OP Stack handler: deposits (mint, halted deposit -> revert all but mint and
  nonce, full gas), L1/operator fees in the balance check, vault routing (base fee credited to
  BaseFeeVault, not burned), operator fee refund for unused gas.
- 2026-11-05: tx execution, GeneralStateTests runner (96.0%), crypto-backed precompiles,
  EIP-7610 collisions.
- 2026-11-05: core interpreter, gas schedule, journaled state, frame stack, CREATE/CALL
  family, EIP-7702 call delegation, identity/sha256 precompiles; end-to-end tests.
