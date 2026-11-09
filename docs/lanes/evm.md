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
- [x] Replay focus (owner, priority over the rest): audit EVM-side fee accounting at Base
  mainnet 53715983+ (Denim): L1 info deposit, L1 data fee, operator fee, DA footprint fee,
  fee vault credits, BaseTime deposit, 7702/system calls. Act first on nf-replay repros.
  Covered end to end: nf-replay reproduces the state root (every balance and vault credit)
  of all 100 blocks 53715983-53716082, and txcheck matches 1745/1745 receipts.
  Audit 1 (vs base/base `handler.rs` `reward_beneficiary`, `l1block.rs`): matches. The tip
  and base-fee vault use post-refund, post-7623-floor gas; the operator vault gets
  charge(gas_used) and the caller is refunded charge(limit) - charge(gas_used) (Jovian x100
  multiplier, no /1e6); the L1 fee is FastLZ-based and exempt for empty/0x7e envelopes;
  deposits pay nothing. BaseTime's `ensure_predeploy` has no caller upstream (the proxy
  arrives through upgrade deposits: consensus lane). The DA footprint feeds the header's
  blob_gas_used, not per-tx fees (executor/builder lanes). System calls live in
  `node/executor.zig`; `begin_transaction` now clears `static_warm`, so they start cold.
  Audit 2: `zig build txcheck -- <replay-raw block dirs>` (`tx_check.zig`) runs every mainnet
  transaction alone on its prestateTracer pre-state and compares status, gas used, and logs
  with its receipt (no trie or executor, so a mismatch isolates the EVM). Blocks
  53715983-53715992: 253/253. With nf-replay's return-data fix (`a1fe2ae3`) reverted it
  flags 8+ transactions, starting at 53715983 tx 3. `call_fuzz.zig` now also checks that a
  callee sees RETURNDATASIZE 0 after an earlier call (it missed that bug before).
  Audit 3: the 100-block window (79 fetched blocks) plus the first 10: 1630/1630. The first
  run flagged 5; all were tool gaps, not EVM bugs: BLOCKHASH needs the fetcher's
  `headers.json` (now loaded), and prestateTracer lists a nonexistent EIP-7702 authority as
  an empty account, which must not be loaded (it would earn the 12500 existing-account
  refund).
  Audit 4: the full 100-block window 53715983-53716082 (the last 21 blocks fetched into
  `~/.cache/needlefish/replay-raw-evm`): 1745/1745.
- [x] Tracer hook for nf-node's debug_trace* (callTracer): `Evm.tracer: ?*const evm.Tracer`
  (null: one branch per frame). `enter(TraceFrame{kind: call|callcode|delegatecall|
  staticcall|create|create2|selfdestruct, from, to, value, gas, input, depth})` is matched by
  exactly one `exit(Outcome)` in stack order (gas used = frame gas - `gas_remaining`; `exit`
  is the halt reason; `created` set for creates; `to` of a create is the derived address
  even when it collides); `log(address, topics, data)` fires as each LOG runs. SELFDESTRUCT
  is a zero-gas child moving the balance. Precompile calls and depth/balance failures also
  get enter/exit.
- [x] Fuzz: SSTORE gas and refund state machine (`sstore_fuzz.zig`: random SSTORE/SLOAD over
  three slots with random originals; exact gas used and raw refund counter vs an
  EIP-2200/2929/3529 model at Osaka; catches a 1-wei refund change). The 2300 stipend
  check stays covered by the state tests.
- [x] Fuzz: CREATE/CREATE2 (`create_fuzz.zig`: address derivation with random nonce and
  salt; EIP-3541 0xef prefix, EIP-684 collision, EIP-170 runtime limit, EIP-3860 init-code
  limit halting the creator; returned word, installed code, creator nonce). Deposit gas
  stays covered by the state tests.
- [x] Performance: a block-sized transaction bench (`evm: block of 1000 transactions`: one
  Denim block of 500 ETH + 500 erc20 transfers from 100 senders, one state reset per
  block): ~0.75 ms/block. Its profile showed `warm_system_addresses` recomputing the
  precompile set (18 `precompiles.lookup`) per tx, ~5%; now cached on `Evm` by
  (fork, upgrade): ~0.72 ms/block. The remaining keccak (~20%) is the erc20 slot hashing.
- [x] Performance (nf-node's replay profile: 40% in `push_frame` code analysis): a
  process-lifetime `bytecode.AnalysisCache` keyed by code hash (64 MiB buffer, 16k-slot
  table kept <= 3/4 full; append-only while frames are live; reset at the next top-level
  message once full; init code and overflow use the frame arena; ReleaseSafe asserts the
  cached code equals the frame's). `node: replay` 387 -> 740 Mgas/s; block bench 0.72 ->
  0.68 ms; txcheck 1745/1745 and both state suites still pass.
- [x] Performance: `slot_for` (~16% of the block bench). Tried one probe per miss
  (`getOrPut` first, remove on a database error): no measurable change (storage loop
  10.5 us, block 0.675 ms), not kept. The cost is memory: `slots_max` 2^18 reserves ~2^19
  buckets of a 64 B key plus a 96 B `Slot` (~75 MB), so each access misses cache and TLB.
- [x] Vectors: EEST v5.4.0 `fixtures_develop` (Osaka and later; the stable set stops at
  Prague) now fetched by `just vectors` into `.cache/vectors/eest-develop`: 63556/63556
  pass, no skipped forks. Nothing to fix.
- [x] Keccak in `node: replay` (~1000 samples): almost all is the witness `NodeStore.add`
  and sparse-trie rehash (db lane), hashing each node once, which is inherent. std's
  keccak-f runs ~139 ns per 32 B hash (~450 cycles), near single-state scalar on Apple
  cores; published AArch64 work (Becker-Kannwischer 2022) gains from SHA3/NEON mainly
  with multi-state batching, which the crypto lane already offers. Not rewriting keccak-f;
  the lever is batching witness hashes through the crypto batch path (db lane).
- [x] Replay profile at ~860 Mgas/s (active samples, idle threads excluded): keccak ~27%
  (witness/trie), `interpreter.run` self ~18%, secp256k1 ~11% (sender recovery in the
  executor; the ecrecover precompile ~2%), `push_frame` ~5.6%, division ~4%; `slot_for`
  under `run` is ~11% inclusive but nearly all cold database reads (db lane). In
  `push_frame`, the cached-code equality assert still ran in ReleaseFast (~1.8%, as
  `mem.eqlBytes`): now only under `runtime_safety`: replay 859 -> ~870 Mgas/s.
- [x] Coverage vs base/base (`crates/common/evm`): Everest's NonceManager stub, Canyon,
  EIP-8130 committed phases, and B-20 stablecoin all have counterparts; `beryl_metrics`
  is telemetry. No gap found.
- [x] Performance: `-Devm-opcode-profile=true` (`opcode_profile.zig`) counts every opcode
  and accumulates timer ticks per handler (children excluded); the bench prints the top 30
  at exit; compiled away otherwise. On `node: replay`: SLOAD ~40% of handler ticks (cold
  witness reads, db lane), MULMOD ~15%, KECCAK256 ~8%, SSTORE 3%, then JUMPI/MSTORE/PUSH.
  MULMOD operands are almost all full 256-bit with a full 256-bit modulus (737k of 762k);
  `not(0)` moduli (FullMath) are 13.6k and now fold hi + lo directly. Division works on
  limb arrays (bitcast, no u256/u512 shift-and-mask per limb) and the product is a 4x4
  schoolbook `wide_mul`: MULMOD 99 -> 77 ticks, mulmod+div loop 145 -> 125 us; replay
  interleaved A/B is within noise at this load (~880-910 Mgas/s). `push_frame` time left
  is first-sight analysis; nothing to specialize there.
- [x] Performance: SLOAD is ~40% of interpreter handler time on replay, nearly all cold
  reads through the witness `SparseState.storage`. Sent to nf-trie-db with the repro; they
  are memoizing keccak(slot/address) in `SparseState` and may add
  `SparseState.prefetch_storage(account, slots)` (batch keccak). Whether the EVM calls a
  prefetch per tx is ours to decide once the signature lands.
- [x] Performance: KECCAK256 (~11% of handler ticks on replay; 93% of inputs <= 64 bytes,
  mostly 64-byte mapping keys; ~60% repeat within a tx, ~91% across the run). Tried a
  1024-entry direct-mapped digest memo on `Evm`: erc20 bench 915 -> 614 ns (it rehashes
  one key), block bench and replay unchanged within noise (interleaved A/B 918 vs 910
  Mgas/s), so not kept.
- [x] Performance: nf-trie-db landed the `SparseState` key-hash memo (replay ~925 -> ~972
  Mgas/s on their runs; SLOAD 497 -> 476 ticks/exec) and offers
  `SparseState.prefetch_storage(address, slots)`. Not wired: it only saves the batch-vs-
  single keccak difference (~77 vs ~140 ns) for slots known before execution, i.e.
  access-list keys, which are rare on Base mainnet; the memo already hashes each key once.
  It would need an optional `Database` vtable hook plus replayer wiring for a gain below
  replay noise. Revisit if access lists become common or the trie walk gets batched.
- [x] Fuzz: journaled `State` against a snapshot-stack model (`journal_fuzz.zig`): nested
  checkpoint/revert/discard, balances, nonces, SSTORE, TSTORE, address and slot warming,
  logs, and account re-creation across up to 4 transactions; every observable compared
  after each step. Catches reverts that stop un-warming slots.
- [x] Performance (EVM side): `State.Limits.for_block_gas(gas_limit)` sizes the slot and
  account tables from the block gas limit (>= 1900 gas per distinct slot, >= 2400 per
  account, plus 2^13 headroom for unmetered system writes; capped at the defaults): a
  37.5M-gas block gets 2^15 of each instead of 2^18 slots. For a `State` reset at least
  once per block. The node lane wires it into the executor and measures `node: replay`.
- [x] Performance: `transact` self time, profiled with its helpers `noinline`: spread
  thin (per 1000-tx block, samples: `op.load_params` 86, `transact` 73, `intrinsic_gas` 68,
  `pay_fees` 58, `validate_and_buy_gas` 50). `intrinsic_gas` now counts zero calldata
  bytes 32 at a time: block bench 0.675 -> 0.66 ms. `load_params` is not cached across
  txs: the L1 attributes deposit rewrites those slots mid-block.
- [x] Performance: re-profiled `node: replay` after the analysis cache. Keccak (~1000
  samples) is the witness `NodeStore.add` / sparse trie (db/node lanes); `push_frame` left
  is first-sight analysis (the bench builds a fresh executor per run). EVM-owned: the
  interpreter loop, `slot_for`, and u256 division (`knuth_step` + `mulmod` ~250 samples).
  Division now runs on 64-bit limbs with Möller-Granlund 2-by-1 reciprocal steps (was
  32-bit limbs): new `evm: mulmod+div loop` bench 286 -> 150 us, replay ~723 -> ~752
  Mgas/s; the uint differential fuzz catches a skipped add-back.
- [x] Performance: `reciprocal` is now a 256-entry seed table plus Newton steps (intx's
  `reciprocal_2by1`) instead of a `__udivti3` call; exact against the u128 division on
  100k random divisors and the edges. mulmod+div loop 150 -> 144 us.
- [x] Fuzz: MODEXP precompile (`modexp_fuzz.zig`): output vs a u512 square-and-multiply
  model over random 0..64-byte base/exponent and 0..32-byte modulus (leading zeros, zero
  lengths, zero/one moduli) at Byzantium/Berlin/Osaka; one gas short of the charge fails
  with all gas consumed. Gas formulas stay covered by crypto-lane vectors and EEST.
- [x] Vectors: P256VERIFY (RIP-7212, used on Base) against the public Wycheproof
  secp256r1 vectors the crypto lane already embeds (~350 cases), through the precompile at
  Fjord (3450 gas) and Osaka (6900 gas): 32-byte 1 when valid, empty when not, fixed gas,
  out of gas one short.
- [x] Fuzz: EIP-7702 delegation chains (`delegation_fuzz.zig`): 1..6 tuples over three
  authorities (absent, empty-present, funded, delegated, real code; sometimes the sender)
  with right/zero/wrong chain, right/wrong/max nonce, missing signer, and clearing, against
  a model of every authority's code and nonce and the gas used (12500 refunds, 1/5 cap).
  Catches a dropped refund and a dropped real-code skip.
- [ ] Performance (measured lever: lookup count, not hash cost): add `-Devm-opcode-profile`
  counters for State account-map and slot-map lookups per SLOAD/SSTORE/BALANCE/CALL on
  replay, then remove redundant ones (expected: SLOAD does an account lookup plus a slot
  lookup; the executing contract's `*Account` can live in the frame).
- [ ] Performance: SLOAD/SSTORE single slot-map probe: fold the warm check, original-value
  load, and present-value read into one `getOrPut` per access; A/B on replay.
- [ ] Performance: CALL family: count account lookups per call (target access, code load,
  delegation target, value transfer) and reuse the loaded `*Account` across them.
- [x] Performance: nf-trie-db's `db.address_map` context (std Wyhash, `u160` equality) in
  `State.accounts` and `MemoryDatabase.accounts`/`storage`: interleaved A/B on the block
  bench ~5% slower with it in `State.accounts` (681 vs 645 us), neutral in `memory_db`
  alone; not adopted. Third account-map context tried in `State` without a gain (see the
  fold+fmix64 attempts): its cost is the lookup count, not hashing or equality.
- [x] Note for the db lane (sent to nf-trie-db): the harness's `db.overlay` account map (`AutoContext([20]u8)`,
  `getIndex` + `meta.eql`) is ~19% of the block bench; an address-specific hash context
  there would help cold account loads.
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
- evm2-style redesign (2026-11-08, approved by the owner; design in the thread's "EVM
  redesign: evm2 research and design" doc). evm2 (alloy-rs/evm2, reth's EVM since v2.9.0) is
  fast mainly from instruction plumbing: pc, stack length and gas stay in machine registers
  between opcodes and reach memory only at opcodes that need the host or dynamic gas. Phases:
  P0 benchmark against evm2 (`etc/bench/evm2.sh`), P1 register locals in the switch, P2
  tail-call handlers (`@call(.always_tail)` with `preserve_none`), P3 keccak memo and a faster
  x86 Keccak-f, P4 state lookups and analysis. CALL keeps the explicit frame stack (evm2
  recurses natively; needlefish's driver is already allocation-free).
- P1: `interpreter.run` keeps `Registers` (pc, gas, stack pointer + length) in locals. Opcodes
  that touch only them, memory, and read-only frame/block fields (arithmetic, stack, PUSH,
  jumps, MLOAD/MSTORE/MSTORE8/MCOPY, CALLDATALOAD and the env/block pushes) run on the
  registers; all others are sync points (write to the frame, run, reload). The stack check is
  one compare (`len -% inputs > 1024 - outputs`). Steps return a `bool` continue flag with the
  exit in a local: a `?Exit` result compiled to a load from a constant global plus a branch on
  every opcode (~8% of snailtracer).
- P2: tail-call handlers measured and rejected. A full `preserve_none` +
  `@call(.always_tail)` backend (one handler per fork and opcode, registers as arguments)
  passed every evm2 fixture but ran 5-14% slower than the P1 switch on every one: Zig's
  labeled `switch` already compiles to threaded dispatch (an indirect jump per arm), which is
  what evm2's tail calls buy over its central loop. The gap to evm2 was inside the handlers,
  found by comparing disassembly: (1) results written as four 8-byte stores (an ADD was four
  `adc`s to memory) that the next DUP/SWAP's 32-byte load cannot forward from, so
  `stack.write` stores a word with one `vmovdqu` (inline asm on x86-64 + AVX; LLVM splits a
  plain vector store again); (2) a 32-bit pc and stack length zero-extended on every opcode
  (now u64); (3) gas as compare + subtract (now `@subWithOverflow` and a borrow branch);
  (4) stack checks narrowed per opcode (underflow only when the stack cannot grow). Together
  fibonacci 42 -> 24 us (evm2 tail-call 27) on B1.
  Follow-up from the preserve_none thread (2026-11-08): stock Zig 0.17.1 already emits real
  `preserve_nonecc` + `musttail`, so fucory's fork adds nothing. The P2 tail calls lost to a
  `push rbp`/`pop rbp` and a `vzeroupper` per handler; with both removed they only reach
  parity (1.00x) with the switch. Of Guillotine's tricks, a stack-top pointer is a net loss
  in ReleaseSafe, and per-basic-block gas checks are worth at most 1.01x.
- P3: KECCAK256 through `common.crypto.keccak` instead of std, with an x86-64 AVX-512
  single-message permutation (`permute_one`: a lane per 128-bit register, `vprolq` and
  `vpternlogq`, as evm2's keccak compiles; 264-272 ns per 64-byte hash against std's
  636-675), and a per-`Evm` memo of digests for inputs of up to 64 bytes
  (`keccak_memo.zig`): direct-mapped, 2^16 entries (~6 MiB reserved lazily), a hit compares
  the whole input, lives across transactions and blocks; `Config.keccak_memo_entries = 0`
  disables it. Same idea as alloy's `keccak-cache-global` that reth and evm2's bench enable,
  but owned and sized at init instead of process-global. B1 now pairs memo-off with evm2
  memo-off and memo-on with evm2 memo-on (`statetest --no-keccak-memo`).
- P4 (state lookups): the account map and `MemoryDatabase`'s account and storage maps hash
  the address folded into one word (`AddressContext`, as `StorageKeyContext` already did for
  slots) instead of wyhash over the bytes. A/B vs P3 on the eight state-heavy fixtures, 7
  rounds: geometric mean 1.02x (erc20_transfer 1.12x, curve_3pool 1.09x). State lookups are
  ~6% of a contract-heavy profile, so the rest of the gap to evm2 there is elsewhere: 256-bit
  division (`uint.div_rem` + `knuth_step`) is 6-20% on curve and uniswap_v3_pool.
- Division: on x86-64 each quotient digit is one `divq` (128 by 64 bits) instead of a
  Möller-Granlund step with a reciprocal computed per call; for the one to four digits of an
  EVM word, the reciprocal setup cost more than it saved. Knuth's loop is unrolled per divisor
  length, a wide ADDMOD/MULMOD dividend that fits a word takes the 256-bit path, and the
  reciprocal path stays for other targets (both are fuzzed against the builtins). An
  intx-style 3-by-2 estimate was tried and gained nothing. A/B vs P4, two sets of 3 rounds:
  geometric mean 1.04-1.07x (uniswap_v3_pool 1.12-1.21x, curve_tricrypto2 1.09-1.11x);
  division falls from ~20% to ~14% of the curve_3pool + uniswap_v3_pool profile.
- Map keys: the account and slot map contexts read an address as three little-endian words
  (`AddressWords`) instead of bit-casting `[20]u8` to `u160`, which compiled to twenty byte
  loads per hash and compare in an out-of-line `eql` (8% of snailtracer). Same hash values,
  so map layout and order are unchanged. A/B vs the division commit: 1.09x geometric mean on
  eight state-heavy fixtures (weth 1.21x, erc20_transfer 1.12x, entry_point 1.11x),
  snailtracer 1.04x.
- ReleaseSafe (the build the node ships): the interpreter loop had 383 branches to panic
  handlers. The most common were checks that cannot fire: `pc += 1` overflow on every
  opcode (pc stays inside the padded code, under 2^33 bytes) and bounds checks on stack pops
  and swaps after the opcode's own stack check. `pc` now advances with a wrapping add (the
  `code[pc]` bounds check at dispatch stays), and with runtime safety the per-opcode stack
  check is two-sided (`len -% inputs > 1024 - max(inputs, outputs)`), which proves
  `len <= 1024` so the optimizer drops the index checks. Code, memory and stack checks that
  can fire all remain; 383 -> 321 panic branches, loop 6% smaller. A/B, 4 rounds: ReleaseSafe
  1.12x geometric mean (factorial 1.47x, weth 1.26x, fibonacci 1.15x, curve 1.11-1.14x).
- hash_10k chains KECCAK256 over 32 fresh bytes, so no memo helps. evm2's keccak-asm uses the
  same AVX-512 lane-per-register permutation as `permute_one`, and ours runs within ~4% of
  it; needlefish's interpreter share of the case is smaller than evm2's. A 32/64-byte fast
  path that builds the sponge state from the input words, without the padded block, measured
  0.96-1.05x in two A/Bs (noise) and was not kept.
- Base 10-block replay (`base replay bench ... --evm-only`, ReleaseSafe), P2 and P4 binaries
  run alternately in one session: every block matches its header on both, 10.82 -> 10.16 ms
  per block (1.07x), every block faster. Absolute times are ~1.6x those of 2026-11-08 because
  the VM ran slower that session.
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
- 2026-11-09: safe builds check a cached code analysis against the caller's code once per
  code buffer, not on every CALL (the entry remembers the buffer that matched; stored code
  is never written in place). The per-hit compare was 8-11% of ReleaseSafe time on
  call-heavy fixtures: aggregation_router 1.15x, curve_tricrypto2 1.15x, universal_router
  1.13x. With the secp256k1 work (crypto lane log), entry_point_v0_7 is 1.12x in
  ReleaseFast. ReleaseSafe profiles of the remaining gaps show memset and page faults only
  in the harness's untimed State.init/reset/deinit, not inside the timed transaction.
- 2026-11-09: B1 after the ReleaseSafe change (10 rounds, idle, tight intervals) vs evm2
  tail-call: ReleaseSafe 1.10x, ReleaseFast 1.37x, both memos 1.41x. Still behind in
  ReleaseFast: entry_point 0.85x, hash_10k 0.93x, curve_tricrypto2 0.96x.
- 2026-11-09: ReleaseSafe drops checks that cannot fire (pc overflow, stack indexes behind
  a two-sided stack check): 1.12x on compute and contract fixtures. Base replay at 0c892cb
  matches every header, 1.11x per block vs P2 in one session.
- 2026-11-09: B1 at P4 (10 rounds, unloaded) vs evm2 tail-call: ReleaseFast 1.36x geometric
  mean, ReleaseSafe 1.04x, both memos on 1.37x; every compute and contract case at or above
  parity except hash_10k (0.93x).
- 2026-11-09: map keys read addresses as words, not byte by byte: 1.09x on state-heavy
  fixtures.
- 2026-11-09: `divq` quotient digits on x86-64, 1.04-1.07x on division-heavy fixtures; Base
  replay at P4 still matches every header, 1.07x faster per block than P2.
- 2026-11-08: P4: folded-address hashing for the account and in-memory database maps,
  1.02x geometric mean on state-heavy fixtures; 256-bit division is the next gap to evm2.
- 2026-11-08: P3 (AVX-512 Keccak-f, per-`Evm` keccak memo): vs evm2 tail-call on 15 rounds,
  ReleaseFast geometric mean 1.05x -> 1.13x memo-off (hash_10k 0.46x -> 0.97x,
  erc20_transfer 0.51x -> 0.92x), 1.07x with both memos on; ReleaseSafe 0.85x.
- 2026-11-08: P0 (evm2 fixture benchmark, `statetest --bench`) and P1 (register locals):
  vs evm2's tail-call build on its 31 fixtures, ReleaseFast geometric mean 0.77x -> 0.89x
  (1.04x vs evm2's stable build); docs/BENCHMARKS.md "EVM vs evm2". EEST stable and develop
  state tests still pass. Next: P2 tail-call handlers.
- 2026-11-08: P2: tail calls rejected (slower than the switch in Zig); single-store stack
  writes, 64-bit registers, borrow-checked gas, narrower stack checks instead. Next: P3 keccak.
- 2026-11-06: paused (project paused by owner). Last pushed work: 23575ed5 (EIP-7702
  delegation fuzz). Next on resume: lookup-count profiling (first unchecked backlog item).
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
