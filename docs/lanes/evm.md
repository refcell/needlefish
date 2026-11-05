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
- [ ] PolicyRegistry V2 (Cobalt: composite policies, children arrays with tail cleanup) and
  V3 (Denim: inverted policy ids); until then the registry is only installed before Cobalt.
- [ ] Base native precompiles (Beryl+: B20 factory, B20 tokens)
  and EIP-8130 (Everest, type 0x79: tx-context transient slots, nonce increments).
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
- [ ] Performance: snailtracer contract workload (needs public bytecode fixture; erc20 done);
  compare with revm on the same machine; profile call-frame and keccak paths.

## Decisions
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

## Log
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
