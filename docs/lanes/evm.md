# Lane: evm

Owns `src/execution/evm`. Reference: revm, op-revm, base/base `crates/execution/evm`,
`crates/common/evm*`, `crates/common/precompiles`.

## Backlog
- [ ] Core interpreter: stack (fixed 1024), memory (bounded, expansion gas), bytecode analysis (jumpdest bitmap, cached), dispatch via tail-call/computed-goto style switch; all opcodes through Cancun/Prague/Osaka (PUSH0, MCOPY, TLOAD/TSTORE, BLOBHASH, BLOBBASEFEE, CLZ...).
- [ ] Gas schedule per fork, warm/cold access lists (EIP-2929), refunds (EIP-3529), SSTORE net metering (EIP-2200), call gas 63/64, init-code limits (EIP-3860).
- [ ] `Host`/state interface (account, storage, code, block hashes, logs, journal with revert checkpoints) — define here as a small Zig interface; trie-db lane implements the backend. Include an in-memory backend for tests.
- [ ] CALL/CALLCODE/DELEGATECALL/STATICCALL/CREATE/CREATE2/SELFDESTRUCT (EIP-6780) with explicit frame stack (no recursion), max depth 1024.
- [ ] Transaction-level execution: intrinsic gas, nonce/balance checks, EIP-1559 fee handling, blob txs, EIP-7702 authorizations, access lists, coinbase/base-fee payments.
- [ ] OP-stack semantics: deposit tx processing (mint, no fee, gas accounting by fork, failed-deposit nonce bump), L1 cost charging to L1FeeVault, BaseFeeVault/SequencerFeeVault, operator fee (Isthmus), Base-specific changes in base/base.
- [ ] Precompile dispatch wired to `common.crypto` with per-fork sets and gas.
- [ ] ethereum/tests GeneralStateTests runner (`just vectors`), pass rate tracked in this file.
- [ ] Differential fuzzing harness (random bytecode, seeded) + `std.testing.fuzz` targets.
- [ ] Performance: benchmark snailtracer/erc20 style workloads; aim beyond revm.

## Decisions

## Log
