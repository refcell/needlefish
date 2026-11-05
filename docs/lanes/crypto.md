# Lane: crypto

Owns `src/common/crypto`. Zero deps: may use `std.crypto` as a correctness oracle or
fallback but hot paths should be our own, optimized implementations.

## Backlog
- [ ] keccak256: fast single + batch (SIMD multi-lane) implementation, vectors, bench vs std.
- [ ] sha256 (use/beat std), ripemd160, blake2f (EIP-152 compression), identity.
- [ ] secp256k1: field/scalar arithmetic (5x52 limbs or similar), GLV endomorphism, wNAF, ecrecover (precompile 0x01 semantics), signing (RFC 6979, constant time), public key → address. Vectors + differential fuzz vs `std.crypto.ecc.Secp256k1`.
- [ ] modexp (EIP-198/2565/7883 gas lives in evm; arithmetic here), big-int helpers.
- [ ] bn254 (alt_bn128): add, mul, pairing check (EIP-196/197) with official vectors.
- [ ] BLS12-381: G1/G2 ops, MSM, pairing, map-to-curve (EIP-2537 precompiles).
- [ ] KZG point evaluation (EIP-4844 precompile 0x0A) with the public trusted setup (embed the public setup as a compressed file or generate from the public ceremony output).
- [ ] secp256r1 / P256VERIFY (RIP-7212 / EIP-7951).
- [ ] Benchmarks for each; target parity with or better than best-known C implementations.

## Decisions

## Log
