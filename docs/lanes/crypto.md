# Lane: crypto

Owns `src/common/crypto`. Zero deps: may use `std.crypto` as a correctness oracle or
fallback but hot paths should be our own, optimized implementations.

## Backlog
- [x] keccak256: fast single + batch (SIMD multi-lane) implementation, vectors, bench vs std.
- [ ] keccak256: dedicated NEON-SHA3 / AVX2 single-message path to beat std by >20%.
- [ ] sha256 (use/beat std), ripemd160, blake2f (EIP-152 compression), identity.
- [ ] secp256k1: field/scalar arithmetic (5x52 limbs or similar), GLV endomorphism, wNAF, ecrecover (precompile 0x01 semantics), signing (RFC 6979, constant time), public key → address. Vectors + differential fuzz vs `std.crypto.ecc.Secp256k1`.
- [x] Generic Montgomery prime field `montgomery.Field(limbs, p)` shared by bn254/BLS/P256.
- [ ] montgomery: no-carry CIOS for moduli with spare top bits, dedicated squaring, faster inversion (bernstein-yang / binary gcd).
- [ ] modexp (EIP-198/2565/7883 gas lives in evm; arithmetic here), big-int helpers.
- [ ] bn254 (alt_bn128): add, mul, pairing check (EIP-196/197) with official vectors.
- [ ] BLS12-381: G1/G2 ops, MSM, pairing, map-to-curve (EIP-2537 precompiles).
- [ ] KZG point evaluation (EIP-4844 precompile 0x0A) with the public trusted setup (embed the public setup as a compressed file or generate from the public ceremony output).
- [ ] secp256r1 / P256VERIFY (RIP-7212 / EIP-7951).
- [ ] Benchmarks for each; target parity with or better than best-known C implementations.

## Decisions
- Keccak permutation is generic over the lane type (`u64` or `@Vector(n, u64)`); batch width
  is 2 on NEON (LLVM emits EOR3/BCAX/XAR/RAX1), 4 on AVX2, 8 on AVX-512. Unrolling the
  round loop measured slower on aarch64, so it is not unrolled.
- Benchmarks live in `src/common/crypto/bench.zig`; `src/testing/bench_main.zig` calls
  `crypto.bench.run(io, filter)` with the process `Io` as the only clock.

- Prime fields share `montgomery.Field(limbs, modulus)`: comptime-derived constants, CIOS
  multiplication, masked final subtraction, Fermat inverse, p = 3 mod 4 sqrt.

## Log
- 2026-11-05: keccak256 one-shot, streaming, SIMD batch; vectors, seeded + coverage fuzz vs std; bench (32B: 147ns single, 71ns/msg batch, std 141ns).
- 2026-11-05: montgomery.Field generic over limbs; tested vs big ints for bn254, P-256, BLS12-381 (bench: 18.9ns bn254 mul, 31.0ns bls mul).
