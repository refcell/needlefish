# Lane: crypto

Owns `src/common/crypto`. Zero deps: may use `std.crypto` as a correctness oracle or
fallback but hot paths should be our own, optimized implementations.

## Backlog
- [x] keccak256: fast single + batch (SIMD multi-lane) implementation, vectors, bench vs std.
- [ ] keccak256: dedicated NEON-SHA3 / AVX2 single-message path to beat std by >20%.
- [x] sha256 (use/beat std), ripemd160, blake2f (EIP-152 compression), identity.
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

- KZG setup: the public c-kzg-4844 `trusted_setup.txt` is stored as raw compressed bytes in
  `kzg/trusted_setup.bin` (4096 G1 Lagrange + 65 G2 monomial points, 202848 bytes,
  sha256 2721e57b...6a7e, asserted in tests). G1 monomial points (EIP-7594 cells) are
  omitted until PeerDAS work needs them.

- sha256: own implementation. aarch64+SHA2 uses `sha256su0/su1` LLVM intrinsics for the
  message schedule and inline asm for `sha256h/h2` (the LLVM h/h2 intrinsics measured ~10%
  slower: the allocator puts a vector copy on the critical chain; asm keeps h in place and
  the copy off-chain). The body and padded tail go through one `compress` call so the
  round constants are hoisted once per hash. Other targets use a scalar unrolled version
  (x86 SHA-NI is not implemented; untestable on this host, std remains the oracle).
- ripemd160: own implementation (std has none); correctness from the paper vectors plus a
  naive runtime-loop reference used as differential oracle. Precompile 0x03 output is the
  digest left-padded to 32 bytes.
- blake2f: scalar, 10 rounds unrolled with comptime sigma rows, any `u32` round count.
  A 4-lane `@Vector` variant (LLVM emits XAR) measured 40% slower (latency-bound single
  G chain; the scalar form overlaps the four columns), so it was dropped. Parity with
  std's compression (87 vs 85 ns per 12 rounds). EIP-152 vector 8 (2^32 - 1 rounds) is
  skipped in Debug and runs in ReleaseSafe/ReleaseFast test builds (~25 s).
- identity (precompile 0x04) is a plain copy; no function is provided, the evm lane copies.
  `blake2f.input_rounds` exposes the round count so evm can charge gas before running F.

## Log
- 2026-11-05: keccak256 one-shot, streaming, SIMD batch; vectors, seeded + coverage fuzz vs std; bench (32B: 147ns single, 71ns/msg batch, std 141ns).
- 2026-11-05: montgomery.Field generic over limbs; tested vs big ints for bn254, P-256, BLS12-381 (bench: 18.9ns bn254 mul, 31.0ns bls mul).
- 2026-11-05: kzg: embedded public trusted setup, versioned hash, 0x0A input framing + output; pairing check plugs in once BLS12-381 lands.
- 2026-11-05: sha256 (ARMv8 SHA2 path, 32B: 26ns vs std 33ns; 4KiB: 1455ns vs std 1643ns), ripemd160 (32B: 131ns; 4KiB: 8.6us), blake2f (12 rounds: 87ns, std compression 85ns); official/EIP-152 vectors 0-8, seeded + coverage fuzz.
