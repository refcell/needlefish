# Lane: crypto

Owns `src/common/crypto`. Zero deps: may use `std.crypto` as a correctness oracle or
fallback but hot paths should be our own, optimized implementations.

## Backlog
- [x] keccak256: fast single + batch (SIMD multi-lane) implementation, vectors, bench vs std.
- [ ] keccak256: dedicated NEON-SHA3 / AVX2 single-message path to beat std by >20%.
- [x] sha256 (use/beat std), ripemd160, blake2f (EIP-152 compression), identity.
- [x] secp256k1: field/scalar arithmetic (5x52 limbs or similar), GLV endomorphism, wNAF, ecrecover (precompile 0x01 semantics), signing (RFC 6979, constant time), public key → address. Vectors + differential fuzz vs `std.crypto.ecc.Secp256k1`.
- [x] Generic Montgomery prime field `montgomery.Field(limbs, p)` shared by bn254/BLS/P256.
- [x] montgomery: faster inversion (safegcd); dedicated squaring evaluated (no gain on M4).
- [x] montgomery: no-carry CIOS for spare-bit moduli evaluated: no gain over row-wise chains
  (bn254 18.3ns, bls 25.8ns either way); not adopted.
- [x] modexp (EIP-198/2565/7883 gas lives in evm; arithmetic here), big-int helpers.
- [ ] modexp: faster inner loops (2-accumulator mac, ADX/MULX-style on x86), window 6 above ~700 exponent bits.
- [x] bn254 (alt_bn128): add, mul, pairing check (EIP-196/197) with official vectors.
- [ ] bn254 perf: lazy-reduction Fp2/Fp12, precomputed G2 line coefficients, mixed-affine
  Miller adds, batch normalization of the GLV tables.
- [x] BLS12-381: G1/G2 ops, MSM, pairing, map-to-curve (EIP-2537 precompiles).
- [ ] BLS12-381 perf: GLV/GLS scalar mul, batch-affine Pippenger buckets, sqrt_ratio SSWU,
  dedicated Fp squaring and lazy reduction in Fp2/Fp6 (G1 mul and map are ~2-3x blst).
- [x] KZG point evaluation (EIP-4844 precompile 0x0A) with the public trusted setup (embed the public setup as a compressed file or generate from the public ceremony output).
- [ ] KZG blob API (EIP-4844 polynomial-commitments): blob_to_kzg_commitment (MSM over the
  Lagrange setup), compute_challenge, barycentric evaluation, compute_kzg_proof,
  compute/verify_blob_kzg_proof (+ batch) — needed by the batcher and blob sidecar checks.
- [ ] KZG cells (EIP-7594 / Osaka blob tx proofs): G1 monomial setup, FK20 cell proofs, verify.
- [x] secp256r1 / P256VERIFY (RIP-7212 / EIP-7951): `p256.verify`, `p256.precompile_p256verify`.
- [x] Benchmarks for each (see "Bench snapshot"); remaining known gaps vs blst/libsecp-class C:
  BLS G2 mul and MSM, modexp large-operand inner loops, keccak single-message (parity only).

## Bench snapshot (2026-11-05, Apple M4 Pro, ReleaseFast, host load ~24, ns/op)

| op | ours | std |
| --- | --- | --- |
| keccak256 32 B / batch per msg / 4 KiB | 147 / 74 / 4367 | 150 / - / 4829 |
| sha256 32 B / 4 KiB | 26 / 1427 | 29 / 1450 |
| ripemd160 32 B / blake2f 12 rounds | 135 / 86 | - / 84 (blake2b 128 B) |
| secp256k1 ecrecover / sign / pubkey | 28577 / 11212 / 9336 | verify 62509 / 74249 / 71221 |
| p256 verify | 52890 | 88463 |
| bn254 add / mul / pairing 2 pairs | 1716 / 12236 / 552420 | - |
| bls12-381 g1 mul (glv) / g2 mul / pairing-2 | 41308 / 200005 / 687248 | - |
| bls12-381 map_fp_to_g1 / g1 msm-64 | 41217 / 1232222 | - |
| kzg point evaluation | 787632 | - |
| modexp 2048 b e=65537 / full exp | 25718 / 2538656 | - |
| Fp mul bn254 / bls12-381; inverse | 20 / 26; 1217 / 1832 | - |

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
- modexp: `bigint.zig` holds slice-based little-endian u64 limb helpers (no allocation),
  `Padded` (a big-endian byte view with implicit right zero padding, so the precompile
  input is never copied) and `Fixed(limbs_max)`. Odd modulus: CIOS Montgomery (runtime limb
  count, length-specialized up to 8 limbs) + dedicated squaring + sliding window (1..5
  bits chosen from exponent length). Montgomery form needs no R^2: base * R mod m comes
  from `reduce_shifted` (Knuth-D streaming one limb at a time, n extra zero limbs). Even
  modulus m = 2^k * q: q via Montgomery, 2^k via truncated products, joined by CRT
  (x = x1 + q * ((x2 - x1) * q^-1 mod 2^k)).
- modexp capacity: only the modulus is bounded (`operand_bytes_max` = 1024 bytes, 128
  limbs, the EIP-7823 limit). Base streams through the reducer and the exponent is scanned
  bitwise, so both may be any length (pre-Osaka). A modulus above capacity returns
  `error.ModulusTooLarge` from `modexp_checked` (pre-Osaka callers must handle it; `modexp`
  asserts instead). `Modexp(limbs)` is generic for a larger capacity.
- modexp above the static capacity (2026-11-05): pre-Osaka history has valid, affordable moduli
  over 1024 bytes (e.g. mod = 2^8192 costs 5547 gas under Berlin with 1-byte base/exponent),
  so rejecting them forked from Base. The arithmetic is now written once over slices:
  `run_in` partitions one flat `[]u64` scratch of `26 * limbs + 2` limbs (m, result, q, x1,
  x2, and a shared pool for the 16-entry window table, squared, accumulator, products).
  `Modexp(n)` just supplies a stack buffer, so the <= 1024-byte fast path is unchanged
  apart from a flat table layout. `precompile_modexp_run_with_scratch` /
  `modexp_with_scratch` take caller memory sized by `scratch_limbs_needed(modulus_len)`
  (the header length, so the EVM lane can size an arena from gas-bounded lengths; crypto
  never allocates). `ScratchTooSmall` and `ModulusTooLarge` (128 MiB sanity cap) are errors,
  not asserts, so no operand value reaches an assert. `precompile_modexp_run` keeps its
  contract (1024-byte capacity, `ModulusTooLarge` above); the EVM lane must pick the scratch
  entry point for pre-Osaka moduli above `operand_bytes_max`.
- modexp gas: pure helpers `adjusted_exponent_length`, `iteration_count`,
  `multiplication_complexity`, `gas_cost(rules, ...)` (byzantium/berlin/osaka, saturating
  u64) mirror revm's `modexp.rs`; `precompile_modexp_parse` returns `Padded` operands plus
  the 32-byte exponent head; base/modulus length > u64 is `LengthOverflow`, an exponent
  length > u64 saturates (so gas saturates). The evm lane charges gas and applies
  `check_osaka_limits`.

- P256VERIFY follows EIP-7951 (as revm's secp256r1 does): exact 160-byte input, r,s in
  [1, n-1], qx,qy < p, on curve, (0,0) rejected, R = u1*G + u2*Q must not be the identity,
  accept when x(R) mod n == r (checked projectively as x == r*Z^2 or (r+n)*Z^2). The hash is
  used as an integer mod n. Failure is `null` (empty output). Gas (6900 Osaka / 3450
  RIP-7212) is charged by the EVM lane, not here.
- P-256 verify is variable time (public inputs): Jacobian a=-3 formulas with explicit
  special cases (P=Q, P=-Q, identity), one interleaved wNAF pass, w=7 static affine table
  for G (32 odd multiples) and w=5 runtime table for Q (8 odd multiples).
- Public vectors: a curated 54-case subset (one per Wycheproof category and outcome) of
  the go-ethereum `p256Verify.json` precompile vectors in `testdata/p256_verify_vectors.txt`.
- Tried comptime "lazy rotation" scalar Keccak (rho folded into shifted-operand EOR/BIC,
  24 rounds unrolled): ~101 ops/round vs ~125 but 245ns vs 147ns per 32B hash on Apple M4
  (shifted-operand logic ops are slower there). Reverted; generic permutation stays.

- secp256k1 field: 4x64 limbs, weakly reduced (< 2^256), overflow folded with
  2^256 = 0x1000003D1 (mod p); branch-free add/sub/mul/sqr/half. Measured against
  libsecp256k1's 5x52 multiply ported to Zig on Apple M4: 4x64 mul 14ns latency / 5ns
  throughput vs 5x52 11.5ns / 9ns, so 4x64 stays (and add/sub need no magnitude tracking).
  Scalars mod n: 4x64, 512 -> 385 -> 258 -> 256-bit folding with 2^256 - n.
- secp256k1 recovery (variable time, public data): GLV split of both scalars, wNAF w=10 for
  G and lambda*G (comptime tables of 256 affine points each, computed with exact
  `comptime_int` arithmetic, independent of the runtime field code), w=5 Jacobian table
  for R; Strauss-Shamir joint loop. Jacobian formulas with explicit infinity and h = 0
  cases; libsecp256k1's 3M+4S doubling with `half`. r^-1 and the final Z^-1 use a
  variable-time safegcd (Bernstein-Yang, signed 62-bit limbs, branch-free 62-divstep
  batches) in `modinv.zig`. g_window 12 measured within noise of 10, so 10 (32 KiB tables).
- secp256k1 API: `ecrecover(hash, v_parity: u1, r, s) ?[64]u8`, `ecrecover_address`,
  `recover_point` (u2 recovery id, bit 1 = r + n with r + n < p), `recover_tx_address`
  (rejects s > n/2, EIP-2), `precompile_ecrecover(input) ?[32]u8` (input right-padded to
  128 bytes, v word exactly 27/28, r,s in [1, n-1], high s allowed, null = empty output).
  `sign`, `public_key`, `address` return `error.InvalidPrivateKey` for 0 or >= n.
- secp256k1 signing: RFC 6979 HMAC-SHA256 nonce (std hmac), constant-time k*G with a
  65x8 comptime table of signed 4-bit windows, masked full-row scans and complete
  projective mixed addition (RCB15 alg. 8); s normalized low, recovery id adjusted.
  The two inversions (k^-1 and Z^-1) use blinding: invert k*b / Z*b with the variable-time
  safegcd and multiply by b, where b comes from HMAC over the RFC 6979 state (without
  advancing it) or HMAC(private key) for `public_key`; this halved sign time (19 -> 11us).
  std's ECDSA adds 32 zero "noise" bytes to its RFC 6979 input, so it is not an RFC 6979
  oracle; vectors (EIP-155 example, key 1 / "Satoshi Nakamoto") cover the nonce instead.
- BLS12-381 (`bls12_381/`): tower Fp2 (u^2 = -1), Fp6 (v^3 = u + 1), Fp12 (w^2 = v) over
  `montgomery.Field(6, p)`; Frobenius/psi/beta constants are hardcoded and re-derived in tests.
  One generic Jacobian `curve.Curve(F, b)` serves G1 and G2. Subgroup checks are the
  endomorphism tests (G1: phi(P) = -x^2 P; G2: psi(P) = x P), cross-checked against [r]P.
  Pairing: Miller loop with Jacobian T and sparse 014 line products (zkcrypto-style
  formulas), at most 16 pairs per loop pass, one shared final exponentiation (HHT hard part).
- BLS12-381 bounds: no allocation. MSM runs signed-digit Pippenger in chunks of 256 points
  (window <= 7, stack digits + 64 buckets); the EIP-2537 MSM/pairing entry points decode in
  the same chunks, so input length only bounds time (callers apply Base's input caps).
  Code is variable time (public inputs only: precompiles and KZG verification).
- EIP-2537 vectors: a curated 72 KB binary subset of go-ethereum's public
  `core/vm/testdata/precompiles/bls*.json` (all hand-written `bls_*` cases, a few `matter_*`
  and `jwasinger` MSMs, all `fail-*` cases) in `bls12_381/vectors/eip2537.bin`; outputs, gas,
  and error kinds are checked. RFC 9380 J.9.1/J.10.1 hash-to-curve vectors are text files.
- `montgomery.Field.from_int_comptime` now reduces negative comptime ints (needed for
  Z = -(2 + u)).

- Point evaluation checks e(C - [y]G1 + [z]proof, G2) * e(-proof, [tau]G2) == 1 (equivalent to
  c-kzg's form, but both G2 inputs fixed and no G2 scalar mul); [tau]G2 is a decoded constant
  checked against the setup in tests. Vectors: all 114 fixed-length c-kzg-4844
  verify_kzg_proof cases (the 8 wrong-length ones cannot occur through the precompile).

- montgomery.mul accumulates each row as two straight carry chains (low halves, then high
  halves) instead of per-limb u128 multiply-add; the old form made LLVM spill NZCV
  (mrs/msr) and use adds+cinc pairs on AArch64.

- `montgomery.Field.inverse` is variable-time safegcd (`safegcd.zig`, generic over width,
  generalized from secp256k1/modinv.zig) because every user of the shared field handles
  public data; Fermat stays as `inverse_constant_time` for any future secret use.

- Dedicated Montgomery squaring (SOS: cross products once, doubled, then REDC with collected
  row carries) measured no faster than `mul(a, a)` on M4 (bls 27.6 vs 26.3 ns, bn254 21.1 vs
  19.7): latency is dominated by the serial reduction. Not adopted; `square` stays `mul`.

- bn254 (`bn254/`): tower Fp2 (u^2 = -1) / Fp6 (v^3 = 9 + u) / Fp12 (w^2 = v) over
  `montgomery.Field(4, p)`. One generic Jacobian `Curve(F, b)` serves G1 and the G2 twist.
  G1 mul uses GLV (beta, lambda, Babai rounding) with interleaved width-5 wNAF; the scalar is
  reduced mod r, which is exact because the G1 cofactor is 1. G2 subgroup check is
  psi(Q) == [6x^2]Q (eprint 2022/352). Miller loop over the NAF of 6x + 2 in homogeneous
  projective coordinates (D-twist sparse 034 lines), up to 8 pairs in lockstep per chunk
  sharing one Fp12 squaring, then one final exponentiation for the whole product
  (Fuentes-Castaneda hard part with Granger-Scott cyclotomic squaring). Official go-ethereum
  bn256 vectors in `bn254/vectors.zig`: all add/mul cases, 9 of 14 pairing cases (all 49
  were checked locally before curating).

## Log
- 2026-11-05: keccak256 one-shot, streaming, SIMD batch; vectors, seeded + coverage fuzz vs std; bench (32B: 147ns single, 71ns/msg batch, std 141ns).
- 2026-11-05: montgomery.Field generic over limbs; tested vs big ints for bn254, P-256, BLS12-381 (bench: 18.9ns bn254 mul, 31.0ns bls mul).
- 2026-11-05: kzg: embedded public trusted setup, versioned hash, 0x0A input framing + output; pairing check plugs in once BLS12-381 lands.
- 2026-11-05: sha256 (ARMv8 SHA2 path, 32B: 26ns vs std 33ns; 4KiB: 1455ns vs std 1643ns), ripemd160 (32B: 131ns; 4KiB: 8.6us), blake2f (12 rounds: 87ns, std compression 85ns); official/EIP-152 vectors 0-8, seeded + coverage fuzz.
- 2026-11-05: modexp (EIP-198/2565/7883/7823) + bigint: public geth vectors (22 incl. even moduli, gas for 3 rule sets), seeded differential fuzz vs std big ints, coverage fuzz; bench (ReleaseFast, M-series): 256-bit full exp 5.6us, 2048-bit e=65537 23.6us, 2048-bit full exp 2.52ms, 4096-bit e=65537 101us, 4096-bit full exp 21.9ms, 8192-bit e=65537 428us, even 2048-bit e=65537 24.4us.
- 2026-11-05: secp256r1 P256VERIFY (EIP-7951) on montgomery.Field; vectors, differential fuzz vs std ecdsa, coverage fuzz; bench (ReleaseFast: verify 51-71us depending on machine load vs std 108us).
- 2026-11-05: secp256k1: ecrecover/precompile 0x01, tx recovery (low s), RFC 6979 signing, public key/address; vectors, seeded differential fuzz vs std (mul, recovery, ecdsa verify), coverage fuzz of precompile vs std reference; bench (ReleaseFast, Apple M4, loaded host): ecrecover 28.8us (std verify 62us), sign 10.7us (std 75us), public_key 8.9us (std 65us).
- 2026-11-05: modexp: pre-Osaka moduli above 1024 bytes via caller-provided scratch (`precompile_modexp_run_with_scratch`, `scratch_limbs_needed`); 1025-byte Berlin example (5547 gas) and differential fuzz vs std big ints for 1025..3000-byte odd/even moduli.
- 2026-11-05: BLS12-381 + EIP-2537 precompiles 0x0b-0x11 (official geth vectors incl. fail cases and gas), RFC 9380 hash-to-curve G1/G2 + expand_message_xmd vectors, ZCash compressed G1/G2, seeded + coverage fuzz; bench (ReleaseFast, M-series): g1 add 477ns, g1 mul 87us, g2 mul 233us, pairing-2 0.72ms, map_fp_to_g1 95us, g1 msm-64 1.62ms.
- 2026-11-05: kzg verify_kzg_proof + 0x0A precompile on BLS12-381; c-kzg + geth vectors; 1.01 ms per call (1.26 ms before the G2-free rearrangement). Fixed kzg tests not running (missing refAllDecls).
- 2026-11-05: montgomery mul row-wise carry chains: bn254 19.6->18.2ns, bls 31.4->25.8ns; bls g1 mul 89->71us, msm-64 1.78->1.25ms, pairing-2 0.71->0.66ms.
- 2026-11-05: generic safegcd inversion: bls Fp inverse 13.8->1.8us, bn254 5.8->1.2us; map_fp_to_g1 77->41us, pairing-2 0.66->0.59ms, kzg point eval 1.01->0.88ms.
- 2026-11-05: bls g1.mul_glv (GLV split by x^2, width-5 NAF, affine tables, mixed adds): 71->42us; kzg point eval now uses it (0.88->0.76ms).
- 2026-11-05: bn254 add/mul/pairing precompiles (EIP-196/197) on montgomery.Field; official geth vectors, G2 subgroup check, bilinearity + seeded/coverage fuzz; bench (ReleaseFast, M-series): add 1.73us, mul 12.2us, pairing 2 pairs 0.56ms.
- 2026-11-05: bls g2.mul_gls (psi = [x], four 64-bit digits, width-5 NAF, affine tables): 198->80us; single-point MSM (G1MSM/G2MSM with k=1) now uses GLV/GLS. Review of bn254 + BLS precompiles: no defects.
- 2026-11-05: bls msm: stateless Booth digits, one pass over all points (no 256-point chunks), window up to 10 (G1) / 9 (G2): msm-4096 / blob_to_kzg_commitment 56.8->44.0ms.
