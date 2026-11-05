# Lane: crypto

Owns `src/common/crypto`. Zero deps: may use `std.crypto` as a correctness oracle or
fallback but hot paths should be our own, optimized implementations.

## Backlog
- [x] keccak256: fast single + batch (SIMD multi-lane) implementation, vectors, bench vs std.
- [x] keccak256 single-message: closed. Lazy rotation measured slower; published AArch64 work
  (Becker-Kannwischer 2022) finds scalar fastest for one message on Apple cores, NEON-SHA3 only
  wins multi-lane, which `keccak256_batch` covers.
- [x] sha256 (use/beat std), ripemd160, blake2f (EIP-152 compression), identity.
- [x] secp256k1: field/scalar arithmetic (5x52 limbs or similar), GLV endomorphism, wNAF, ecrecover (precompile 0x01 semantics), signing (RFC 6979, constant time), public key → address. Vectors + differential fuzz vs `std.crypto.ecc.Secp256k1`.
- [x] Generic Montgomery prime field `montgomery.Field(limbs, p)` shared by bn254/BLS/P256.
- [x] montgomery: faster inversion (safegcd); dedicated squaring evaluated (no gain on M4).
- [x] montgomery: no-carry CIOS for spare-bit moduli evaluated: no gain over row-wise chains
  (bn254 18.3ns, bls 25.8ns either way); not adopted.
- [x] modexp (EIP-198/2565/7883 gas lives in evm; arithmetic here), big-int helpers.
- [x] modexp: faster inner loops for moduli > 512 bits (4-way unrolled row MAC): 2048b full exp
  2.60->1.87ms, 4096b 22.3->15.8ms.
- [x] modexp window 6 / Karatsuba squaring: closed by analysis (window 6 saves ~1.3% of
  multiplications at 2048 bits for 2x table scratch; Karatsuba only pays above 2048-bit moduli).
- [x] bn254 (alt_bn128): add, mul, pairing check (EIP-196/197) with official vectors.
- [x] bn254 perf: lazy-reduction Fp2 (pairing 559->494us). Precomputed G2 lines do not apply
  (EVM pairing inputs are variable); Fp6-level lazy reduction does not fit (4p^2 headroom only).
- [x] BLS12-381: G1/G2 ops, MSM, pairing, map-to-curve (EIP-2537 precompiles).
- [x] BLS12-381 perf: GLV/GLS scalar mul, batch-affine Pippenger buckets (done); dedicated
  squaring and lazy Fp2 evaluated, both slower on M4 (not adopted).
- [x] BLS12-381: single-exponentiation SSWU square root for Fp (map_fp_to_g1 41->34us).
- [x] KZG point evaluation (EIP-4844 precompile 0x0A) with the public trusted setup (embed the public setup as a compressed file or generate from the public ceremony output).
- [x] KZG blob API (EIP-4844 polynomial-commitments): blob_to_kzg_commitment (MSM over the
  Lagrange setup), compute_challenge, barycentric evaluation, compute_kzg_proof,
  compute/verify_blob_kzg_proof (+ batch) — needed by the batcher and blob sidecar checks.
- [x] KZG cells (EIP-7594 / Osaka blob tx proofs): G1 monomial setup, FK20 cell proofs, verify,
  recover. Landed (ddbf591, 4391655, ef23739); reviewed clean; ReleaseSafe vectors incl. FK20 pass.
- [x] bls: prepared G2 lines (`pairing.prepare`, `pairing_check_prepared`); KZG fixed G2 lines
  prepared at comptime.
- [x] bls GLV-split MSM: closed. Needs 2n half-scalars of scratch (128 KiB at n = 4096) or
  per-window recomputation (~same cost as the ~5 ms of bucket sums it saves).
- [x] fuzz coverage audit: every precompile/decoder file has a std.testing.fuzz target; added
  safegcd (BLS + secp moduli) and lazy-reduction checks to the montgomery target.
- [x] safegcd codegen: the generic copy's i318 accumulator was the 10% gap; rounded to whole
  words, secp256k1 now uses `safegcd.zig` and modinv.zig is deleted.
- [x] p256 window-8 generator table: closed by analysis (removes ~4 of ~32 mixed adds, ~2%).
- [ ] fuzz campaigns: first pass done (keccak 1.4M runs, every other target 20K, ReleaseSafe,
  no failures). Note: one `--fuzz` run spends its budget on a single test, so run each target
  with its own `-Dtest-filter`. Longer runs pending lower host load.
- [x] secp256k1 p2p API (base/base discv5/ENR/libp2p use k256/secp256k1 for these):
  `compress_public_key`, `decompress_public_key`, `decode_public_key`, `verify` (plain ECDSA,
  accepts high s like std; `is_low_s` for libsecp/k256 semantics), `ecdh` (discv5: compressed
  shared point, constant time via `point.mul_ct`). verify 24us (std 63us), ecdh 29us (std 69us).
- [x] constant-time audit of secret paths (advisor, gpt-sol): LLVM turned mask selects into
  branches/selective loads on x86_64 (table lookup, accumulator select) and `sign` branched
  on high s. Fixed with `ct.zig` (asm value barrier on masks; `ct.equal`/`ct.nonzero`),
  `Scalar.is_high_bit`/`select`. Verified by emitting ReleaseFast asm for x86_64 and aarch64:
  no data-dependent branches in lookup/select/low-s (only the public 8-entry loop edge), all
  table rows loaded. No measurable bench cost. Accepted residuals (standard): key validation
  exits, RFC 6979 retry loop, zero-blind fallback, blinded (not fixed-time) inversions.
- [x] sha256 ARMv8 SHA2: already in place (`sha256.hardware_accelerated`, sha256h/h2 asm +
  su0/su1 intrinsics); closed by inspection.
- [x] secp256k1 batch ecrecover: deferred. Senders are recovered one envelope at a time via
  `tx.Envelope.recover_sender(recoverer)`; a batch API (~5% from a shared inversion) is only
  worth adding if block import starts recovering in batches.
- [x] ecdh via constant-time GLV: deferred by decision. ECDH runs once per discv5 session
  handshake; ~11us saving does not justify a constant-time lambda split (current
  `split_lambda` is not audited for secret inputs).
- [x] KZG blob verify perf: `evaluate_blob` evaluates straight from blob bytes as one
  running fraction (4 muls/element, 4 independent lanes, raw limbs read as Montgomery form
  with one final *R), replacing conversion + batch inversion (6 muls/element, serial chains).
  Evaluation 330 -> 214us per blob; verify_blob_kzg_proof 1.05 -> 0.91-0.99ms; batch (6)
  3.95 -> 3.25ms. 8 lanes (265us) and 2 lanes (247us) were slower. New component benches:
  kzg/compute_challenge 45us, kzg/decompress_g1 37us.
- [x] bn254 pairing perf: G2 subgroup check rewritten (502 -> ~460us for 2 pairs); split is
  Miller loop 247us / final exp 166us. Further work (034x034 line products ~5% of the
  Miller loop, Karabina squarings ~20% of final exp) closed by analysis: pairing-2 costs
  ~4 ns/gas, well under ecrecover's ~9.5 ns/gas, so it is not a gas-DoS bottleneck.
- [x] BLS pairing perf: closed by the same analysis (pairing-2 588us / 102,900 gas =
  ~5.7 ns/gas).
- [x] x86_64 test coverage from the arm64 host. Baseline / v2 under Rosetta:
  `zig build test -Dtarget=x86_64-macos -frosetta -Dtest-filter=crypto` (all pass). For
  x86_64_v3 (AVX2) use qemu, not Rosetta: cross-build with `zig test -OReleaseSafe -target
  x86_64-linux-musl -mcpu x86_64_v3 --dep build_options -Mroot=src/base.zig
  -Mbuild_options=<cached options.zig> --test-filter <f> --test-no-exec -femit-bin=<bin>`
  and run `qemu-x86_64 -cpu max <bin>` in an arm64 alpine container (`apk add qemu-x86_64`).
- [x] x86_64_v3 cells "miscompile": FK20 proofs for 4 of 7 c-kzg blobs came out wrong only
  under Rosetta with optimized v3 builds (Debug v3, baseline, v2, v2+avx+bmi2+adx correct;
  ReleaseSafe and ReleaseFast gave different wrong points). Stage hashing showed every
  FK20 stage matches when run step by step. The same x86_64_v3 ReleaseSafe/ReleaseFast
  code run under qemu `-cpu max` passes all 124 kzg tests including the EIP-7594 vectors,
  and arm64 passes natively. Verdict: Rosetta 2 AVX emulation bug, not a needlefish or LLVM
  defect; no code change. The c-kzg EIP-7594 vectors are the regression test (run them under
  qemu for x86_64_v3).
- [x] FK20 fixed-base prover tables (opt-in, `Settings.attach_prover_tables`, ~25 MiB):
  `bls.msm.msm_precomputed` over shifts [2^(9w)]P (w < 29) does each of the 128 row MSMs in
  one batch-affine bucket pass without doublings. compute_cells_and_kzg_proofs 202 -> 93 ms
  (window 7/8/10: 108/108/109 ms). Proofs checked against every c-kzg EIP-7594 vector with
  and without tables; seeded + coverage-guided differential vs `msm`. Batcher should attach.
- [x] Wycheproof vectors (C2SP, Apache-2.0) in `wycheproof_tests.zig`: secp256k1 ECDSA P1363
  SHA-256 (234 tests), secp256r1 ECDSA P1363 SHA-256 (241, EIP-7951 semantics), secp256k1
  ECDH on raw points (495, incl. 21 invalid-curve / invalid-point rejections). Converted by
  `etc/scripts/crypto-wycheproof.py` into `vectors/*.txt` (~250 KB); non-64-byte P1363
  signatures and ASN.1/wrong-curve ECDH cases are dropped (not expressible in the raw API).
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

## Precompile time per gas (2026-11-05, M4 Pro, ReleaseFast, loaded host)

| precompile | gas | time | ns/gas |
| --- | --- | --- | --- |
| ecrecover (0x01) | 3000 | 28.5 us | 9.5 |
| p256verify, RIP-7212 pricing (Fjord..pre-Azul) | 3450 | 47.7 us | 13.8 |
| p256verify, EIP-7951 pricing (Osaka/Azul) | 6900 | 47.7 us | 6.9 |
| bn254 add (0x06) | 150 | 1.72 us | 11.5 |
| bn254 mul (0x07) | 6000 | 12.2 us | 2.0 |
| bn254 pairing, 2 pairs (0x08) | 113000 | 494 us | 4.4 |
| bls12-381 pairing, 2 pairs (0x0f) | 102900 | 588 us | 5.7 |
| bls12-381 map_fp_to_g1 (0x10) | 5500 | 34 us | 6.2 |
| kzg point evaluation (0x0a) | 50000 | 650 us | 13.0 |

ecrecover sets the accepted ratio (~9.5 ns/gas). Above it: bn254 add (11.5, dominated by
input decoding and one inversion), p256 under RIP-7212 pricing (13.8), kzg point evaluation
(13.0). All stay within ~1.5x of ecrecover, so none is a block-time outlier.

## Decisions

- x86_64_v3 results under Rosetta are not trusted (wrong FK20 output reproduced only there); verify AVX2 builds with qemu-x86_64 -cpu max.

- Constant-time code must route every secret-derived mask or flag through `ct.barrier` (`ct.mask`, `ct.equal`, `ct.nonzero`); plain `(a & ~m) | (b & m)` is not enough, LLVM re-branches it on x86_64. Check new secret paths by emitting ReleaseFast asm for x86_64-linux and aarch64-linux.
- Keccak permutation is generic over the lane type (`u64` or `@Vector(n, u64)`); batch width
  is 2 on NEON (LLVM emits EOR3/BCAX/XAR/RAX1), 4 on AVX2, 8 on AVX-512. Unrolling the
  round loop measured slower on aarch64, so it is not unrolled.
- Benchmarks live in `src/common/crypto/bench.zig`; `src/testing/bench_main.zig` calls
  `crypto.bench.run(io, filter)` with the process `Io` as the only clock.

- Prime fields share `montgomery.Field(limbs, modulus)`: comptime-derived constants, CIOS
  multiplication, masked final subtraction, Fermat inverse, p = 3 mod 4 sqrt.

- KZG setup: the public c-kzg-4844 `trusted_setup.txt` is stored as raw compressed bytes in
  `kzg/trusted_setup.bin` in file order: 4096 G1 Lagrange, 65 G2 monomial, then 4096 G1
  monomial points (EIP-7594 cells), 399456 bytes, sha256 608ac720...fae3 (asserted in tests).
  The first 202848 bytes are byte-identical to the previous Lagrange+G2 file. Consistency
  tests: the Lagrange points sum to monomial point 0 (= the G1 generator) and
  e([tau^(i+1)]G1, G2) = e([tau^i]G1, [tau]G2) for sampled i.

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

- EIP-7594 cells (`kzg/cells.zig`, re-exported as `kzg.cells`): spec names
  `compute_cells`, `compute_cells_and_kzg_proofs`, `verify_cell_kzg_proof_batch`,
  `recover_cells_and_kzg_proofs` (+ `recover_cells` without proofs). No allocation:
  `Settings.Storage` (~1.15 MiB: 8193 roots of the order-8192 domain, 64 monomial G1
  points, prepared [tau^64]G2 lines, FK20 tables 128 x 64 affine points) and `Workspace`
  (~1.1 MiB) come from the caller; `Settings.init_verifier` skips the FK20 tables.
  Verification batch scratch is caller-provided (`VerifyStorage(n)`, ~240 B per cell).
  Malformed input (length mismatch, index >= 128, non-canonical element, invalid point)
  is an error, never `false`, as in c-kzg; every proof, commitment, and cell is validated
  before hashing. Recovery requires strictly ascending indices (spec) and recomputes all
  cells from the degree < 4096 polynomial even when all 128 cells are given (spec; c-kzg
  copies them through, which only differs for inconsistent inputs).
- FFTs (`kzg/fft.zig`) are iterative radix-2 (bit-reversal permutation + log2 n passes), in
  place, any power of two up to 8192 by striding the shared root table. G1 FFT butterflies
  use GLV scalar multiplication and skip the unit twiddle. FK20 follows c-kzg `fk20.c`
  (circulant size 128, the 1/128 of the inverse G1 FFT folded into the MSM scalars); the
  128 per-row MSMs use the generic `msm.msm` (64 points each); c-kzg's optional fixed-base
  tables (`wbits`, 96 MiB at 8 bits) are not implemented.
- EIP-7594 vectors: c-kzg-4844 `tests/{compute_cells,compute_cells_and_kzg_proofs,
  verify_cell_kzg_proof_batch,recover_cells_and_kzg_proofs,
  compute_verify_cell_kzg_proof_batch_challenge}` curated into `kzg/cell_vectors.txt`
  (155 KiB): cells are references into the cells of the seven blobs already committed in
  `blob_vectors.bin` (checked against the sha256 of each vector's full cell output), proofs
  are stored in full. Covered: all 7+4 compute cases (wrong-length blobs map to the
  synthetic invalid blobs; the type makes other lengths impossible), all 32 verify cases,
  all 18 recover cases, 8 of 10 challenge cases (the two ~1 MB ones are dropped; the
  128-cell verify cases exercise the same hash). Debug runs cells, recovery of cells, and
  small verify batches; FK20 proofs and 128-cell batches run in ReleaseSafe/ReleaseFast.

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

- KZG blob API (`kzg/blob.zig`, consensus-specs deneb polynomial-commitments): `Settings.init(storage)`
  decodes the 4096 Lagrange G1 points (unchecked: public setup, hash asserted) into
  caller-provided `Settings.Storage` (about 560 KiB) and builds the bit-reversed roots of unity
  (omega = 7^((r-1)/4096)). The setup file holds the Lagrange points in natural order; they are
  stored bit-reversed at init, as the spec applies `bit_reversal_permutation` to the setup.
  Operations take a caller-provided `Workspace` (about 512 KiB) and never allocate. Evaluation and
  proofs share one batch inversion (Montgomery trick, zeros skipped) of z - w_i; for z in the
  domain y = p[m] and the quotient entry m uses `compute_quotient_eval_within_domain`. The
  quotient divides by (w_i - z) as in the spec (a sign slip here was caught by the vectors).
  `compute_challenge` and the batch r hash follow the spec byte for byte. The batch check folds
  the y terms into one generator multiple (as c-kzg does): two MSMs of sizes n and 2n+1 plus one
  two-pair pairing check via `verify.pairing_check_fixed_g2`; scratch is caller-provided
  (`BatchStorage(n)`), blobs are passed as `[]const *const Blob`. Empty batch is valid.
- Blob MSM: `bls.msm.msm` over all 4096 points (the bls lane's single-pass Booth Pippenger, c = 10). A
  dedicated blob-only variant with a carry array measured the same as main's batch-affine msm (34 ms before it, 26 ms now), so it was dropped.
- Blob vectors: 105 c-kzg-4844 mainnet cases (9 blob_to_kzg_commitment, 48 compute_kzg_proof, 11
  compute_blob_kzg_proof, 23 verify_blob_kzg_proof, 14 batch) in `kzg/blob_vectors.txt`, with the
  7 distinct valid blobs (896 KiB) in `blob_vectors.bin`; the two non-canonical blobs are
  synthesised in the test and wrong-length cases (not expressible with typed arrays) are dropped.
  In Debug (MSM and subgroup checks take seconds) the vector test runs all error cases, one
  in-domain proof, one verify and one batch (about 8 s incl. a 2 s setup decode); all other
  modes run every vector plus seeded round trips, a batch test, and a batch test.

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
- 2026-11-05: bls G1 msm >= 256 points: batch-affine bucket accumulation (128 pending adds per inversion, Jacobian side buckets for collisions): msm-4096 44.0->36.3ms.
- 2026-11-05: KZG blob API (blob_to_kzg_commitment, compute_kzg_proof, compute/verify_blob_kzg_proof, batch) with c-kzg vectors, round trips, fuzz; bench (ReleaseFast, Apple M-series, loaded host): commitment 26 ms, compute_blob_kzg_proof 27 ms, verify_blob_kzg_proof 1.1 ms, batch of 6 verify 3.9 ms (0.65 ms/blob).
- 2026-11-05: bls prepared G2 lines: pairing-2 588->493us; KZG checks use comptime-prepared lines for G2 and [tau]G2: point evaluation 0.76->0.65ms, verify_blob_kzg_proof 1.0ms.
- 2026-11-05: montgomery lazy reduction (mul_wide/reduce_wide/add_unreduced, needs 4p < R); bn254 Fp2 mul uses it: pairing 2 pairs 559->494us. Tried on BLS12-381 Fp2 (6 limbs): slower (586->612us), not adopted.
- 2026-11-05: review of KZG blob API, prepared lines, MSM (Booth + batch-affine), GLV/GLS: no consensus defects; fixed batch length mismatch to return InvalidInputLength instead of asserting.
- 2026-11-05: tried replacing secp256k1/modinv.zig with generic safegcd.Modulus(u256, ...): ecrecover 28.6->31.7us (same algorithm, codegen difference); kept the specialized copy.
- 2026-11-05: bls SSWU (Fp) single exponentiation via sqrt(-Z) trick: map_fp_to_g1 41->34us. Closed keccak single-message item (see backlog).
- 2026-11-05: modexp large-modulus Montgomery rows unrolled 4-way (small comptime lengths keep fused loops): 2048b full exp 2.60->1.87ms, 4096b 22.3->15.8ms, 256b unchanged.
- 2026-11-05: p256 verify: safegcd s^-1 (was Fermat), affine Q table via one shared inversion + mixed adds: 50.7->47.7us.
- 2026-11-05: safegcd Wide rounded to whole words (i318 -> i320); secp256k1 switched to the generic safegcd (ecrecover 28.5us, unchanged) and modinv.zig removed.
- 2026-11-05: coverage fuzz pass (ReleaseSafe): keccak 1.4M runs; sha256, ripemd160, blake2f, modexp, secp256k1, p256, kzg verify/framing/blob, safegcd, montgomery, bls precompile 20K each (bn254 shares the bls filter name): no failures.
- 2026-11-05: kzg EIP-7594 cells: G1 monomial setup, Fr/G1 FFT, FK20 compute_cells_and_kzg_proofs,
  verify_cell_kzg_proof_batch, recover_cells_and_kzg_proofs; all c-kzg vectors (see Decisions).
  Bench (ReleaseFast, M4 Pro, loaded host): compute_cells 1.38 ms, compute_cells_and_kzg_proofs
  189 ms, verify batch 1 cell 2.11 ms / 128 cells 13.7 ms, recover from 64 cells + proofs 207 ms.
- 2026-11-05: EIP-7594 cells (FK20 compute 189 ms/blob, batch verify, recovery) reviewed: no defects; setup bytes match public c-kzg setup; ReleaseSafe cell tests (FK20 proofs) green.
- 2026-11-05: added coverage fuzz for cell recovery (arbitrary indices/cells never crash; recovered cells canonical); 3K ReleaseSafe runs clean.
- 2026-11-05: montgomery.pow sliding window (w=5, public exponents): bls map_fp_to_g1 34->31.8us, bls inverse_constant_time 13.8->11.1us, bn254 5.8->5.2us.
- 2026-11-05: cell verify cost model (128 cells, 12.1 ms): ~5 ms proof decompression (sqrt ~15 us + subgroup check ~25 us each; no sound batched subgroup check because G1 cofactor has small factors), ~5 ms two 128-point MSMs, 1.3 ms 64-point MSM, 0.5 ms pairing. A 6-blob v1 sidecar is ~70-80 ms. No further work planned.
- 2026-11-05: secp256k1 SEC1 encode/decode, plain verify, constant-time ecdh (`point.mul_ct`, RCB15 complete doubling) with std-oracle tests and a coverage fuzz target. BLS signatures (sign/aggregate) not added: base/base uses BLS12-381 only for the EIP-2537 precompiles, not p2p/consensus.
- 2026-11-05: constant-time hardening (`ct.zig` value barrier) after advisor audit; verify r+n and infinity vectors added.
- 2026-11-05: fuzz campaign (ReleaseSafe, nice 19): SEC1/verify/ecdh 200K runs, ecrecover precompile 500K runs, clean.
- 2026-11-05: KZG `evaluate_blob` (fraction-sum barycentric, 4 lanes): batch verify (6) 3.95 -> 3.25ms.
- 2026-11-05: bn254 G2 subgroup check [x+1]Q + psi([x]Q) + psi^2([x]Q) = psi^3([2x]Q) (one 63-bit mul instead of 127-bit [6x^2]Q; old test kept as oracle): pairing-2 502 -> ~460us. Split: Miller loop (2 pairs) 247us, final exponentiation 166us (new benches).
- 2026-11-05: fuzz campaign: p256 precompile 300K runs clean.
- 2026-11-05: crypto suite passes on x86_64 (baseline and x86_64_v3) under Rosetta.
- 2026-11-05: x86_64_v3 cells failure traced to Rosetta (qemu -cpu max passes all kzg tests for v3 ReleaseSafe/ReleaseFast); documented the qemu path.
- 2026-11-05: full crypto suite x86_64_v3 ReleaseSafe under qemu -cpu max: 262/262 pass (incl. heavy KZG/cells); blob fuzz 20K runs clean.
- 2026-11-05: Wycheproof ECDSA (secp256k1, P-256) and secp256k1 ECDH vectors, all pass.
- 2026-11-05: modexp raw-input fuzz 300K runs clean but shallow (47 coverage points: inputs stop at header parsing); added a structured operand target checked against the std.math.big oracle.
- 2026-11-05: FK20 prover tables, cells+proofs 202 -> 93 ms per blob.
- 2026-11-05: modexp operand-vs-oracle fuzz 200K runs clean (1559 unique runs, 1028 coverage points vs 47 for the raw-input target).
- 2026-11-05: msm_precomputed vs msm fuzz 50K runs clean (229 coverage points).
