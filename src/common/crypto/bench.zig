//! Crypto micro benchmarks. Called from `src/testing/bench_main.zig` with the
//! process `Io` injected (the only clock source), so library code stays pure.
//! Each case reports ns/op for our implementation and, when std has one, the
//! std implementation as a baseline.

const std = @import("std");
const assert = std.debug.assert;
const keccak = @import("keccak.zig");
const secp256k1 = @import("secp256k1/root.zig");
const montgomery = @import("montgomery.zig");
const bls_bench = @import("bls12_381/bench.zig");
const modexp = @import("modexp.zig");
const p256 = @import("p256.zig");
const kzg = @import("kzg/root.zig");
const bn254 = @import("bn254/root.zig");
const kzg_bench = @import("kzg/bench.zig");

const kzg_bench_input_hex = "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f" ++
    "549b564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d3630624d25032e67a7e6a" ++
    "4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a18f59a8d2a1a625a17f3fea0fe5eb8c896db3" ++
    "764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7873033e038326e87ed3e1276" ++
    "fd140253fa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a";

fn bench_kzg_point_evaluation(iterations: u32) u64 {
    var input: [kzg.input_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&input, kzg_bench_input_hex) catch unreachable; // Constant.
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const output = kzg.precompile_point_evaluation(&input) catch unreachable; // Valid.
        accumulator +%= output[31];
    }
    return accumulator;
}
const Prng = @import("../../testing/prng.zig").Prng;

const Bn254Fp = montgomery.Field(
    4,
    0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47,
);
const Bls12Fp = montgomery.Field(
    6,
    (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192) |
        0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab,
);

fn bench_field_mul(comptime F: type) fn (u32) u64 {
    return struct {
        fn run(iterations: u32) u64 {
            var a = F.from_int(0x1234_5678_9abc_def0);
            const b = F.from_int(0x0fed_cba9_8765_4321);
            for (0..iterations) |_| a = a.mul(b);
            return a.limbs_value[0];
        }
    }.run;
}
const sha256 = @import("sha256.zig");
const ripemd160 = @import("ripemd160.zig");
const blake2f = @import("blake2f.zig");

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
};

fn bench_keccak_32(iterations: u32) u64 {
    var data: [32]u8 = @splat(0x5a);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = keccak.keccak256(&data);
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_keccak_32_std(iterations: u32) u64 {
    var data: [32]u8 = @splat(0x5a);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&data, &digest, .{});
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_keccak_32_batch(iterations: u32) u64 {
    var data: [keccak.batch_width][32]u8 = @splat(@splat(0x5a));
    var accumulator: u64 = 0;
    // Each batch call hashes `batch_width` messages; report per message.
    for (0..iterations / keccak.batch_width) |_| {
        var inputs: [keccak.batch_width][]const u8 = undefined;
        for (&inputs, &data) |*input, *message| input.* = message;
        var digests: [keccak.batch_width][32]u8 = undefined;
        keccak.keccak256_batch(&inputs, &digests);
        for (&data, digests) |*message, digest| message[0] = digest[0];
        accumulator +%= digests[0][31];
    }
    return accumulator;
}

fn bench_keccak_4k(iterations: u32) u64 {
    var data: [4096]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = keccak.keccak256(&data);
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_keccak_4k_std(iterations: u32) u64 {
    var data: [4096]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&data, &digest, .{});
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_sha256_32(iterations: u32) u64 {
    var data: [32]u8 = @splat(0x5a);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = sha256.sha256(&data);
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_sha256_32_std(iterations: u32) u64 {
    var data: [32]u8 = @splat(0x5a);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&data, &digest, .{});
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_sha256_4k(iterations: u32) u64 {
    var data: [4096]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = sha256.sha256(&data);
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_sha256_4k_std(iterations: u32) u64 {
    var data: [4096]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&data, &digest, .{});
        data[0] = digest[0];
        accumulator +%= digest[31];
    }
    return accumulator;
}

fn bench_ripemd160_32(iterations: u32) u64 {
    var data: [32]u8 = @splat(0x5a);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = ripemd160.ripemd160(&data);
        data[0] = digest[0];
        accumulator +%= digest[19];
    }
    return accumulator;
}

fn bench_ripemd160_4k(iterations: u32) u64 {
    var data: [4096]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const digest = ripemd160.ripemd160(&data);
        data[0] = digest[0];
        accumulator +%= digest[19];
    }
    return accumulator;
}

/// MODEXP with a `modulus_bytes` modulus (odd unless `even`) and `exponent_bytes` exponent
/// of full width (or the 17-bit 65537 when `exponent_bytes` is 3 with the fixed RSA value).
fn bench_modexp(
    comptime modulus_bytes: u32,
    comptime exponent_bytes: u32,
    comptime even: bool,
) fn (u32) u64 {
    return struct {
        fn run(iterations: u32) u64 {
            var prng = Prng.init(modulus_bytes * 1000 + exponent_bytes);
            var base: [modulus_bytes]u8 = undefined;
            var exponent: [exponent_bytes]u8 = undefined;
            var modulus: [modulus_bytes]u8 = undefined;
            prng.fill(&base);
            prng.fill(&modulus);
            modulus[0] |= 0x80;
            const low = modulus[modulus_bytes - 1];
            modulus[modulus_bytes - 1] = if (even) low & 0xfe else low | 1;
            if (exponent_bytes == 3) {
                exponent = .{ 0x01, 0x00, 0x01 };
            } else {
                prng.fill(&exponent);
                exponent[0] |= 0x80;
            }
            var accumulator: u64 = 0;
            for (0..iterations) |_| {
                var out: [modulus_bytes]u8 = undefined;
                modexp.modexp(&base, &exponent, &modulus, &out);
                base[modulus_bytes - 1] ^= out[modulus_bytes - 1];
                base[1] = out[1];
                accumulator +%= out[0];
            }
            return accumulator +% base[0];
        }
    }.run;
}

fn bench_blake2f_12(iterations: u32) u64 {
    var h = [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var m: [16]u64 = @splat(0x0123456789abcdef);
    for (0..iterations) |index| {
        blake2f.blake2f(12, &h, &m, .{ index, 0 }, false);
        m[0] = h[0];
    }
    return h[7];
}

/// std baseline: one 128-byte message is a single BLAKE2b-512 compression (12 rounds).
fn bench_blake2b_128_std(iterations: u32) u64 {
    var data: [128]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var digest: [64]u8 = undefined;
        std.crypto.hash.blake2.Blake2b512.hash(&data, &digest, .{});
        data[0..64].* = digest;
        accumulator +%= digest[63];
    }
    return accumulator;
}

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// One valid P-256 signature over a fixed prehashed message, shared by both benches.
const P256Sample = struct {
    hash: [32]u8,
    r: [32]u8,
    s: [32]u8,
    qx: [32]u8,
    qy: [32]u8,
    public_key: Ecdsa.PublicKey,

    fn make() P256Sample {
        const key_pair = Ecdsa.KeyPair.generateDeterministic(@splat(0x42)) catch unreachable;
        const hash: [32]u8 = @splat(0x17);
        const signature = key_pair.signPrehashed(hash, null) catch unreachable;
        const sec1 = key_pair.public_key.toUncompressedSec1();
        return .{
            .hash = hash,
            .r = signature.r,
            .s = signature.s,
            .qx = sec1[1..33].*,
            .qy = sec1[33..65].*,
            .public_key = key_pair.public_key,
        };
    }
};

fn bench_p256_verify(iterations: u32) u64 {
    const sample = P256Sample.make();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const valid = p256.verify(sample.hash, sample.r, sample.s, sample.qx, sample.qy);
        assert(valid);
        accumulator +%= @intFromBool(valid);
    }
    return accumulator;
}

fn bench_p256_verify_std(iterations: u32) u64 {
    const sample = P256Sample.make();
    const signature: Ecdsa.Signature = .{ .r = sample.r, .s = sample.s };
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        signature.verifyPrehashed(sample.hash, sample.public_key) catch unreachable;
        accumulator +%= 1;
    }
    return accumulator;
}

/// Public dev mnemonic account 0 key: deterministic, publicly known.
const bench_private_key: [32]u8 = .{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};

fn bench_ecrecover(iterations: u32) u64 {
    var hash: [32]u8 = @splat(0x42);
    var accumulator: u64 = 0;
    // Distinct hashes per signature so no work is shared between iterations.
    const signature = secp256k1.sign(bench_private_key, hash) catch unreachable;
    for (0..iterations) |index| {
        hash[0] = @truncate(index);
        const recovered = secp256k1.ecrecover_address(
            hash,
            @truncate(signature.recovery_id),
            signature.r,
            signature.s,
        );
        accumulator +%= if (recovered) |address| address[0] else 1;
    }
    return accumulator;
}

fn bench_sign(iterations: u32) u64 {
    var hash: [32]u8 = @splat(0x24);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const signature = secp256k1.sign(bench_private_key, hash) catch unreachable;
        hash[0] = signature.s[0];
        accumulator +%= signature.r[31];
    }
    return accumulator;
}

fn bench_public_key(iterations: u32) u64 {
    var private_key = bench_private_key;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const public = secp256k1.public_key(private_key) catch unreachable;
        private_key[31] = public[63] | 1;
        accumulator +%= public[0];
    }
    return accumulator;
}

fn bench_verify(iterations: u32) u64 {
    const hash: [32]u8 = @splat(0x42);
    const signature = secp256k1.sign(bench_private_key, hash) catch unreachable;
    var public = secp256k1.public_key(bench_private_key) catch unreachable;
    var accumulator: u64 = 0;
    for (0..iterations) |index| {
        var digest = hash;
        digest[0] = @truncate(index);
        accumulator +%= @intFromBool(secp256k1.verify(digest, signature.r, signature.s, &public));
    }
    public[0] ^= @truncate(accumulator);
    return accumulator +% public[0];
}

fn bench_ecdh(iterations: u32) u64 {
    var private_key = bench_private_key;
    const public = secp256k1.public_key(bench_private_key) catch unreachable;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const shared = secp256k1.ecdh(private_key, &public) catch unreachable;
        private_key[31] = shared[32] | 1;
        accumulator +%= shared[1];
    }
    return accumulator;
}

fn bench_ecdh_std(iterations: u32) u64 {
    var private_key = bench_private_key;
    const public = std.crypto.ecc.Secp256k1.basePoint.mul(bench_private_key, .big) catch
        unreachable;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const shared = (public.mul(private_key, .big) catch unreachable).toCompressedSec1();
        private_key[31] = shared[32] | 1;
        accumulator +%= shared[1];
    }
    return accumulator;
}

const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

fn bench_public_key_std(iterations: u32) u64 {
    var private_key = bench_private_key;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const public = std.crypto.ecc.Secp256k1.basePoint.mul(private_key, .big) catch unreachable;
        const encoded = public.toUncompressedSec1();
        private_key[31] = encoded[64] | 1;
        accumulator +%= encoded[1];
    }
    return accumulator;
}

fn bench_sign_std(iterations: u32) u64 {
    const key_pair = StdEcdsa.KeyPair.fromSecretKey(
        StdEcdsa.SecretKey.fromBytes(bench_private_key) catch unreachable,
    ) catch unreachable;
    var hash: [32]u8 = @splat(0x24);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const signature = key_pair.signPrehashed(hash, null) catch unreachable;
        hash[0] = signature.s[0];
        accumulator +%= signature.r[31];
    }
    return accumulator;
}

/// std has no public key recovery; ECDSA verification (u1 G + u2 Q plus checks)
/// is the closest equivalent workload.
fn bench_verify_std(iterations: u32) u64 {
    const key_pair = StdEcdsa.KeyPair.fromSecretKey(
        StdEcdsa.SecretKey.fromBytes(bench_private_key) catch unreachable,
    ) catch unreachable;
    const hash: [32]u8 = @splat(0x42);
    const signature = key_pair.signPrehashed(hash, null) catch unreachable;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        signature.verifyPrehashed(hash, key_pair.public_key) catch unreachable;
        accumulator +%= 1;
    }
    return accumulator;
}

fn bench_field_square(comptime F: type) fn (u32) u64 {
    return struct {
        fn run(iterations: u32) u64 {
            var a = F.from_int(0x1234_5678_9abc_def0);
            for (0..iterations) |_| a = a.square();
            return a.limbs_value[0];
        }
    }.run;
}

fn bench_field_inverse(comptime F: type, comptime vartime: bool) fn (u32) u64 {
    return struct {
        fn run(iterations: u32) u64 {
            var a = F.from_int(0x1234_5678_9abc_def0);
            const b = F.from_int(3);
            for (0..iterations) |_| {
                a = if (vartime) a.inverse() else a.inverse_constant_time();
                a = a.add(b);
            }
            return a.limbs_value[0];
        }
    }.run;
}

// Inputs from the official go-ethereum bn256 vectors (chfast1, chfast1, jeff1).
const bn254_add_input = hex_bytes(bn254.vectors.add[0].input);
const bn254_mul_input = hex_bytes(bn254.vectors.mul[0].input);
const bn254_pairing_input = hex_bytes(bn254.vectors.pairing[0].input);

fn hex_bytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime vector, checked in tests.
    return out;
}

fn bench_bn254_add(iterations: u32) u64 {
    var input = bn254_add_input;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const output = bn254.precompile_bn254_add(&input) catch unreachable; // Valid vector.
        accumulator +%= output[63];
        std.mem.doNotOptimizeAway(&input);
    }
    return accumulator;
}

fn bench_bn254_mul(iterations: u32) u64 {
    var input = bn254_mul_input;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const output = bn254.precompile_bn254_mul(&input) catch unreachable; // Valid vector.
        accumulator +%= output[63];
        input[95] = output[63]; // Vary the scalar; any 256-bit scalar is valid.
    }
    return accumulator;
}

fn bench_bn254_miller_loop_2(iterations: u32) u64 {
    const g1_points = [2]bn254.g1.G1Affine{ bn254.g1.generator, bn254.g1.generator.neg() };
    const g2_points = [2]bn254.g2.G2Affine{ bn254.g2.generator, bn254.g2.generator };
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const f = bn254.pairing.miller_loop(&g1_points, &g2_points);
        accumulator +%= f.c0.c0.c0.limbs_value[0];
        std.mem.doNotOptimizeAway(&g1_points);
    }
    return accumulator;
}

fn bench_bn254_final_exponentiation(iterations: u32) u64 {
    const g1_points = [1]bn254.g1.G1Affine{bn254.g1.generator};
    const g2_points = [1]bn254.g2.G2Affine{bn254.g2.generator};
    var f = bn254.pairing.miller_loop(&g1_points, &g2_points);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const result = bn254.pairing.final_exponentiation(f);
        accumulator +%= result.c0.c0.c0.limbs_value[0];
        f = f.mul(result);
    }
    return accumulator;
}

fn bench_bn254_pairing_2(iterations: u32) u64 {
    comptime assert(bn254_pairing_input.len == 2 * 192);
    var input = bn254_pairing_input;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const output = bn254.precompile_bn254_pairing(&input) catch unreachable; // Valid.
        accumulator +%= output[31];
        std.mem.doNotOptimizeAway(&input);
    }
    return accumulator;
}

pub const cases = [_]Case{
    .{ .name = "bn254/add", .iterations = 200_000, .run = bench_bn254_add },
    .{ .name = "bn254/mul", .iterations = 20_000, .run = bench_bn254_mul },
    .{ .name = "bn254/pairing 2 pairs", .iterations = 500, .run = bench_bn254_pairing_2 },
    .{ .name = "bn254/miller loop 2 pairs", .iterations = 1_000, .run = bench_bn254_miller_loop_2 },
    .{
        .name = "bn254/final exponentiation",
        .iterations = 1_000,
        .run = bench_bn254_final_exponentiation,
    },
    .{ .name = "field/bn254 square", .iterations = 10_000_000, .run = bench_field_square(Bn254Fp) },
    .{
        .name = "field/bls12-381 square",
        .iterations = 10_000_000,
        .run = bench_field_square(Bls12Fp),
    },
    .{
        .name = "field/bn254 inverse_constant_time",
        .iterations = 20_000,
        .run = bench_field_inverse(Bn254Fp, false),
    },
    .{
        .name = "field/bn254 inverse",
        .iterations = 20_000,
        .run = bench_field_inverse(Bn254Fp, true),
    },
    .{
        .name = "field/bls12-381 inverse_constant_time",
        .iterations = 20_000,
        .run = bench_field_inverse(Bls12Fp, false),
    },
    .{
        .name = "field/bls12-381 inverse",
        .iterations = 20_000,
        .run = bench_field_inverse(Bls12Fp, true),
    },
    .{ .name = "kzg/point evaluation", .iterations = 200, .run = bench_kzg_point_evaluation },
    .{
        .name = "kzg/blob_to_kzg_commitment",
        .iterations = 20,
        .run = kzg_bench.blob_to_kzg_commitment,
    },
    .{
        .name = "kzg/compute_blob_kzg_proof",
        .iterations = 20,
        .run = kzg_bench.compute_blob_kzg_proof,
    },
    .{
        .name = "kzg/verify_blob_kzg_proof",
        .iterations = 200,
        .run = kzg_bench.verify_blob_kzg_proof,
    },
    .{
        .name = "kzg/verify_blob_kzg_proof_batch (6)",
        .iterations = 50,
        .run = kzg_bench.verify_blob_kzg_proof_batch_6,
    },
    .{ .name = "kzg/compute_challenge", .iterations = 2_000, .run = kzg_bench.compute_challenge },
    .{
        .name = "kzg/evaluate_polynomial",
        .iterations = 1_000,
        .run = kzg_bench.evaluate_polynomial,
    },
    .{ .name = "kzg/evaluate_blob", .iterations = 1_000, .run = kzg_bench.evaluate_blob },
    .{ .name = "kzg/decompress_g1", .iterations = 5_000, .run = kzg_bench.decompress_g1 },
    .{ .name = "kzg/compute_cells", .iterations = 20, .run = kzg_bench.compute_cells },
    .{
        .name = "kzg/compute_cells_and_kzg_proofs",
        .iterations = 5,
        .run = kzg_bench.compute_cells_and_kzg_proofs,
    },
    .{
        .name = "kzg/compute_cells_and_kzg_proofs (tables)",
        .iterations = 5,
        .run = kzg_bench.compute_cells_and_kzg_proofs_tables,
    },
    .{
        .name = "kzg/verify_cell_kzg_proof_batch (1)",
        .iterations = 100,
        .run = kzg_bench.verify_cell_kzg_proof_batch_1,
    },
    .{
        .name = "kzg/verify_cell_kzg_proof_batch (128)",
        .iterations = 10,
        .run = kzg_bench.verify_cell_kzg_proof_batch_128,
    },
    .{
        .name = "kzg/recover_cells_and_kzg_proofs (64)",
        .iterations = 5,
        .run = kzg_bench.recover_cells_and_kzg_proofs,
    },
    .{ .name = "field/bn254 mul", .iterations = 10_000_000, .run = bench_field_mul(Bn254Fp) },
    .{ .name = "field/bls12-381 mul", .iterations = 10_000_000, .run = bench_field_mul(Bls12Fp) },
    .{ .name = "bls12-381/g1 add", .iterations = 1_000_000, .run = bls_bench.g1_add },
    .{ .name = "bls12-381/g1 mul", .iterations = 5_000, .run = bls_bench.g1_mul },
    .{ .name = "bls12-381/g1 mul glv", .iterations = 5_000, .run = bls_bench.g1_mul_glv },
    .{ .name = "bls12-381/g2 mul", .iterations = 2_000, .run = bls_bench.g2_mul },
    .{ .name = "bls12-381/g2 mul gls", .iterations = 2_000, .run = bls_bench.g2_mul_gls },
    .{ .name = "bls12-381/pairing-2", .iterations = 500, .run = bls_bench.pairing_2 },
    .{
        .name = "bls12-381/pairing-2 prepared",
        .iterations = 500,
        .run = bls_bench.pairing_2_prepared,
    },
    .{ .name = "bls12-381/map_fp_to_g1", .iterations = 5_000, .run = bls_bench.map_fp_to_g1 },
    .{ .name = "bls12-381/g1 msm-64", .iterations = 200, .run = bls_bench.g1_msm_64 },
    .{ .name = "bls12-381/g1 msm-4096", .iterations = 10, .run = bls_bench.g1_msm_4096 },
    .{ .name = "modexp/256b full exp", .iterations = 20_000, .run = bench_modexp(32, 32, false) },
    .{ .name = "modexp/2048b e=65537", .iterations = 2_000, .run = bench_modexp(256, 3, false) },
    .{ .name = "modexp/2048b full exp", .iterations = 20, .run = bench_modexp(256, 256, false) },
    .{ .name = "modexp/4096b e=65537", .iterations = 500, .run = bench_modexp(512, 3, false) },
    .{ .name = "modexp/4096b full exp", .iterations = 5, .run = bench_modexp(512, 512, false) },
    .{ .name = "modexp/8192b e=65537", .iterations = 100, .run = bench_modexp(1024, 3, false) },
    .{ .name = "modexp/2048b even e=65537", .iterations = 500, .run = bench_modexp(256, 3, true) },
    .{ .name = "keccak256/32B", .iterations = 2_000_000, .run = bench_keccak_32 },
    .{ .name = "keccak256/32B (std)", .iterations = 2_000_000, .run = bench_keccak_32_std },
    .{ .name = "keccak256/32B batch", .iterations = 2_000_000, .run = bench_keccak_32_batch },
    .{ .name = "keccak256/4KiB", .iterations = 50_000, .run = bench_keccak_4k },
    .{ .name = "keccak256/4KiB (std)", .iterations = 50_000, .run = bench_keccak_4k_std },
    .{ .name = "p256/verify", .iterations = 5_000, .run = bench_p256_verify },
    .{ .name = "p256/verify (std)", .iterations = 5_000, .run = bench_p256_verify_std },
    .{ .name = "sha256/32B", .iterations = 2_000_000, .run = bench_sha256_32 },
    .{ .name = "sha256/32B (std)", .iterations = 2_000_000, .run = bench_sha256_32_std },
    .{ .name = "sha256/4KiB", .iterations = 100_000, .run = bench_sha256_4k },
    .{ .name = "sha256/4KiB (std)", .iterations = 100_000, .run = bench_sha256_4k_std },
    .{ .name = "ripemd160/32B", .iterations = 1_000_000, .run = bench_ripemd160_32 },
    .{ .name = "ripemd160/4KiB", .iterations = 50_000, .run = bench_ripemd160_4k },
    .{ .name = "blake2f/12 rounds", .iterations = 1_000_000, .run = bench_blake2f_12 },
    .{ .name = "blake2b/128B (std)", .iterations = 1_000_000, .run = bench_blake2b_128_std },
    .{ .name = "secp256k1/ecrecover", .iterations = 20_000, .run = bench_ecrecover },
    .{ .name = "secp256k1/verify", .iterations = 20_000, .run = bench_verify },
    .{ .name = "secp256k1/verify (std)", .iterations = 5_000, .run = bench_verify_std },
    .{ .name = "secp256k1/ecdh", .iterations = 10_000, .run = bench_ecdh },
    .{ .name = "secp256k1/ecdh (std)", .iterations = 5_000, .run = bench_ecdh_std },
    .{ .name = "secp256k1/sign", .iterations = 20_000, .run = bench_sign },
    .{ .name = "secp256k1/sign (std)", .iterations = 5_000, .run = bench_sign_std },
    .{ .name = "secp256k1/public_key", .iterations = 20_000, .run = bench_public_key },
    .{ .name = "secp256k1/public_key (std)", .iterations = 5_000, .run = bench_public_key_std },
};

/// Runs every case whose name contains `filter` (all when null).
pub fn run(io: std.Io, filter: ?[]const u8) void {
    for (cases) |case| {
        if (filter) |pattern| {
            if (std.mem.indexOf(u8, case.name, pattern) == null) continue;
        }
        assert(case.iterations > 0);
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        const result = case.run(case.iterations);
        const end = std.Io.Clock.awake.now(io).nanoseconds;
        std.mem.doNotOptimizeAway(result);
        assert(end >= start);
        const elapsed: f64 = @floatFromInt(end - start);
        const per_op = elapsed / @as(f64, @floatFromInt(case.iterations));
        std.debug.print("{s:<36} {d:>12.1} ns/op\n", .{ case.name, per_op });
    }
}
