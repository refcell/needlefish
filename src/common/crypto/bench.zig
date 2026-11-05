//! Crypto micro benchmarks. Called from `src/testing/bench_main.zig` with the
//! process `Io` injected (the only clock source), so library code stays pure.
//! Each case reports ns/op for our implementation and, when std has one, the
//! std implementation as a baseline.

const std = @import("std");
const assert = std.debug.assert;
const keccak = @import("keccak.zig");
const montgomery = @import("montgomery.zig");
const modexp = @import("modexp.zig");
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

pub const cases = [_]Case{
    .{ .name = "field/bn254 mul", .iterations = 10_000_000, .run = bench_field_mul(Bn254Fp) },
    .{ .name = "field/bls12-381 mul", .iterations = 10_000_000, .run = bench_field_mul(Bls12Fp) },
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
    .{ .name = "sha256/32B", .iterations = 2_000_000, .run = bench_sha256_32 },
    .{ .name = "sha256/32B (std)", .iterations = 2_000_000, .run = bench_sha256_32_std },
    .{ .name = "sha256/4KiB", .iterations = 100_000, .run = bench_sha256_4k },
    .{ .name = "sha256/4KiB (std)", .iterations = 100_000, .run = bench_sha256_4k_std },
    .{ .name = "ripemd160/32B", .iterations = 1_000_000, .run = bench_ripemd160_32 },
    .{ .name = "ripemd160/4KiB", .iterations = 50_000, .run = bench_ripemd160_4k },
    .{ .name = "blake2f/12 rounds", .iterations = 1_000_000, .run = bench_blake2f_12 },
    .{ .name = "blake2b/128B (std)", .iterations = 1_000_000, .run = bench_blake2b_128_std },
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
