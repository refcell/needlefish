//! Crypto micro benchmarks. Called from `src/testing/bench_main.zig` with the
//! process `Io` injected (the only clock source), so library code stays pure.
//! Each case reports ns/op for our implementation and, when std has one, the
//! std implementation as a baseline.

const std = @import("std");
const assert = std.debug.assert;
const keccak = @import("keccak.zig");

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

pub const cases = [_]Case{
    .{ .name = "keccak256/32B", .iterations = 2_000_000, .run = bench_keccak_32 },
    .{ .name = "keccak256/32B (std)", .iterations = 2_000_000, .run = bench_keccak_32_std },
    .{ .name = "keccak256/32B batch", .iterations = 2_000_000, .run = bench_keccak_32_batch },
    .{ .name = "keccak256/4KiB", .iterations = 50_000, .run = bench_keccak_4k },
    .{ .name = "keccak256/4KiB (std)", .iterations = 50_000, .run = bench_keccak_4k_std },
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
