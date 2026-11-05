//! Micro benchmark harness.
//!
//! A case is any struct with `name: []const u8`, `iterations: u32` (a hint), and
//! `run: *const fn (iterations: u32) u64` (returns a value the harness keeps alive so
//! the work is not optimized away). An optional `bytes_per_op: u64` adds throughput.
//! Lanes keep their case tables next to their code (e.g. `common.crypto.bench.cases`)
//! and `bench_main.zig` lists them; this file holds the runner and cases for code that
//! has no lane-owned table yet.
//!
//! The runner calibrates iterations so each sample takes about `sample_ns_target`,
//! runs `sample_count` samples, and reports the fastest: the minimum is the most
//! stable estimate of cost on a noisy machine. The clock comes from the injected `Io`.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../common/rlp/root.zig");
const swarm = @import("sim/swarm.zig");

pub const sample_count = 5;
pub const sample_ns_target: u64 = 50 * std.time.ns_per_ms;
pub const iterations_max: u64 = 1 << 30;

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
    bytes_per_op: u64 = 0,
};

pub const Result = struct {
    ns_per_op: f64,
    iterations: u64,
    megabytes_per_s: ?f64,
};

pub fn matches(name: []const u8, filter: ?[]const u8) bool {
    const pattern = filter orelse return true;
    return std.mem.indexOf(u8, name, pattern) != null;
}

fn time_ns(io: std.Io, run: *const fn (u32) u64, iterations: u32) u64 {
    assert(iterations > 0);
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    std.mem.doNotOptimizeAway(run(iterations));
    const end = std.Io.Clock.awake.now(io).nanoseconds;
    assert(end >= start);
    return @intCast(@max(1, end - start));
}

/// Measure one case. `case` may be any struct with the fields documented above.
pub fn measure(io: std.Io, case: anytype) Result {
    assert(case.iterations > 0);
    // Calibrate: grow from the hint until one sample reaches the target (bounded).
    var iterations: u64 = @max(1, case.iterations / 100);
    var calibration: u32 = 0;
    while (calibration < 32) : (calibration += 1) {
        const elapsed_ns = time_ns(io, case.run, @intCast(iterations));
        if (elapsed_ns >= sample_ns_target / 4 or iterations >= iterations_max) {
            const scaled = iterations * sample_ns_target / elapsed_ns;
            iterations = std.math.clamp(scaled, 1, iterations_max);
            break;
        }
        iterations = @min(iterations * 4, iterations_max);
    }
    var best_ns: u64 = std.math.maxInt(u64);
    var sample: u32 = 0;
    while (sample < sample_count) : (sample += 1) {
        best_ns = @min(best_ns, time_ns(io, case.run, @intCast(iterations)));
    }
    const ns_per_op = @as(f64, @floatFromInt(best_ns)) / @as(f64, @floatFromInt(iterations));
    assert(ns_per_op > 0);
    const has_bytes = @hasField(@TypeOf(case), "bytes_per_op");
    const bytes_per_op: u64 = if (has_bytes) case.bytes_per_op else 0;
    const megabytes_per_s: ?f64 = if (bytes_per_op == 0)
        null
    else
        @as(f64, @floatFromInt(bytes_per_op)) * 1000.0 / ns_per_op;
    return .{
        .ns_per_op = ns_per_op,
        .iterations = iterations,
        .megabytes_per_s = megabytes_per_s,
    };
}

/// Run every case in `cases` (a slice or array) whose name matches `filter`.
pub fn run_cases(io: std.Io, table: anytype, filter: ?[]const u8) void {
    for (table) |case| {
        if (!matches(case.name, filter)) continue;
        const result = measure(io, case);
        if (result.megabytes_per_s) |megabytes_per_s| {
            std.debug.print("{s:<40} {d:>12.1} ns/op {d:>10.1} MB/s\n", .{
                case.name, result.ns_per_op, megabytes_per_s,
            });
        } else {
            std.debug.print("{s:<40} {d:>12.1} ns/op\n", .{ case.name, result.ns_per_op });
        }
    }
}

// Cases for code without a lane-owned table yet.

/// A list of 64 32-byte strings, the shape of a typical RLP-encoded hash list.
fn rlp_hash_list(buffer: *[64 * 33 + 3]u8) []const u8 {
    var encoder = rlp.Encoder.init(buffer);
    encoder.list_header(64 * 33);
    var index: u8 = 0;
    while (index < 64) : (index += 1) {
        var hash: [32]u8 = @splat(index);
        hash[0] = 0xa0;
        encoder.bytes(&hash);
    }
    const written = encoder.written();
    assert(written.len == buffer.len);
    return written;
}

fn bench_rlp_validate(iterations: u32) u64 {
    var buffer: [64 * 33 + 3]u8 = undefined;
    const input = rlp_hash_list(&buffer);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(input.ptr);
        accumulator +%= rlp.validate(input, rlp.depth_max) catch unreachable; // Valid input.
    }
    return accumulator;
}

fn bench_rlp_reencode(iterations: u32) u64 {
    var buffer: [64 * 33 + 3]u8 = undefined;
    const input = rlp_hash_list(&buffer);
    var output: [64 * 33 + 3]u8 = undefined;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(input.ptr);
        const written = rlp.reencode(&output, input) catch unreachable; // Valid input.
        accumulator +%= written[written.len - 1];
    }
    return accumulator;
}

fn bench_sim_seed(iterations: u32) u64 {
    var accumulator: u64 = 0;
    var seed: u64 = 0;
    while (seed < iterations) : (seed += 1) {
        const config = swarm.config_for_seed(seed);
        const outcome = swarm.run_config(std.heap.page_allocator, seed, config);
        accumulator +%= @backingInt(outcome catch unreachable); // Allocation only.
    }
    return accumulator;
}

const list_bytes = 64 * 33 + 3;

pub const cases = [_]Case{
    .{
        .name = "rlp/validate 64x32B list",
        .iterations = 1_000_000,
        .run = bench_rlp_validate,
        .bytes_per_op = list_bytes,
    },
    .{
        .name = "rlp/reencode 64x32B list",
        .iterations = 1_000_000,
        .run = bench_rlp_reencode,
        .bytes_per_op = list_bytes,
    },
    .{ .name = "sim/cluster seed (16 sim-minutes)", .iterations = 100, .run = bench_sim_seed },
};

test "bench: cases run" {
    for (cases) |case| {
        if (std.mem.startsWith(u8, case.name, "sim/")) continue; // Covered by sim tests.
        _ = case.run(2);
    }
    try std.testing.expect(matches("rlp/validate", "rlp"));
    try std.testing.expect(!matches("rlp/validate", "trie"));
    try std.testing.expect(matches("x", null));
}
