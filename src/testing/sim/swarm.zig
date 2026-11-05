//! Swarm testing and failing-seed minimization.
//!
//! `run_range` runs many seeds in-process (each with its own random config) and
//! reports failures. `minimize` greedily shrinks a failing seed's config (disable fault
//! classes, fewer verifiers, shorter phases) while the failure persists, so the bug
//! report is as small as the seed allows. Network and fault randomness still derive
//! from the seed, so the minimized config replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../prng.zig").Prng;
const cluster_module = @import("cluster.zig");
const Config = cluster_module.Config;
const Cluster = cluster_module.Cluster;
const network_module = @import("network.zig");

pub const Regression = struct { seed: u64, config: Config };

/// Seeds that once failed, kept forever as regression tests. Append on every fix:
/// `just sim-minimize SEED` prints a ready-to-paste entry. Pinning the config keeps the
/// failing scenario even when `Config.random` changes.
pub const regressions = [_]Regression{
    // Checkpoint restored safe head without the matching L1 block hash.
    .{ .seed = 56, .config = .{
        .verifier_count = 5,
        .network = .{
            .latency_ns_min = 13000000,
            .latency_ns_max = 296000000,
            .drop_ppm = 116261,
            .duplicate_ppm = 104417,
            .capacity = 4096,
        },
        .l2_block_time_ns = 2000000000,
        .l1_block_time_ns = 12000000000,
        .fault_end_ns = 600000000000,
        .production_end_ns = 660000000000,
        .settle_end_ns = 960000000000,
        .crashes_per_minute = 2,
        .partitions_per_minute = 3,
        .disk_fault_ppm = 313460,
        .downtime_ns_max = 116000000000,
        .l1_reorgs_per_minute = 2,
        .clock_skew_ns_max = 0,
    } },
    // Rewind restored a safe head above the post-restart unsafe head.
    .{ .seed = 1275, .config = .{
        .verifier_count = 1,
        .network = .{
            .latency_ns_min = 35000000,
            .latency_ns_max = 281000000,
            .drop_ppm = 0,
            .duplicate_ppm = 191331,
            .capacity = 4096,
        },
        .l2_block_time_ns = 2000000000,
        .l1_block_time_ns = 12000000000,
        .fault_end_ns = 600000000000,
        .production_end_ns = 660000000000,
        .settle_end_ns = 960000000000,
        .crashes_per_minute = 6,
        .partitions_per_minute = 3,
        .disk_fault_ppm = 469070,
        .downtime_ns_max = 67000000000,
        .l1_reorgs_per_minute = 3,
        .clock_skew_ns_max = 21000000000,
    } },
    // Same as 1275.
    .{ .seed = 2506, .config = .{
        .verifier_count = 4,
        .network = .{
            .latency_ns_min = 43000000,
            .latency_ns_max = 246000000,
            .drop_ppm = 137563,
            .duplicate_ppm = 188440,
            .capacity = 4096,
        },
        .l2_block_time_ns = 2000000000,
        .l1_block_time_ns = 12000000000,
        .fault_end_ns = 600000000000,
        .production_end_ns = 660000000000,
        .settle_end_ns = 960000000000,
        .crashes_per_minute = 6,
        .partitions_per_minute = 4,
        .disk_fault_ppm = 56631,
        .downtime_ns_max = 8000000000,
        .l1_reorgs_per_minute = 2,
        .clock_skew_ns_max = 17000000000,
    } },
    // Clamping that safe head instead left a derivation gap.
    .{ .seed = 3426, .config = .{
        .verifier_count = 5,
        .network = .{
            .latency_ns_min = 10000000,
            .latency_ns_max = 403000000,
            .drop_ppm = 277617,
            .duplicate_ppm = 0,
            .capacity = 4096,
        },
        .l2_block_time_ns = 2000000000,
        .l1_block_time_ns = 12000000000,
        .fault_end_ns = 600000000000,
        .production_end_ns = 660000000000,
        .settle_end_ns = 960000000000,
        .crashes_per_minute = 6,
        .partitions_per_minute = 0,
        .disk_fault_ppm = 459539,
        .downtime_ns_max = 71000000000,
        .l1_reorgs_per_minute = 2,
        .clock_skew_ns_max = 20000000000,
    } },
    // Same as 3426.
    .{ .seed = 4530, .config = .{
        .verifier_count = 2,
        .network = .{
            .latency_ns_min = 25000000,
            .latency_ns_max = 255000000,
            .drop_ppm = 178525,
            .duplicate_ppm = 19170,
            .capacity = 4096,
        },
        .l2_block_time_ns = 2000000000,
        .l1_block_time_ns = 12000000000,
        .fault_end_ns = 600000000000,
        .production_end_ns = 660000000000,
        .settle_end_ns = 960000000000,
        .crashes_per_minute = 4,
        .partitions_per_minute = 0,
        .disk_fault_ppm = 455717,
        .downtime_ns_max = 28000000000,
        .l1_reorgs_per_minute = 2,
        .clock_skew_ns_max = 0,
    } },
};

/// Print `config` as a Zig `Regression` literal for `regressions`.
pub fn print_regression(seed: u64, config: Config) void {
    std.debug.print("    .{{ .seed = {d}, .config = .{{\n", .{seed});
    inline for (@typeInfo(Config).@"struct".field_names) |name| {
        const value = @field(config, name);
        if (@TypeOf(value) == network_module.Config) {
            std.debug.print("        .network = .{{\n", .{});
            inline for (@typeInfo(network_module.Config).@"struct".field_names) |inner| {
                std.debug.print("            .{s} = {d},\n", .{ inner, @field(value, inner) });
            }
            std.debug.print("        }},\n", .{});
        } else if (@TypeOf(value) == bool) {
            std.debug.print("        .{s} = {},\n", .{ name, value });
        } else {
            std.debug.print("        .{s} = {d},\n", .{ name, value });
        }
    }
    std.debug.print("    }} }},\n", .{});
}

pub const Outcome = enum { ok, safety, liveness };

pub fn run_config(allocator: std.mem.Allocator, seed: u64, config: Config) !Outcome {
    var cluster = try Cluster.init(allocator, seed, config);
    defer cluster.deinit(allocator);
    _ = cluster.run() catch |err| return switch (err) {
        error.SafetyViolation => .safety,
        error.LivenessViolation => .liveness,
    };
    return .ok;
}

pub fn config_for_seed(seed: u64) Config {
    var prng = Prng.init(seed);
    return Config.random(&prng);
}

pub const RangeResult = struct { passed: u64 = 0, failed: u64 = 0, first_failure: ?u64 = null };

/// Run seeds `[seed_first, seed_first + count)`.
pub fn run_range(allocator: std.mem.Allocator, seed_first: u64, count: u64) !RangeResult {
    assert(count > 0);
    var result: RangeResult = .{};
    var seed = seed_first;
    while (seed < seed_first + count) : (seed += 1) {
        const outcome = try run_config(allocator, seed, config_for_seed(seed));
        if (outcome == .ok) {
            result.passed += 1;
            continue;
        }
        result.failed += 1;
        if (result.first_failure == null) result.first_failure = seed;
        std.debug.print("swarm: FAIL seed={d} {s}\n", .{ seed, @tagName(outcome) });
    }
    assert(result.passed + result.failed == count);
    return result;
}

const reduction_count = 17;

/// Apply reduction `index` to `config`. Returns null when it would change nothing.
fn reduce(config: Config, index: u32) ?Config {
    assert(index < reduction_count);
    var next = config;
    switch (index) {
        0 => next.crashes_per_minute = 0,
        1 => next.partitions_per_minute = 0,
        2 => next.network.drop_ppm = 0,
        3 => next.network.duplicate_ppm = 0,
        4 => next.disk_fault_ppm = 0,
        5 => next.verifier_count = @max(1, config.verifier_count / 2),
        6 => next.network.latency_ns_max = config.network.latency_ns_min,
        7 => next.downtime_ns_max = @max(cluster_module.step_ns, config.downtime_ns_max / 2),
        8 => {
            // Halve the fault phase, keeping the production and settle windows.
            const cut = config.fault_end_ns / 2;
            next.fault_end_ns -= cut;
            next.production_end_ns -= cut;
            next.settle_end_ns -= cut;
        },
        9 => next.crashes_per_minute = config.crashes_per_minute / 2,
        10 => next.clock_skew_ns_max = 0,
        11 => next.l1_reorgs_per_minute = 0,
        12 => next.spam_per_minute = 0,
        13 => next.mempool_evictions_per_minute = 0,
        14 => next.reorg_tx_loss_ppm = 0,
        15 => next.frame_size = @import("codec.zig").frame_size_full,
        16 => next.l1_block_txs_min = @import("nodes.zig").l1_batches_max,
        else => unreachable,
    }
    if (std.meta.eql(next, config)) return null;
    next.validate();
    return next;
}

/// Greedy shrink: keep any reduction that preserves the failure kind. Bounded passes.
pub fn minimize(allocator: std.mem.Allocator, seed: u64, config: Config) !Config {
    const outcome = try run_config(allocator, seed, config);
    assert(outcome != .ok);
    var best = config;
    var pass: u32 = 0;
    while (pass < 16) : (pass += 1) {
        var changed = false;
        var index: u32 = 0;
        while (index < reduction_count) : (index += 1) {
            const candidate = reduce(best, index) orelse continue;
            if (try run_config(allocator, seed, candidate) == outcome) {
                best = candidate;
                changed = true;
            }
        }
        if (!changed) break;
    }
    assert(try run_config(allocator, seed, best) == outcome);
    return best;
}

test "swarm: pinned regressions" {
    for (regressions) |regression| {
        const outcome = try run_config(std.testing.allocator, regression.seed, regression.config);
        try std.testing.expectEqual(Outcome.ok, outcome);
    }
}

test "swarm: reductions shrink and stay valid" {
    var config = config_for_seed(9);
    var index: u32 = 0;
    while (index < reduction_count) : (index += 1) {
        if (reduce(config, index)) |next| config = next;
    }
    try std.testing.expectEqual(@as(u32, 0), config.crashes_per_minute);
    try std.testing.expectEqual(@as(u32, 0), config.network.drop_ppm);
    try std.testing.expect(reduce(config, 0) == null);
}

test "swarm: seed range" {
    const result = try run_range(std.testing.allocator, 100, 8);
    try std.testing.expectEqual(@as(u64, 0), result.failed);
}
