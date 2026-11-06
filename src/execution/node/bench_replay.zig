//! Replay benchmark: the ten committed Base mainnet blocks (53715983..53715992, 253
//! transactions, Denim-era 200 ms blocks) executed by the node's executor over the replay
//! witness backend. Archive decode and replayer setup are outside the timed region; each
//! sample times the ten `replay_next` calls (execution, commit, state root, receipts) and
//! the best sample is reported as Mgas/s and ms per block. Senders are recovered in
//! parallel as in `base node`.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("../../testing/bench.zig");
const chainspec = @import("../chainspec/root.zig");
const replay = @import("../../infra/replay/root.zig");
const mainnet = @import("../../infra/replay/mainnet_test.zig");

const name = "node: replay 10 Base mainnet blocks (Mgas/s)";
const samples = 30;

pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches(name, filter)) return;
    replay_samples(io) catch |err| {
        std.debug.print("{s}: failed ({s})\n", .{ name, @errorName(err) });
    };
}

fn replay_samples(io: std.Io) !void {
    const allocator = std.heap.page_allocator;
    var archive = try replay.archive.Archive.init(allocator, mainnet.fixture_config);
    defer archive.deinit(allocator);
    try replay.archive.decode(allocator, mainnet.fixture, &archive);
    const replayer = try allocator.create(replay.replayer.Replayer);
    defer allocator.destroy(replayer);
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    var config = replay.replayer.config_for(&archive);
    // As `base node`: one sender-recovery worker per spare core, at most 7.
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    var best_ns: u64 = std.math.maxInt(u64);
    var gas: u64 = 0;
    for (0..samples) |_| {
        try replayer.init(allocator, spec, &archive, config);
        defer replayer.deinit(allocator);
        gas = 0;
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        while (!replayer.done()) {
            const outcome = try replayer.replay_next();
            if (!outcome.ok()) return error.ReplayMismatch;
            gas += outcome.gas_used;
        }
        const end = std.Io.Clock.awake.now(io).nanoseconds;
        assert(end > start);
        best_ns = @min(best_ns, @as(u64, @intCast(end - start)));
    }
    const blocks: f64 = @floatFromInt(archive.block_count);
    const ms = @as(f64, @floatFromInt(best_ns)) / 1e6;
    std.debug.print("{s:<40} {d:>8.2} ms/block {d:>10.1} Mgas/s ({d} gas)\n", .{
        name,
        ms / blocks,
        @as(f64, @floatFromInt(gas)) * 1e3 / @as(f64, @floatFromInt(best_ns)),
        gas,
    });
}

test "bench_replay: mainnet blocks replay identically with parallel sender recovery" {
    // Recovery workers only change who recovers each sender; every header field, receipt
    // and state root must still match mainnet.
    const allocator = std.testing.allocator;
    var archive = try replay.archive.Archive.init(allocator, mainnet.fixture_config);
    defer archive.deinit(allocator);
    try replay.archive.decode(allocator, mainnet.fixture, &archive);
    const replayer = try allocator.create(replay.replayer.Replayer);
    defer allocator.destroy(replayer);
    var config = replay.replayer.config_for(&archive);
    config.executor.recovery_threads = 3;
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    try replayer.init(allocator, spec, &archive, config);
    defer replayer.deinit(allocator);
    var blocks: u32 = 0;
    while (!replayer.done()) : (blocks += 1) {
        const outcome = try replayer.replay_next();
        try std.testing.expect(outcome.ok());
    }
    try std.testing.expectEqual(archive.block_count, blocks);
}
