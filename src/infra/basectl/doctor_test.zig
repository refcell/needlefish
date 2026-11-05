//! `basectl doctor` tests: grading paths on hand-built facts, and full runs over fake
//! transports (healthy devnet, degraded, and broken).

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const doctor = @import("doctor.zig");
const sync_status = @import("sync_status.zig");
const FakeTransport = @import("fake.zig").FakeTransport;

const Writer = types.Writer;

fn find(report: *const doctor.Report, name: []const u8) doctor.Check {
    for (report.checks.slice()) |check| {
        if (std.mem.eql(u8, check.name, name)) return check;
    }
    @panic("missing check");
}

fn status_with(unsafe: u64, safe: u64, finalized: u64) sync_status.SyncStatus {
    std.debug.assert(unsafe >= safe and safe >= finalized);
    return .{
        .unsafe_l2 = .{ .number = unsafe },
        .safe_l2 = .{ .number = safe },
        .finalized_l2 = .{ .number = finalized },
    };
}

fn healthy_facts() doctor.Facts {
    return .{
        .l1_chain_id = .{ .ok = 900 },
        .l2_chain_id = .{ .ok = 901 },
        .rollup_config = .{ .ok = .{ .l1_chain_id = 900, .l2_chain_id = 901 } },
        .first = .{
            .l1_head = .{ .ok = 10 },
            .l2_head = .{ .ok = 100 },
            .sync = .{ .ok = status_with(100, 90, 50) },
        },
        .second = .{
            .l1_head = .{ .ok = 11 },
            .l2_head = .{ .ok = 102 },
            .sync = .{ .ok = status_with(102, 92, 50) },
        },
        .cl_peers = .{ .ok = .{ .connected = 8, .table = 20, .banned = 0, .known = 9 } },
        .el_peers = .{ .ok = 6 },
        .batcher = .{ .ok = .{ .stopped = false, .in_flight = 1, .da_backlog_bytes = 10 } },
        .sequencer_active = .{ .ok = true },
        .is_leader = .{ .failed = .not_configured },
    };
}

test "basectl doctor: healthy facts pass" {
    const facts = healthy_facts();
    const report = doctor.evaluate(&facts, .{}, "devnet");
    try testing.expect(!report.has_failures());
    try testing.expectEqual(@as(u32, 0), report.summary.warn);
    try testing.expectEqual(@as(u32, 14), report.summary.pass);
    try testing.expectEqual(doctor.Status.pass, find(&report, "l2_chain_id").status);
}

test "basectl doctor: degraded facts warn" {
    var facts = healthy_facts();
    facts.cl_peers.ok.connected = 2;
    facts.second.sync = .{ .ok = status_with(400, 200, 100) };
    facts.second.l1_head = .{ .ok = 10 };
    facts.el_peers = .{ .failed = .unavailable };
    facts.sequencer_active = .{ .ok = false };
    const report = doctor.evaluate(&facts, .{}, "devnet");
    try testing.expect(!report.has_failures());
    try testing.expectEqual(doctor.Status.warn, find(&report, "cl_peer_count").status);
    try testing.expectEqual(doctor.Status.warn, find(&report, "safe_head_recency").status);
    try testing.expectEqual(doctor.Status.warn, find(&report, "l1_head_advancing").status);
    try testing.expectEqual(doctor.Status.skip, find(&report, "el_peer_count").status);
    try testing.expectEqual(doctor.Status.info, find(&report, "sequencer_active").status);
}

test "basectl doctor: broken facts fail" {
    var facts = healthy_facts();
    facts.l2_chain_id = .{ .ok = 8453 };
    facts.second.l2_head = .{ .ok = 100 };
    facts.second.sync = .{ .ok = status_with(1000, 600, 100) };
    facts.batcher.ok.stopped = true;
    facts.el_peers = .{ .ok = 0 };
    facts.l1_chain_id = .{ .failed = .transport };
    facts.is_leader = .{ .ok = false };
    const report = doctor.evaluate(&facts, .{}, "devnet");
    try testing.expect(report.has_failures());
    const failing = [_][]const u8{
        "l1_rpc",        "l2_chain_id",    "l2_head_advancing", "safe_head_recency",
        "el_peer_count", "batcher_active", "sequencer_active",
    };
    for (failing) |name| try testing.expectEqual(doctor.Status.fail, find(&report, name).status);
    try testing.expectEqualStrings(
        "chain id 8453, rollup config expects 901",
        find(&report, "l2_chain_id").message.slice(),
    );
    var buffer: [4096]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try doctor.render(&report, &writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "\nFAIL batcher_active\n" ++
        "  message: batch submission is stopped\n") != null);
}

const NoSleep = struct {
    slept_ms: u64 = 0,
    fn sleep(context: *anyopaque, duration_ms: u64) void {
        const no_sleep: *NoSleep = @ptrCast(@alignCast(context));
        no_sleep.slept_ms += duration_ms;
    }
};

fn run(
    l1: *FakeTransport,
    l2: *FakeTransport,
    rollup: *FakeTransport,
    batcher: ?*FakeTransport,
) !doctor.Report {
    const allocator = testing.allocator;
    var l1_client = try l1.client(allocator);
    defer l1_client.deinit(allocator);
    var l2_client = try l2.client(allocator);
    defer l2_client.deinit(allocator);
    var rollup_client = try rollup.client(allocator);
    defer rollup_client.deinit(allocator);
    var batcher_client = if (batcher) |fake| try fake.client(allocator) else null;
    defer if (batcher_client) |*client| client.deinit(allocator);
    const context: types.Context = .{
        .l1 = .{ .client = &l1_client },
        .l2 = .{ .client = &l2_client },
        .rollup = .{ .client = &rollup_client },
        .batcher = .{ .client = if (batcher_client) |*client| client else null },
    };
    var no_sleep: NoSleep = .{};
    const sleeper: doctor.Sleeper = .{ .context = &no_sleep, .sleep_fn = NoSleep.sleep };
    const facts = doctor.gather(&context, 2_000, sleeper);
    try testing.expectEqual(@as(u64, 2_000), no_sleep.slept_ms);
    return doctor.evaluate(&facts, .{ .peer_fail_below = 0, .peer_warn_below = 1 }, "devnet");
}

test "basectl doctor: fake devnet passes, then a stalled one fails" {
    var first: [2048]u8 = undefined;
    var second: [2048]u8 = undefined;
    var l1: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_chainId", .result = "\"0x384\"" },
        .{ .method = "eth_blockNumber", .result = "\"0x10\"", .once = true },
        .{ .method = "eth_blockNumber", .result = "\"0x11\"" },
    } };
    var l2: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_chainId", .result = "\"0x385\"" },
        .{ .method = "eth_blockNumber", .result = "\"0x64\"", .once = true },
        .{ .method = "eth_blockNumber", .result = "\"0x66\"" },
        .{ .method = "net_peerCount", .result = "\"0x0\"" },
    } };
    var rollup: FakeTransport = .{ .answers = &.{
        .{
            .method = "optimism_rollupConfig",
            .result = "{\"l1_chain_id\":900,\"l2_chain_id\":901}",
        },
        .{
            .method = "optimism_syncStatus",
            .result = sync_status.sample_sync_status(&first, 100, 90, 60, 16),
            .once = true,
        },
        .{
            .method = "optimism_syncStatus",
            .result = sync_status.sample_sync_status(&second, 102, 92, 60, 17),
        },
        .{ .method = "admin_sequencerActive", .result = "true" },
    } };
    var batcher: FakeTransport = .{ .answers = &.{.{
        .method = "admin_getBatcherStatus",
        .result = "{\"stopped\":false,\"in_flight\":0,\"da_backlog_bytes\":0}",
    }} };
    const healthy = try run(&l1, &l2, &rollup, &batcher);
    try testing.expect(!healthy.has_failures());
    try testing.expectEqual(doctor.Status.skip, find(&healthy, "cl_peer_count").status);
    try testing.expectEqual(doctor.Status.pass, find(&healthy, "unsafe_head_advancing").status);
    try testing.expectEqual(doctor.Status.pass, find(&healthy, "l1_chain_id").status);

    // Reset the scripts: the `once` answers are spent, so every head now reads the same.
    var stalled_rollup = rollup;
    stalled_rollup.used = @splat(true);
    stalled_rollup.used[3] = false;
    stalled_rollup.used[2] = false;
    var down: FakeTransport = .{ .answers = &.{}, .transport_down = true };
    const broken = try run(&l1, &l2, &stalled_rollup, &down);
    try testing.expect(broken.has_failures());
    try testing.expectEqual(doctor.Status.fail, find(&broken, "l2_head_advancing").status);
    try testing.expectEqual(doctor.Status.fail, find(&broken, "unsafe_head_advancing").status);
    try testing.expectEqual(doctor.Status.fail, find(&broken, "batcher_active").status);
    try testing.expectEqual(doctor.Status.skip, find(&broken, "l2_chain_id").status);
}
