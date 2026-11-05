//! Derived L2 block parity (base/base shadow mode, `l2_block_parity.rs`).
//!
//! A shadow batcher posts to a shadow inbox that only a parity validator derives from. The
//! monitor compares the validator's derived blocks with the leader sequencer's unsafe
//! blocks by hash, up to `min(sequencer unsafe, validator safe)` and at most
//! `blocks_per_step_max` blocks per step. It starts after the validator's safe head at the
//! first step. A failed block fetch stops the step; that block is retried on the next one.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const blocks_per_step_max = 25;

pub const Hash = [32]u8;

pub const Stats = struct {
    checked: u32 = 0,
    matches: u32 = 0,
    mismatches: u32 = 0,
    /// Blocks at or below the comparable head that one side did not return.
    missing: u32 = 0,
    fetch_errors: u32 = 0,

    fn add(stats: *Stats, other: Stats) void {
        stats.checked += other.checked;
        stats.matches += other.matches;
        stats.mismatches += other.mismatches;
        stats.missing += other.missing;
        stats.fetch_errors += other.fetch_errors;
    }
};

pub const Mismatch = struct { number: u64, sequencer: Hash, validator: Hash };

pub const Error = rpc.Error || rpc.DecodeError;

pub const Monitor = struct {
    /// Next block to compare; null until the first step reads the validator's safe head.
    next_block: ?u64 = null,
    totals: Stats = .{},
    last_mismatch: ?Mismatch = null,
    sequencer_unsafe: u64 = 0,
    validator_safe: u64 = 0,

    /// One pass: reads both heads, then compares the next comparable blocks in order.
    pub fn step(monitor: *Monitor, sequencer: *rpc.Client, validator: *rpc.Client) Error!Stats {
        monitor.sequencer_unsafe = try head(sequencer, "\"latest\"");
        monitor.validator_safe = try head(validator, "\"safe\"");
        const next = monitor.next_block orelse {
            monitor.next_block = monitor.validator_safe + 1;
            return .{};
        };
        const comparable = @min(monitor.sequencer_unsafe, monitor.validator_safe);
        if (comparable < next) return .{};
        const last = @min(comparable, next + blocks_per_step_max - 1);
        var stats: Stats = .{};
        var number = next;
        while (number <= last) : (number += 1) {
            const sequencer_hash = block_hash(sequencer, number) catch {
                stats.fetch_errors += 1;
                break;
            };
            const validator_hash = block_hash(validator, number) catch {
                stats.fetch_errors += 1;
                break;
            };
            monitor.record(&stats, number, sequencer_hash, validator_hash);
            monitor.next_block = number + 1;
        }
        assert(stats.checked <= blocks_per_step_max);
        assert(stats.checked == stats.matches + stats.mismatches + stats.missing);
        monitor.totals.add(stats);
        return stats;
    }

    fn record(monitor: *Monitor, stats: *Stats, number: u64, left: ?Hash, right: ?Hash) void {
        stats.checked += 1;
        const sequencer_hash = left orelse return missing(stats);
        const validator_hash = right orelse return missing(stats);
        if (std.mem.eql(u8, &sequencer_hash, &validator_hash)) {
            stats.matches += 1;
            return;
        }
        stats.mismatches += 1;
        monitor.last_mismatch = .{
            .number = number,
            .sequencer = sequencer_hash,
            .validator = validator_hash,
        };
    }

    fn missing(stats: *Stats) void {
        stats.missing += 1;
    }

    /// Blocks compared so far wait behind the comparable head (base/base
    /// `verification_backlog`).
    pub fn backlog(monitor: *const Monitor) u64 {
        const next = monitor.next_block orelse return 0;
        const comparable = @min(monitor.sequencer_unsafe, monitor.validator_safe);
        return (comparable + 1) -| next;
    }
};

/// The number of the block tagged `tag` (a JSON string such as `"safe"`).
fn head(client: *rpc.Client, tag: []const u8) Error!u64 {
    var params_buffer: [32]u8 = undefined;
    const params = std.fmt.bufPrint(&params_buffer, "[{s},false]", .{tag}) catch unreachable;
    const block = try client.call("eth_getBlockByNumber", params);
    return rpc.number(try rpc.field(block, "number"));
}

fn block_hash(client: *rpc.Client, number: u64) Error!?Hash {
    var params_buffer: [40]u8 = undefined;
    const params = std.fmt.bufPrint(&params_buffer, "[\"0x{x}\",false]", .{number}) catch
        unreachable; // A u64 quantity fits.
    const block = try client.call("eth_getBlockByNumber", params);
    if (block == .null) return null;
    return try rpc.fixed(32, try rpc.field(block, "hash"));
}

const testing = std.testing;

/// Scripted L2 node: `head_latest`/`head_safe` and per-number hash seeds (0 = missing).
const FakeL2 = struct {
    latest: u64,
    safe: u64,
    seeds: [128]u8 = @splat(1),
    fail_at: ?u64 = null,

    fn transport(l2: *FakeL2) rpc.Transport {
        return .{ .context = l2, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const l2: *FakeL2 = @ptrCast(@alignCast(context));
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        const params = body[std.mem.indexOf(u8, body, "\"params\":[").? + 10 ..];
        const number: u64 = if (std.mem.startsWith(u8, params, "\"latest\""))
            l2.latest
        else if (std.mem.startsWith(u8, params, "\"safe\""))
            l2.safe
        else blk: {
            const end = std.mem.indexOfScalarPos(u8, params, 1, '"').?;
            break :blk std.fmt.parseInt(u64, params[3..end], 16) catch return error.TransportFailed;
        };
        if (l2.fail_at == number) return error.TransportFailed;
        const seed = if (number < l2.seeds.len) l2.seeds[number] else 0;
        const prefix = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":";
        const block = "{{\"number\":\"0x{x}\",\"hash\":\"0x{x:0>62}{x:0>2}\"}}}}";
        const text = if (seed == 0 or number > l2.latest)
            std.fmt.bufPrint(response, prefix ++ "null}}", .{id})
        else
            std.fmt.bufPrint(response, prefix ++ block, .{ id, number, number, seed });
        return (text catch return error.ResponseTooLarge).len;
    }
};

fn client_for(l2: *FakeL2) !rpc.Client {
    return rpc.Client.init(testing.allocator, l2.transport(), .{
        .request_bytes_max = 512,
        .response_bytes_max = 512,
        .parse_bytes_max = 16 * 1024,
    });
}

test "parity: starts after the validator safe head, compares, and reports mismatches" {
    var sequencer: FakeL2 = .{ .latest = 40, .safe = 10 };
    var validator: FakeL2 = .{ .latest = 40, .safe = 5 };
    var sequencer_client = try client_for(&sequencer);
    defer sequencer_client.deinit(testing.allocator);
    var validator_client = try client_for(&validator);
    defer validator_client.deinit(testing.allocator);
    var monitor: Monitor = .{};
    try testing.expectEqual(Stats{}, try monitor.step(&sequencer_client, &validator_client));
    try testing.expectEqual(@as(?u64, 6), monitor.next_block);
    // Validator derived up to 9: blocks 6..9 match.
    validator.safe = 9;
    const first = try monitor.step(&sequencer_client, &validator_client);
    try testing.expectEqual(Stats{ .checked = 4, .matches = 4 }, first);
    // Block 11 differs, block 12 is missing on the validator; 40 blocks cap at 25 per step.
    validator.safe = 40;
    validator.seeds[11] = 2;
    validator.seeds[12] = 0;
    const second = try monitor.step(&sequencer_client, &validator_client);
    try testing.expectEqual(@as(u32, blocks_per_step_max), second.checked);
    try testing.expectEqual(@as(u32, 1), second.mismatches);
    try testing.expectEqual(@as(u32, 1), second.missing);
    try testing.expectEqual(@as(u64, 11), monitor.last_mismatch.?.number);
    try testing.expectEqual(@as(u64, 6), monitor.backlog());
    // A fetch failure stops the step and retries the same block next time.
    sequencer.fail_at = 36;
    const third = try monitor.step(&sequencer_client, &validator_client);
    try testing.expectEqual(Stats{ .checked = 1, .matches = 1, .fetch_errors = 1 }, third);
    sequencer.fail_at = null;
    const fourth = try monitor.step(&sequencer_client, &validator_client);
    try testing.expectEqual(@as(u32, 5), fourth.checked);
    try testing.expectEqual(@as(?u64, 41), monitor.next_block);
    try testing.expectEqual(@as(u32, 35), monitor.totals.checked);
}

/// Every comparable block is checked exactly once, in order, however heads and failures
/// interleave.
fn check_random_run(prng: *Prng) !void {
    var sequencer: FakeL2 = .{ .latest = 0, .safe = 0 };
    var validator: FakeL2 = .{ .latest = 0, .safe = 0 };
    for (&validator.seeds) |*seed| seed.* = if (prng.chance(1, 10)) @intCast(prng.below(3)) else 1;
    var sequencer_client = try client_for(&sequencer);
    defer sequencer_client.deinit(testing.allocator);
    var validator_client = try client_for(&validator);
    defer validator_client.deinit(testing.allocator);
    var monitor: Monitor = .{};
    for (0..40) |_| {
        sequencer.latest = @min(120, sequencer.latest + prng.below(6));
        validator.latest = sequencer.latest;
        validator.safe = @min(sequencer.latest, validator.safe + prng.below(8));
        sequencer.fail_at = if (prng.chance(1, 6)) prng.below(121) else null;
        const before = monitor.next_block;
        const stats = monitor.step(&sequencer_client, &validator_client) catch continue;
        try testing.expect(stats.checked <= blocks_per_step_max);
        if (before) |next| try testing.expectEqual(next + stats.checked, monitor.next_block.?);
        try testing.expect(monitor.next_block.? <= @min(sequencer.latest, validator.safe) + 1 or
            stats.checked == 0);
    }
    const totals = monitor.totals;
    try testing.expectEqual(totals.checked, totals.matches + totals.mismatches + totals.missing);
}

test "parity: seeded fuzz of head and failure interleavings" {
    var prng = Prng.init(0x9a21);
    for (0..64) |_| try check_random_run(&prng);
}

test "parity: fuzz" {
    try testing.fuzz({}, fuzz_parity, .{});
}

fn fuzz_parity(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [8]u8 = @splat(0);
    _ = smith.slice(&bytes);
    var prng = Prng.init(std.mem.readInt(u64, &bytes, .little));
    try check_random_run(&prng);
}
