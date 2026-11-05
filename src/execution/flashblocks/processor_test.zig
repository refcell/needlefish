//! Processor tests: base/base `processor.rs` sequencing and reconciliation behavior, the
//! cache-and-replay path, needlefish's continuity checks, and a seeded plus
//! `std.testing.fuzz` run over a perturbed feed (drops, duplicates, swaps, canonical
//! blocks, reorgs). Invariants: every held block equals a prefix of the feed's deltas and
//! the state builder executes each held transaction exactly once, in order, between resets.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const processor_module = @import("processor.zig");
const pending = @import("pending.zig");
const state = @import("state.zig");
const test_feed = @import("test_feed.zig");
const primitives = @import("../../common/primitives/root.zig");
const keccak256 = @import("../../common/crypto/keccak.zig").keccak256;
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;

/// Checks that executions continue where the previous one stopped.
const Recorder = struct {
    block_number: ?u64 = null,
    end: u32 = 0,
    executed: u64 = 0,
    resets: u64 = 0,
    failure: ?anyerror = null,
    fail_next: bool = false,

    pub fn reset(recorder: *Recorder) void {
        recorder.block_number = null;
        recorder.end = 0;
        recorder.resets += 1;
    }

    pub fn execute(
        recorder: *Recorder,
        block: *const pending.Block,
        start: u32,
        end: u32,
    ) state.Error!void {
        if (recorder.fail_next) {
            recorder.fail_next = false;
            return error.ExecutionFailed;
        }
        recorder.check(block, start) catch |err| {
            if (recorder.failure == null) recorder.failure = err;
        };
        recorder.block_number = block.block_number;
        recorder.end = end;
        recorder.executed += end - start;
    }

    fn check(recorder: *const Recorder, block: *const pending.Block, start: u32) !void {
        const previous = recorder.block_number orelse return testing.expectEqual(0, start);
        if (previous == block.block_number) return testing.expectEqual(recorder.end, start);
        try testing.expectEqual(previous + 1, block.block_number);
        try testing.expectEqual(@as(u32, 0), start);
    }
};

const Processor = processor_module.Processor(Recorder);

const limits: pending.Limits = .{
    .blocks_max = 6,
    .flashblocks_per_block_max = 16,
    .transactions_per_block_max = 64,
    .transaction_bytes_per_block_max = 4096,
};

const Harness = struct {
    recorder: Recorder = .{},
    processor: Processor = undefined,

    fn init(harness: *Harness, canonical_tip: ?u64) !void {
        harness.* = .{};
        harness.processor = try Processor.init(testing.allocator, .{
            .max_depth = 3,
            .limits = limits,
            .cache = .{ .entries_max = 32, .bytes_max = 64 * 1024 },
            .decode_arena_bytes = 256 * 1024,
            .canonical_tip = canonical_tip,
        }, &harness.recorder);
    }

    fn deinit(harness: *Harness) void {
        harness.processor.deinit(testing.allocator);
    }

    /// Sends the feed's flashblock; index 0 builds on block `b - 1` ending at `parent_last`.
    fn send(harness: *Harness, b: u64, i: u64, parent_last: u64) void {
        var built: test_feed.Built = .{};
        built.build(b, i, test_feed.block_hash(b - 1, parent_last));
        harness.processor.on_flashblock(built.flashblock);
    }

    fn latest(harness: *const Harness) ?[2]u64 {
        const block = harness.processor.pending.latest() orelse return null;
        return .{ block.block_number, block.latest_index() };
    }

    fn check(harness: *const Harness) !void {
        try test_feed.expect_pending(&harness.processor.pending);
        if (harness.recorder.failure) |err| return err;
    }
};

test "processor: sequencing like base/base" {
    var h: Harness = undefined;
    try h.init(null);
    defer h.deinit();
    h.send(10, 1, 0); // No pending blocks and not index 0.
    try testing.expectEqual(@as(?[2]u64, null), h.latest());
    try testing.expectEqual(@as(u64, 1), h.processor.stats.missing_first);
    h.send(10, 0, 4);
    h.send(10, 1, 0);
    h.send(10, 1, 0); // Duplicate.
    try testing.expectEqual(@as(u64, 1), h.processor.stats.duplicates);
    h.send(10, 2, 0);
    h.send(11, 0, 2);
    h.send(11, 1, 0);
    try testing.expectEqual(@as(?[2]u64, .{ 11, 1 }), h.latest());
    try testing.expectEqual(@as(u32, 2), h.processor.pending.count);
    try h.check();
    h.send(11, 3, 0); // Gap: cleared.
    try testing.expectEqual(@as(?[2]u64, null), h.latest());
    h.send(12, 0, 1); // Fresh start (no canonical view: parent counts as known).
    h.send(14, 0, 0); // Invalid new block index: cleared.
    try testing.expectEqual(@as(?[2]u64, null), h.latest());
    try testing.expectEqual(@as(u64, 2), h.processor.stats.unexpected_order);
    try h.check();
    try testing.expect(h.recorder.resets >= 3);
}

test "processor: predecessor link, payload id, and parent hash continuity" {
    var h: Harness = undefined;
    try h.init(null);
    defer h.deinit();
    h.send(5, 0, 0);
    var built: test_feed.Built = .{};
    built.build(5, 1, .zero);
    built.flashblock.metadata.prev_flashblock_id = .{ .block_number = 4, .index = 9 };
    h.processor.on_flashblock(built.flashblock);
    try testing.expectEqual(@as(?[2]u64, null), h.latest());
    h.send(5, 0, 0);
    built.build(5, 1, .zero);
    built.flashblock.metadata.prev_flashblock_id = .{ .block_number = 5, .index = 0 };
    h.processor.on_flashblock(built.flashblock);
    try testing.expectEqual(@as(?[2]u64, .{ 5, 1 }), h.latest());
    built.build(5, 2, .zero);
    built.flashblock.payload_id = @splat(0xee);
    h.processor.on_flashblock(built.flashblock);
    try testing.expectEqual(@as(?[2]u64, null), h.latest());
    // A next block on another parent restarts the pending blocks from it.
    h.send(5, 0, 0);
    h.send(6, 0, 7);
    try testing.expectEqual(@as(?[2]u64, .{ 6, 0 }), h.latest());
    try testing.expectEqual(@as(u32, 1), h.processor.pending.count);
    try testing.expectEqual(@as(u64, 1), h.processor.stats.clear_reorg);
    // Shape errors are rejected without touching the pending blocks.
    built.build(6, 1, .zero);
    built.flashblock.base = built.flashblock.base orelse .{
        .parent_beacon_block_root = .zero,
        .parent_hash = .zero,
        .fee_recipient = .zero,
        .prev_randao = .zero,
        .block_number = 6,
        .gas_limit = 1,
        .timestamp = 1,
        .extra_data = "",
        .base_fee_per_gas = 1,
    };
    h.processor.on_flashblock(built.flashblock);
    try testing.expectEqual(@as(?[2]u64, .{ 6, 0 }), h.latest());
    try h.check();
}

fn hashes_of(b: u64, flashblock_count: u64, out: []B256) []B256 {
    var count: usize = 0;
    for (0..flashblock_count) |i| {
        for (0..test_feed.transaction_count(b, i)) |k| {
            var buffer: [test_feed.transaction_size_max]u8 = undefined;
            out[count] = .{ .bytes = keccak256(test_feed.transaction(b, i, @intCast(k), &buffer)) };
            count += 1;
        }
    }
    return out[0..count];
}

test "processor: canonical catch up, continue, reorg, and depth limit" {
    var h: Harness = undefined;
    try h.init(null);
    defer h.deinit();
    var hashes: [64]B256 = undefined;
    for (20..24) |b| {
        h.send(b, 0, 1);
        h.send(b, 1, 0);
    }
    h.processor.on_canonical(20, hashes_of(20, 2, &hashes)); // Continue.
    try testing.expectEqual(@as(u32, 4), h.processor.pending.count);
    const tracked = hashes_of(21, 2, &hashes);
    try testing.expect(tracked.len > 1);
    h.processor.on_canonical(21, tracked[1..]); // Reorg: keeps 22, 23.
    try testing.expectEqual(@as(?u64, 22), h.processor.pending.earliest_block_number());
    try testing.expectEqual(@as(u64, 1), h.processor.stats.clear_reorg);
    try h.check();
    h.processor.on_canonical(23, hashes_of(23, 2, &hashes)); // Catch up.
    try testing.expect(h.processor.pending.is_empty());
    try testing.expectEqual(@as(u64, 1), h.processor.stats.clear_catchup);
    h.send(23, 0, 0); // Superseded.
    try testing.expectEqual(@as(u64, 1), h.processor.stats.superseded);
    for (24..30) |b| h.send(b, 0, if (b == 24) 1 else 0);
    // Canonical 28 with earliest 24: depth 4 > 3, keeps only 29.
    h.processor.on_canonical(28, hashes_of(28, 1, &hashes));
    try testing.expectEqual(@as(?u64, 29), h.processor.pending.earliest_block_number());
    try testing.expectEqual(@as(u32, 1), h.processor.pending.count);
    // A canonical tip far past the pending blocks drops them as stale.
    h.processor.on_canonical(40, &.{});
    try testing.expect(h.processor.pending.is_empty());
    try h.check();
}

test "processor: early flashblocks wait in the cache and replay" {
    var h: Harness = undefined;
    try h.init(10);
    defer h.deinit();
    h.send(12, 0, 3); // Parent 11 is not canonical yet.
    h.send(12, 1, 0); // Its predecessor is cached: cached too.
    h.send(12, 3, 0); // Not cached: index 2 is missing.
    try testing.expectEqual(@as(u64, 2), h.processor.stats.cached);
    try testing.expect(h.processor.pending.is_empty());
    h.processor.on_canonical(11, &.{});
    try testing.expectEqual(@as(u64, 2), h.processor.stats.replayed);
    try testing.expectEqual(@as(?[2]u64, .{ 12, 1 }), h.latest());
    h.send(12, 2, 0);
    try testing.expectEqual(@as(?[2]u64, .{ 12, 2 }), h.latest());
    // An execution failure clears the pending blocks.
    h.recorder.fail_next = true;
    h.send(12, 3, 0);
    try testing.expect(h.processor.pending.is_empty());
    try h.check();
}

/// A perturbed feed with canonical blocks; see the file comment for the invariants.
fn check_feed(seed: u64) !void {
    var prng = Prng.init(seed);
    // A quarter of the runs are clean: no perturbation and no canonical view.
    const perturb = !prng.chance(1, 4);
    var h: Harness = undefined;
    try h.init(if (perturb and prng.chance(1, 2)) 0 else null);
    defer h.deinit();
    var lengths: [80]u64 = undefined; // Flashblocks per feed block 1..80.
    for (&lengths) |*length| length.* = prng.range(1, 6);
    var b: u64 = 1;
    var i: u64 = 0;
    var previous: ?[2]u64 = null;
    var hashes: [64]B256 = undefined;
    while (b < lengths.len) {
        const parent_last = if (b > 1) lengths[b - 2] - 1 else 0;
        switch (if (perturb) prng.below(40) else 39) {
            0 => {}, // Drop this flashblock.
            1 => if (previous) |p| {
                h.send(p[0], p[1], if (p[0] > 1) lengths[p[0] - 2] - 1 else 0);
            },
            2 => {
                const canonical = prng.range(@max(b, 3) - 2, b);
                const full = lengths[canonical - 1];
                const count = if (prng.chance(1, 4)) prng.below(full + 1) else full;
                h.processor.on_canonical(canonical, hashes_of(canonical, count, &hashes));
            },
            else => h.send(b, i, parent_last),
        }
        previous = .{ b, i };
        i += 1;
        if (i == lengths[b - 1]) {
            b += 1;
            i = 0;
        }
        try h.check();
    }
    if (!perturb) {
        try testing.expectEqual(@as(u64, 0), h.processor.stats.unexpected_order);
        try testing.expectEqual(@as(?[2]u64, .{ b - 1, lengths[b - 2] - 1 }), h.latest());
        try testing.expectEqual(@as(u32, limits.blocks_max), h.processor.pending.count);
    }
}

test "processor: seeded fuzz over a perturbed feed" {
    var prng = Prng.init(0x9_0ce5);
    for (0..150) |_| try check_feed(prng.int(u64));
}

test "processor: fuzz over a perturbed feed" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try check_feed(smith.value(u64));
        }
    }.run, .{});
}

comptime {
    assert(limits.blocks_max < 80);
}
