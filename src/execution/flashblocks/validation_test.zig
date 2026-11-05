//! Validation tests: base/base's rstest cases, shape/continuity checks, and seeded plus
//! `std.testing.fuzz` checks that every classification satisfies its defining property.

const std = @import("std");
const testing = std.testing;
const validation = @import("validation.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;
const FlashblockId = flashblocks.FlashblockId;
const SequenceResult = validation.SequenceResult;

fn id(block_number: u64, index: u64) FlashblockId {
    return .{ .block_number = block_number, .index = index };
}

fn expect_sequence(
    expected: SequenceResult,
    latest: FlashblockId,
    incoming: FlashblockId,
    prev: FlashblockId,
) !void {
    const result = validation.validate_sequence(
        latest.block_number,
        latest.index,
        incoming.block_number,
        incoming.index,
        prev,
    );
    try testing.expectEqualDeep(expected, result);
}

test "validation: sequence cases from base/base" {
    const latest = id(100, 5);
    try expect_sequence(.next_in_sequence, latest, id(100, 6), id(100, 5));
    try expect_sequence(.next_in_sequence, latest, id(100, 6), .{});
    try expect_sequence(.first_of_next_block, latest, id(101, 0), id(100, 5));
    try expect_sequence(.first_of_next_block, latest, id(101, 0), .{});
    try expect_sequence(.duplicate, latest, id(100, 5), .{});
    try expect_sequence(
        .{ .non_sequential_gap = .{ .expected = 6, .actual = 7 } },
        latest,
        id(100, 7),
        id(100, 5),
    );
    try expect_sequence(
        .{ .invalid_new_block_index = .{ .block_number = 101, .index = 3 } },
        latest,
        id(101, 3),
        id(100, 5),
    );
    try expect_sequence(
        .{ .invalid_new_block_index = .{ .block_number = 105, .index = 0 } },
        latest,
        id(105, 0),
        id(100, 5),
    );
    try expect_sequence(
        .{ .non_sequential_predecessor = .{ .expected = id(100, 5), .actual = id(100, 4) } },
        latest,
        id(101, 0),
        id(100, 4),
    );
    try expect_sequence(
        .{ .invalid_new_block_index = .{ .block_number = 99, .index = 0 } },
        latest,
        id(99, 0),
        id(100, 5),
    );
}

fn hashes(comptime bytes: []const u8) [bytes.len]B256 {
    var out: [bytes.len]B256 = undefined;
    for (bytes, &out) |byte, *hash| hash.* = .{ .bytes = @splat(byte) };
    return out;
}

fn expect_reorg(expected: ?[2]u64, tracked: []const B256, canonical: []const B256) !void {
    const result = validation.detect_reorg(tracked, canonical);
    if (expected) |counts| {
        try testing.expectEqualDeep(validation.ReorgResult{ .reorg_detected = .{
            .tracked_count = counts[0],
            .canonical_count = counts[1],
        } }, result);
    } else {
        try testing.expect(!result.is_reorg());
    }
}

test "validation: reorg detection cases from base/base" {
    try expect_reorg(null, &.{}, &.{});
    try expect_reorg(null, &hashes("\x01"), &hashes("\x01"));
    try expect_reorg(null, &hashes("\x01\x02\x03"), &hashes("\x01\x02\x03"));
    try expect_reorg(null, &hashes("\x01\x01\x02"), &hashes("\x01\x01\x02"));
    try expect_reorg(.{ 3, 3 }, &hashes("\x01\x02\x03"), &hashes("\x03\x01\x02"));
    try expect_reorg(.{ 2, 2 }, &hashes("\x01\x02"), &hashes("\x02\x01"));
    try expect_reorg(.{ 3, 2 }, &hashes("\x01\x02\x03"), &hashes("\x01\x02"));
    try expect_reorg(.{ 1, 3 }, &hashes("\x01"), &hashes("\x01\x02\x03"));
    try expect_reorg(.{ 1, 0 }, &hashes("\x01"), &.{});
    try expect_reorg(null, &.{}, &hashes("\x01"));
    try expect_reorg(.{ 3, 2 }, &hashes("\x01\x01\x02"), &hashes("\x01\x02"));
    try expect_reorg(.{ 1, 1 }, &hashes("\x42"), &hashes("\x43"));
}

test "validation: reconcile cases from base/base" {
    const r = validation.reconcile;
    try testing.expectEqual(validation.Strategy.no_pending_state, r(null, null, 100, 10, false));
    try testing.expectEqual(validation.Strategy.no_pending_state, r(100, null, 100, 10, false));
    try testing.expectEqual(validation.Strategy.catch_up, r(100, 105, 105, 10, false));
    try testing.expectEqual(validation.Strategy.catch_up, r(100, 105, 110, 10, true));
    try testing.expectEqual(validation.Strategy.handle_reorg, r(100, 110, 105, 10, true));
    try testing.expectEqualDeep(
        validation.Strategy{ .depth_limit_exceeded = .{ .depth = 15, .max_depth = 10 } },
        r(100, 120, 115, 10, false),
    );
    try testing.expectEqual(validation.Strategy.@"continue", r(100, 120, 110, 10, false));
    try testing.expectEqual(validation.Strategy.@"continue", r(100, 120, 99, 10, false));
}

fn base_for(block_number: u64) flashblocks.PayloadBase {
    return .{
        .parent_beacon_block_root = .zero,
        .parent_hash = .{ .bytes = @splat(0xaa) },
        .fee_recipient = .zero,
        .prev_randao = .zero,
        .block_number = block_number,
        .gas_limit = 30_000_000,
        .timestamp = 1,
        .extra_data = "",
        .base_fee_per_gas = 1,
    };
}

fn flashblock_at(
    block_number: u64,
    index: u64,
    base: ?flashblocks.PayloadBase,
) flashblocks.Flashblock {
    return .{
        .payload_id = @splat(1),
        .index = index,
        .base = base,
        .diff = .{
            .state_root = .zero,
            .receipts_root = .zero,
            .logs_bloom = .zero,
            .gas_used = 0,
            .block_hash = .zero,
            .transactions = &.{},
            .withdrawals = &.{},
            .withdrawals_root = .zero,
        },
        .metadata = .{ .block_number = block_number },
    };
}

test "validation: shape and continuity" {
    try validation.validate_shape(&flashblock_at(5, 0, base_for(5)));
    try validation.validate_shape(&flashblock_at(5, 3, null));
    const no_base = flashblock_at(5, 0, null);
    try testing.expectError(error.MissingBase, validation.validate_shape(&no_base));
    try testing.expectError(
        error.UnexpectedBase,
        validation.validate_shape(&flashblock_at(5, 1, base_for(5))),
    );
    try testing.expectError(
        error.BlockNumberMismatch,
        validation.validate_shape(&flashblock_at(5, 0, base_for(6))),
    );
    try testing.expectError(
        error.GenesisFlashblock,
        validation.validate_shape(&flashblock_at(0, 0, base_for(0))),
    );
    var long = base_for(5);
    const long_extra: [33]u8 = @splat(0);
    long.extra_data = &long_extra;
    const too_long = flashblock_at(5, 0, long);
    try testing.expectError(error.ExtraDataTooLong, validation.validate_shape(&too_long));

    const next = flashblock_at(5, 1, null);
    try validation.validate_continuity(.next_in_sequence, &next, @splat(1), .zero);
    try testing.expectError(
        error.PayloadIdMismatch,
        validation.validate_continuity(.next_in_sequence, &next, @splat(2), .zero),
    );
    const first = flashblock_at(6, 0, base_for(6));
    try validation.validate_continuity(.first_of_next_block, &first, @splat(9), .zero);
    try validation.validate_continuity(.first_of_next_block, &first, @splat(9), .{
        .bytes = @splat(0xaa),
    });
    try testing.expectError(
        error.ParentHashMismatch,
        validation.validate_continuity(.first_of_next_block, &first, @splat(9), .{
            .bytes = @splat(0xbb),
        }),
    );
}

/// Every classification implies its defining relation between latest and incoming.
fn check_sequence(seed: u64) !void {
    var prng = Prng.init(seed);
    const near = [_]u64{ 0, 1, 2, std.math.maxInt(u64) - 1, std.math.maxInt(u64) };
    const latest_block = if (prng.chance(1, 8)) near[prng.below(near.len)] else prng.below(8);
    const latest_index = if (prng.chance(1, 8)) near[prng.below(near.len)] else prng.below(8);
    const block = latest_block +% prng.below(3) -% 1;
    const index = if (prng.chance(1, 2)) latest_index +% prng.below(3) -% 1 else prng.below(3);
    const prev: FlashblockId = switch (prng.below(3)) {
        0 => .{},
        1 => id(latest_block, latest_index),
        else => id(prng.below(4), prng.below(4)),
    };
    const result = validation.validate_sequence(latest_block, latest_index, block, index, prev);
    const prev_ok = (prev.block_number == 0 and prev.index == 0) or
        std.meta.eql(prev, id(latest_block, latest_index));
    switch (result) {
        .duplicate => try testing.expect(block == latest_block and index == latest_index),
        .non_sequential_predecessor => try testing.expect(!prev_ok),
        .next_in_sequence => {
            try testing.expect(prev_ok and block == latest_block);
            try testing.expectEqual(latest_index +| 1, index);
        },
        .first_of_next_block => {
            try testing.expect(prev_ok and index == 0);
            try testing.expectEqual(latest_block + 1, block);
        },
        .non_sequential_gap => |gap| {
            try testing.expect(prev_ok and block == latest_block);
            try testing.expectEqual(index, gap.actual);
            try testing.expect(gap.expected != gap.actual);
        },
        .invalid_new_block_index => try testing.expect(prev_ok and block != latest_block),
    }
}

test "validation: seeded fuzz sequence classification" {
    var prng = Prng.init(0xf1a5_7a11d);
    for (0..20_000) |_| try check_sequence(prng.int(u64));
}

test "validation: fuzz sequence classification" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try check_sequence(smith.value(u64));
        }
    }.run, .{});
}
