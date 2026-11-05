//! Proposal targets (base/base `crates/proof/proposer/src/proof_target.rs`): the next L2
//! block to prove from a parent block, and the onchain state a proposal chains from.

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;
pub const Address = [20]u8;

/// Onchain state a proposal chains from: a game found in the `DisputeGameFactory`, or the
/// `AnchorStateRegistry` anchor root when no game follows it.
pub const RecoveredState = struct {
    /// Proxy address of the parent game, or the `AnchorStateRegistry` address as the
    /// "no parent" sentinel for the first game after an anchor without a game.
    parent: Address,
    /// Output root claimed by the game or anchor state.
    output_root: Hash,
    /// L2 block number of the claim.
    l2_block_number: u64,

    pub fn eql(a: RecoveredState, b: RecoveredState) bool {
        return a.l2_block_number == b.l2_block_number and
            std.mem.eql(u8, &a.parent, &b.parent) and
            std.mem.eql(u8, &a.output_root, &b.output_root);
    }
};

/// The next proposal target after `current_block`; null on a zero interval or overflow.
pub fn next_block(current_block: u64, block_interval: u64) ?u64 {
    if (block_interval == 0) return null;
    const target = std.math.add(u64, current_block, block_interval) catch return null;
    assert(target > current_block);
    assert(target - current_block == block_interval);
    return target;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "proposer target: next block handles interval cases" {
    // Ported from `next_block_handles_interval_cases`.
    const cases = [_]struct { u64, u64, ?u64 }{
        .{ 100, 0, null },
        .{ 100, 100, 200 },
        .{ 150, 100, 250 },
        .{ std.math.maxInt(u64), 1, null },
    };
    for (cases) |case| try testing.expectEqual(case[2], next_block(case[0], case[1]));
}

test "proposer target: recovered state equality covers every field" {
    const a: RecoveredState = .{
        .parent = @splat(1),
        .output_root = @splat(2),
        .l2_block_number = 3,
    };
    var b = a;
    try testing.expect(a.eql(b));
    b.parent[19] = 9;
    try testing.expect(!a.eql(b));
    b = a;
    b.output_root[0] = 9;
    try testing.expect(!a.eql(b));
    b = a;
    b.l2_block_number = 4;
    try testing.expect(!a.eql(b));
}

fn fuzz_next_block(_: void, smith: *std.testing.Smith) anyerror!void {
    const current = smith.value(u64);
    const interval = smith.value(u64);
    if (next_block(current, interval)) |target| {
        try testing.expect(interval > 0);
        try testing.expectEqual(current +% interval, target);
    } else {
        try testing.expect(interval == 0 or current > std.math.maxInt(u64) - interval);
    }
}

test "proposer target: fuzz next block" {
    try fuzz.run({}, fuzz_next_block, .{ .iterations = 512 });
}
