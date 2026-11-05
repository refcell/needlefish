//! Test support: a deterministic flashblock feed. The transactions of flashblock
//! `(block_number, index)` are a pure function of the position, so a checker can
//! regenerate what was published and compare a pending block against the concatenation
//! of its deltas without storing them.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const flashblocks = @import("../../common/flashblocks/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const pending = @import("pending.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;

pub const transactions_per_flashblock_max = 4;
pub const transaction_size_max = 48;

pub fn transaction_count(block_number: u64, index: u64) u32 {
    return @intCast((block_number *% 7 +% index *% 3) % (transactions_per_flashblock_max + 1));
}

pub fn transaction(block_number: u64, index: u64, k: u32, out: *[transaction_size_max]u8) []u8 {
    assert(k < transactions_per_flashblock_max);
    var prng = Prng.init(block_number *% 0x9e37_79b9 ^ (index << 8) ^ k);
    const size: usize = @intCast(prng.range(1, transaction_size_max));
    prng.fill(out[0..size]);
    return out[0..size];
}

/// The delta hash a feed publishes at a position.
pub fn block_hash(block_number: u64, index: u64) B256 {
    var hash: B256 = .{ .bytes = @splat(0x5a) };
    std.mem.writeInt(u64, hash.bytes[0..8], block_number, .big);
    std.mem.writeInt(u64, hash.bytes[8..16], index, .big);
    return hash;
}

pub fn payload_id(block_number: u64) [8]u8 {
    var id: [8]u8 = undefined;
    std.mem.writeInt(u64, &id, block_number ^ 0xfeed, .big);
    return id;
}

/// One flashblock and the storage its slices point into. Must not move after `build`.
pub const Built = struct {
    storage: [transactions_per_flashblock_max][transaction_size_max]u8 = undefined,
    slices: [transactions_per_flashblock_max][]const u8 = undefined,
    flashblock: flashblocks.Flashblock = undefined,

    /// Index 0 gets a base whose parent is `parent_hash`.
    pub fn build(built: *Built, block_number: u64, index: u64, parent_hash: B256) void {
        const count = transaction_count(block_number, index);
        for (0..count) |k| {
            built.slices[k] = transaction(block_number, index, @intCast(k), &built.storage[k]);
        }
        built.flashblock = .{
            .payload_id = payload_id(block_number),
            .index = index,
            .base = if (index == 0) .{
                .parent_beacon_block_root = .zero,
                .parent_hash = parent_hash,
                .fee_recipient = .zero,
                .prev_randao = .zero,
                .block_number = block_number,
                .gas_limit = 30_000_000,
                .timestamp = 1_700_000_000 + block_number * 2,
                .extra_data = "",
                .base_fee_per_gas = 1_000_000_000,
            } else null,
            .diff = .{
                .state_root = .zero,
                .receipts_root = .zero,
                .logs_bloom = .zero,
                .gas_used = index * 21_000,
                .block_hash = block_hash(block_number, index),
                .transactions = built.slices[0..count],
                .withdrawals = &.{},
                .withdrawals_root = .zero,
            },
            .metadata = .{ .block_number = block_number },
        };
        assert(built.flashblock.diff.transactions.len == count);
    }
};

/// The block equals the concatenation of the feed's deltas `0..block.flashblock_count`,
/// in order, with the latest delta's hash.
pub fn expect_block(block: *const pending.Block) !void {
    const block_number = block.block_number;
    try testing.expect(block.flashblock_count > 0);
    var position: u32 = 0;
    for (0..block.flashblock_count) |index| {
        const range = block.flashblock_transactions(@intCast(index));
        const count = transaction_count(block_number, index);
        try testing.expectEqual(count, range[1] - range[0]);
        for (0..count) |k| {
            var buffer: [transaction_size_max]u8 = undefined;
            const expected = transaction(block_number, index, @intCast(k), &buffer);
            try testing.expectEqualSlices(u8, expected, block.transaction(position));
            position += 1;
        }
    }
    try testing.expectEqual(block.transaction_count, position);
    try testing.expect(block.header.block_hash.eql(block_hash(block_number, block.latest_index())));
    try testing.expectEqual(payload_id(block_number), block.payload_id);
}

/// Every held block matches the feed, and block numbers are consecutive.
pub fn expect_pending(blocks: *const pending.PendingBlocks) !void {
    var position: u32 = 0;
    while (position < blocks.count) : (position += 1) {
        const block = blocks.at(position);
        try expect_block(block);
        if (position > 0) {
            try testing.expectEqual(blocks.at(position - 1).block_number + 1, block.block_number);
        }
    }
}
