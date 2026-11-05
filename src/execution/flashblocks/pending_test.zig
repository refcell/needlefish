//! Pending block view tests: assembly, lookup, eviction, trimming, capacity errors that
//! leave the view unchanged, and a model-checked seeded plus `std.testing.fuzz` run.

const std = @import("std");
const testing = std.testing;
const pending = @import("pending.zig");
const test_feed = @import("test_feed.zig");
const keccak256 = @import("../../common/crypto/keccak.zig").keccak256;
const Prng = @import("../../testing/prng.zig").Prng;

const PendingBlocks = pending.PendingBlocks;

const small: pending.Limits = .{
    .blocks_max = 3,
    .flashblocks_per_block_max = 6,
    .transactions_per_block_max = 12,
    .transaction_bytes_per_block_max = 256,
    .withdrawals_per_block_max = 2,
};

fn begin(blocks: *PendingBlocks, block_number: u64) !bool {
    var built: test_feed.Built = .{};
    built.build(block_number, 0, .zero);
    return blocks.begin_block(&built.flashblock);
}

fn append(blocks: *PendingBlocks, block_number: u64, index: u64) !void {
    var built: test_feed.Built = .{};
    built.build(block_number, index, .zero);
    try blocks.append(&built.flashblock);
}

test "pending: assemble, look up, evict, and trim" {
    var blocks = try PendingBlocks.init(testing.allocator, small);
    defer blocks.deinit(testing.allocator);
    try testing.expect(blocks.latest() == null);
    try testing.expect(!try begin(&blocks, 10));
    try append(&blocks, 10, 1);
    try append(&blocks, 10, 2);
    try testing.expect(!try begin(&blocks, 11));
    try testing.expect(!try begin(&blocks, 12));
    try test_feed.expect_pending(&blocks);
    const block = blocks.get(10).?;
    try testing.expectEqual(@as(u64, 2), block.latest_index());
    const first = block.transaction(0);
    try testing.expect(block.hashes()[0].eql(.{ .bytes = keccak256(first) }));
    try testing.expectEqual(@as(?u32, 0), block.find_transaction(block.hashes()[0]));
    try testing.expect(blocks.get(9) == null and blocks.get(13) == null);
    // Full: block 13 evicts block 10.
    try testing.expect(try begin(&blocks, 13));
    try testing.expectEqual(@as(?u64, 11), blocks.earliest_block_number());
    try testing.expectEqual(@as(?u64, 13), blocks.latest_block_number());
    try test_feed.expect_pending(&blocks);
    blocks.drop_through(12);
    try testing.expectEqual(@as(u32, 1), blocks.count);
    try testing.expectEqual(@as(?u64, 13), blocks.earliest_block_number());
    blocks.drop_through(100);
    try testing.expect(blocks.is_empty());
    try testing.expect(!try begin(&blocks, 50));
    try test_feed.expect_pending(&blocks);
}

test "pending: capacity errors leave the view unchanged" {
    var limits = small;
    limits.flashblocks_per_block_max = 2;
    var blocks = try PendingBlocks.init(testing.allocator, limits);
    defer blocks.deinit(testing.allocator);
    _ = try begin(&blocks, 3);
    try append(&blocks, 3, 1);
    const before = blocks.get(3).?.transaction_count;
    try testing.expectError(error.TooManyFlashblocks, append(&blocks, 3, 2));
    try testing.expectEqual(before, blocks.get(3).?.transaction_count);
    try testing.expectEqual(@as(u64, 1), blocks.get(3).?.latest_index());

    var tight = small;
    tight.transaction_bytes_per_block_max = 1;
    var other = try PendingBlocks.init(testing.allocator, tight);
    defer other.deinit(testing.allocator);
    // Block 1 index 0 carries transactions (7 % 5 = 2), more than one byte.
    try testing.expectError(error.TransactionBytesFull, begin(&other, 1));
    try testing.expect(other.is_empty());
}

/// Random begins, appends, trims, and clears against a model of (first block, counts).
fn check_model(seed: u64) !void {
    var prng = Prng.init(seed);
    var blocks = try PendingBlocks.init(testing.allocator, small);
    defer blocks.deinit(testing.allocator);
    var next_block: u64 = 1 + prng.below(1000);
    var model_counts: [3]u32 = undefined;
    var model_first: u64 = 0;
    var model_len: u32 = 0;
    for (0..200) |_| {
        switch (prng.below(10)) {
            0 => {
                blocks.clear();
                model_len = 0;
                next_block += prng.below(3);
            },
            1 => {
                const bound = next_block -| prng.below(4);
                blocks.drop_through(bound);
                while (model_len > 0 and model_first <= bound) {
                    std.mem.copyForwards(u32, model_counts[0..], model_counts[1..model_len]);
                    model_len -= 1;
                    model_first += 1;
                }
            },
            2, 3 => {
                const evicted = begin(&blocks, next_block) catch |err| {
                    try testing.expect(err == error.TooManyTransactions or
                        err == error.TransactionBytesFull);
                    continue;
                };
                try testing.expectEqual(model_len == small.blocks_max, evicted);
                if (evicted) {
                    std.mem.copyForwards(u32, model_counts[0..], model_counts[1..model_len]);
                    model_len -= 1;
                    model_first += 1;
                }
                if (model_len == 0) model_first = next_block;
                model_counts[model_len] = 1;
                model_len += 1;
                next_block += 1;
            },
            else => {
                if (model_len == 0) continue;
                const count = model_counts[model_len - 1];
                append(&blocks, next_block - 1, count) catch |err| {
                    try testing.expect(err != error.TooManyWithdrawals);
                    continue;
                };
                model_counts[model_len - 1] += 1;
            },
        }
        try testing.expectEqual(model_len, blocks.count);
        for (model_counts[0..model_len], 0..) |count, offset| {
            const block = blocks.get(model_first + offset).?;
            try testing.expectEqual(count, block.flashblock_count);
        }
        try test_feed.expect_pending(&blocks);
    }
}

test "pending: seeded fuzz against a model" {
    var prng = Prng.init(0xb10c_5);
    for (0..200) |_| try check_model(prng.int(u64));
}

test "pending: fuzz against a model" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try check_model(smith.value(u64));
        }
    }.run, .{});
}
