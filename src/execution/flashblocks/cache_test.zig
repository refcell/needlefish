//! Cache tests: base/base's `cache.rs` cases, the byte and entry bounds, and a seeded plus
//! `std.testing.fuzz` comparison against a simple model.

const std = @import("std");
const testing = std.testing;
const cache_module = @import("cache.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const test_feed = @import("test_feed.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Cache = cache_module.Cache;

fn insert(cache: *Cache, block_number: u64, index: u64) bool {
    var built: test_feed.Built = .{};
    built.build(block_number, index, .zero);
    return cache.insert(built.flashblock);
}

var take_buffer: [64 * 1024]u8 = undefined;
var decode_buffer: [256 * 1024]u8 = undefined;

/// Drains `block_number`, returning the indices in order and checking each round trips.
fn drain(cache: *Cache, block_number: u64, out: []u64) !u32 {
    var count: u32 = 0;
    while (cache.take_lowest(block_number, &take_buffer)) |json| {
        var fixed: std.heap.FixedBufferAllocator = .init(&decode_buffer);
        const flashblock = try flashblocks.decode_json(fixed.allocator(), json);
        try testing.expectEqual(block_number, flashblock.metadata.block_number);
        var built: test_feed.Built = .{};
        built.build(block_number, flashblock.index, .zero);
        const expected = built.flashblock.diff.transactions;
        try testing.expectEqualDeep(expected, flashblock.diff.transactions);
        out[count] = flashblock.index;
        count += 1;
    }
    return count;
}

test "cache: insert and drain in index order" {
    var cache = try Cache.init(testing.allocator, .{}, 10);
    defer cache.deinit(testing.allocator);
    try testing.expect(insert(&cache, 11, 1));
    try testing.expect(insert(&cache, 11, 0));
    try testing.expectEqual(@as(u32, 1), cache.block_count());
    try testing.expectEqual(@as(u32, 2), cache.total_flashblocks());
    var indices: [8]u64 = undefined;
    try testing.expectEqual(@as(u32, 2), try drain(&cache, 11, &indices));
    try testing.expectEqualSlices(u64, &.{ 0, 1 }, indices[0..2]);
    try testing.expect(cache.is_empty());
    try testing.expectEqual(@as(u32, 0), try drain(&cache, 42, &indices));
}

test "cache: cacheable window and canonical eviction" {
    var cache = try Cache.init(testing.allocator, .{}, 10);
    defer cache.deinit(testing.allocator);
    // Block 16 is the last cacheable block (10 + 5 + 1).
    try testing.expect(insert(&cache, 16, 0));
    try testing.expect(!insert(&cache, 17, 0));
    try testing.expectEqual(@as(u32, 1), cache.block_count());
    cache.update_canonical(10);
    try testing.expect(insert(&cache, 11, 0));
    try testing.expect(insert(&cache, 12, 0));
    try testing.expect(insert(&cache, 13, 0));
    cache.update_canonical(12);
    try testing.expectEqual(@as(u32, 2), cache.block_count()); // 13 and 16.
    var indices: [8]u64 = undefined;
    try testing.expectEqual(@as(u32, 0), try drain(&cache, 11, &indices));
    try testing.expectEqual(@as(u32, 0), try drain(&cache, 12, &indices));
    try testing.expectEqual(@as(u32, 1), try drain(&cache, 13, &indices));
    // Inserting block 18 keeps only blocks above 13.
    try testing.expect(insert(&cache, 18, 0));
    try testing.expect(cache.has_flashblock(16, 0));
    try testing.expect(insert(&cache, 18, 1));
    try testing.expect(insert(&cache, 18, 1)); // Replaces.
    try testing.expectEqual(@as(u32, 3), cache.total_flashblocks());
}

test "cache: not cacheable without a canonical block, and bounded" {
    var none = try Cache.init(testing.allocator, .{}, null);
    defer none.deinit(testing.allocator);
    try testing.expect(!none.is_cacheable(1));
    try testing.expect(!insert(&none, 1, 0));

    var tiny = try Cache.init(testing.allocator, .{ .entries_max = 2, .bytes_max = 4096 }, 0);
    defer tiny.deinit(testing.allocator);
    try testing.expect(insert(&tiny, 1, 0));
    try testing.expect(insert(&tiny, 1, 1));
    try testing.expect(!insert(&tiny, 1, 2)); // Entries full.
    var bytes = try Cache.init(testing.allocator, .{ .bytes_max = 64 }, 0);
    defer bytes.deinit(testing.allocator);
    try testing.expect(!insert(&bytes, 1, 0)); // The JSON does not fit.
    try testing.expect(bytes.is_empty());
}

/// Random inserts, canonical updates, and drains against a presence model.
fn check_model(seed: u64) !void {
    var prng = Prng.init(seed);
    const entries_max = 16;
    var cache = try Cache.init(testing.allocator, .{ .entries_max = entries_max }, 100);
    defer cache.deinit(testing.allocator);
    // model[b][i]: block 100 + b, index i.
    var model: [20][4]bool = @splat(@splat(false));
    var canonical: u64 = 100;
    for (0..300) |_| {
        const b = prng.below(model.len);
        const i = prng.below(4);
        switch (prng.below(6)) {
            0 => {
                canonical = @max(canonical, 100 + prng.below(model.len));
                cache.update_canonical(canonical);
                for (&model, 0..) |*row, offset| {
                    if (100 + offset <= canonical) row.* = @splat(false);
                }
            },
            1 => {
                var indices: [entries_max]u64 = undefined;
                const count = try drain(&cache, 100 + b, &indices);
                var expected: u32 = 0;
                for (model[b], 0..) |present, index| {
                    if (!present) continue;
                    try testing.expectEqual(@as(u64, index), indices[expected]);
                    expected += 1;
                }
                try testing.expectEqual(expected, count);
                model[b] = @splat(false);
            },
            else => {
                const inserted = insert(&cache, 100 + b, i);
                if (100 + b > canonical + 6) {
                    try testing.expect(!inserted);
                    continue;
                }
                for (&model, 0..) |*row, offset| {
                    if (offset + 5 <= b) row.* = @splat(false);
                }
                model[b][i] = inserted;
            },
        }
        var total: u32 = 0;
        for (model, 0..) |row, offset| for (row, 0..) |present, index| {
            try testing.expectEqual(present, cache.has_flashblock(100 + offset, index));
            total += @intFromBool(present);
        };
        try testing.expectEqual(total, cache.total_flashblocks());
    }
}

test "cache: seeded fuzz against a model" {
    var prng = Prng.init(0xcac4e);
    for (0..100) |_| try check_model(prng.int(u64));
}

test "cache: fuzz against a model" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try check_model(smith.value(u64));
        }
    }.run, .{});
}
