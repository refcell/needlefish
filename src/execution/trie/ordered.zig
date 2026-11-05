//! Ordered trie root: the root of a trie keyed by `rlp(index)`, used for the transactions,
//! receipts, and withdrawals roots of a block header.
//!
//! RLP keys do not sort like their indices: `rlp(0) = 0x80` sorts after `rlp(1..127)`, which
//! encode as single bytes. `adjust_index_for_rlp` visits indices in key order (as alloy-trie
//! does), so the streaming `HashBuilder` can run without sorting or allocation.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("node.zig");
const Nibbles = @import("nibbles.zig").Nibbles;
const HashBuilderType = @import("hash_builder.zig").HashBuilderType;

/// `rlp(u64)` is at most 9 bytes: 18 nibbles.
pub const OrderedHashBuilder = HashBuilderType(18);

/// Writes `rlp(index)` into `out`, returning the encoding.
pub fn encode_index(index: u64, out: *[9]u8) []const u8 {
    if (index == 0) {
        out[0] = 0x80;
        return out[0..1];
    }
    if (index < 0x80) {
        out[0] = @intCast(index);
        return out[0..1];
    }
    const bytes: u32 = (64 - @as(u32, @clz(index)) + 7) / 8;
    assert(bytes >= 1 and bytes <= 8);
    out[0] = 0x80 + @as(u8, @intCast(bytes));
    var position: u32 = 0;
    while (position < bytes) : (position += 1) {
        const shift: u6 = @intCast((bytes - 1 - position) * 8);
        out[1 + position] = @truncate(index >> shift);
    }
    return out[0 .. 1 + bytes];
}

/// The item index to visit at step `step` of `count`, so that keys arrive in sorted order.
pub fn adjust_index_for_rlp(step: u64, count: u64) u64 {
    assert(step < count);
    if (step > 0x7f) return step;
    if (step == 0x7f or step + 1 == count) return 0;
    return step + 1;
}

/// Root of the trie mapping `rlp(i)` to `items[i]`. Items are already-encoded values.
pub fn ordered_trie_root(items: []const []const u8) node.Hash {
    return ordered_trie_root_with_nodes(items, null);
}

/// `ordered_trie_root`, also streaming every hashed node's encoding to `sink`.
pub fn ordered_trie_root_with_nodes(
    items: []const []const u8,
    sink: ?@import("hash_builder.zig").NodeSink,
) node.Hash {
    var builder = OrderedHashBuilder.init();
    builder.node_sink = sink;
    var step: u64 = 0;
    while (step < items.len) : (step += 1) {
        const index = adjust_index_for_rlp(step, items.len);
        var key_buffer: [9]u8 = undefined;
        const key = Nibbles.from_bytes(encode_index(index, &key_buffer));
        builder.add_leaf(key.slice(), items[@intCast(index)]);
    }
    return builder.root();
}

const testing = std.testing;
const trie_module = @import("trie.zig");
const Prng = @import("../../testing/prng.zig").Prng;

test "ordered: empty list has the empty root" {
    try testing.expectEqual(node.empty_root, ordered_trie_root(&.{}));
}

test "ordered: index encoding" {
    var buffer: [9]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x80}, encode_index(0, &buffer));
    try testing.expectEqualSlices(u8, &.{0x7f}, encode_index(127, &buffer));
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x80 }, encode_index(128, &buffer));
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x01, 0x00 }, encode_index(256, &buffer));
}

test "ordered: adjusted indices visit keys in strictly increasing order" {
    const counts = [_]u64{ 1, 2, 3, 127, 128, 129, 200, 300 };
    for (counts) |count| {
        var previous: [9]u8 = undefined;
        var previous_len: usize = 0;
        var seen: [300]bool = @splat(false);
        for (0..count) |step| {
            const index = adjust_index_for_rlp(step, count);
            try testing.expect(!seen[index]);
            seen[index] = true;
            var buffer: [9]u8 = undefined;
            const key = encode_index(index, &buffer);
            if (step > 0) {
                const order = std.mem.order(u8, previous[0..previous_len], key);
                try testing.expectEqual(std.math.Order.lt, order);
            }
            @memcpy(previous[0..key.len], key);
            previous_len = key.len;
        }
    }
}

test "ordered: seeded differential against the mutable trie" {
    const Trie = trie_module.TrieType(.{ .key_bytes_max = 9, .value_size_max = 64 });
    var trie = try Trie.init(testing.allocator, 2048);
    defer trie.deinit(testing.allocator);
    var prng = Prng.init(0x0bde);
    var storage: [400][64]u8 = undefined;
    var items: [400][]const u8 = undefined;
    for (0..12) |_| {
        const count = prng.range(0, items.len);
        trie.clear();
        for (0..count) |index| {
            const len = prng.range(1, 64);
            prng.fill(storage[index][0..len]);
            items[index] = storage[index][0..len];
            var key_buffer: [9]u8 = undefined;
            try trie.put(encode_index(index, &key_buffer), items[index]);
        }
        try testing.expectEqual(trie.root_hash(), ordered_trie_root(items[0..count]));
    }
}

/// Test sink: buffers one node at a time and records its hash.
const CollectNodes = struct {
    buffer: [1024]u8 = undefined,
    len: usize = 0,
    hashes: std.AutoHashMapUnmanaged(node.Hash, void) = .empty,

    fn write(context: *anyopaque, bytes: []const u8) void {
        const collect: *CollectNodes = @ptrCast(@alignCast(context));
        @memcpy(collect.buffer[collect.len..][0..bytes.len], bytes);
        collect.len += bytes.len;
    }

    fn end(context: *anyopaque) void {
        const collect: *CollectNodes = @ptrCast(@alignCast(context));
        const hash = node.keccak256(collect.buffer[0..collect.len]);
        collect.hashes.put(testing.allocator, hash, {}) catch @panic("test allocation");
        collect.len = 0;
    }

    /// `TrieType.visit_nodes` visitor: checks each hashed node was emitted.
    const Check = struct {
        collect: *CollectNodes,
        seen: *u32,
        pub fn visit(check: Check, visit_info: trie_module.Visit) !void {
            if (visit_info.encoding.len < 32 and visit_info.path.len > 0) return;
            const hash = node.keccak256(visit_info.encoding);
            try testing.expect(check.collect.hashes.contains(hash));
            check.seen.* += 1;
        }
    };
};

test "ordered: the node sink emits exactly the hashed nodes" {
    const Trie = trie_module.TrieType(.{ .key_bytes_max = 9, .value_size_max = 64 });
    var trie = try Trie.init(testing.allocator, 2048);
    defer trie.deinit(testing.allocator);
    try trie.track_changes(testing.allocator);
    var prng = Prng.init(0x51c4);
    var storage: [300][64]u8 = undefined;
    var items: [300][]const u8 = undefined;
    for (0..10) |_| {
        const count = prng.range(1, items.len);
        trie.clear();
        for (0..count) |index| {
            const len = prng.range(1, 64);
            prng.fill(storage[index][0..len]);
            items[index] = storage[index][0..len];
            var key_buffer: [9]u8 = undefined;
            try trie.put(encode_index(index, &key_buffer), items[index]);
        }
        var collect: CollectNodes = .{};
        defer collect.hashes.deinit(testing.allocator);
        const sink: @import("hash_builder.zig").NodeSink = .{
            .context = &collect,
            .write = CollectNodes.write,
            .end = CollectNodes.end,
        };
        const root = ordered_trie_root_with_nodes(items[0..count], sink);
        try testing.expectEqual(trie.root_hash(), root);
        try testing.expect(collect.hashes.contains(root));
        var seen: u32 = 0;
        const check: CollectNodes.Check = .{ .collect = &collect, .seen = &seen };
        try trie.visit_nodes(trie.root, .all, check);
        try testing.expectEqual(@as(u32, @intCast(collect.hashes.count())), seen);
    }
}
