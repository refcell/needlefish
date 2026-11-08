//! The engine block ring of `base el-run`: the last executed blocks (header RLP and EIP-2718
//! transactions) kept in memory, so the Engine API (`el_engine.zig`) can serve full blocks
//! at the safe head, which trails the tip by more blocks than the database keeps
//! (`to_disk.shape_node.chain.blocks_max`, without bodies).
//!
//! Bounded by a block count and a byte budget, both fixed at startup; pushing past either
//! evicts the oldest blocks. Blocks are consecutive (each push is the next number; anything
//! else restarts the ring), so a lookup by number is an index and a lookup by hash scans back
//! from the newest block.
//!
//! Each block is one record in a circular byte arena: header length and transaction count
//! (u32 little endian), the transaction lengths (u32 each), the header, the transactions.
//! Records never wrap: a record that does not fit before the arena's end starts at offset
//! zero. Record positions are virtual offsets that only grow (`start`, physical offset
//! `start % arena.len`), so "the live records span at most `arena.len` virtual bytes" is the
//! whole no-overlap invariant.

const std = @import("std");
const base = @import("base");
const assert = std.debug.assert;
const lazy_alloc = base.utilities.lazy_alloc;

pub const Options = struct {
    blocks_max: u32 = 16_384,
    bytes_max: u64 = 512 << 20,
    /// Largest transaction count of one block (`el_source.transactions_max`).
    transactions_max: u32 = 1 << 14,
};

pub const Block = struct {
    number: u64,
    hash: [32]u8,
    header_rlp: []const u8,
    /// Borrowed from the ring (or the caller's scratch) until the next push.
    transactions: []const []const u8,
};

const Entry = struct {
    number: u64,
    hash: [32]u8,
    /// Virtual offset of the record; the physical offset is `start % arena.len`.
    start: u64,
    size: u64,
};

pub const Ring = struct {
    entries: []Entry,
    arena: []u8,
    transactions_max: u32,
    /// Index of the oldest entry.
    first: u32 = 0,
    count: u32 = 0,
    /// Virtual offset where the next record may start.
    write_start: u64 = 0,
    /// Bytes of the retained records (padding excluded).
    bytes_used: u64 = 0,
    pushed: u64 = 0,
    evicted: u64 = 0,
    /// Blocks larger than the whole arena (the ring restarts after them).
    too_large: u64 = 0,
    /// Pushes that did not extend the newest block (the ring restarted).
    restarts: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Ring {
        assert(options.blocks_max > 0);
        assert(options.bytes_max >= 1024);
        assert(options.transactions_max > 0);
        const entries = try allocator.alloc(Entry, options.blocks_max);
        errdefer allocator.free(entries);
        const arena = try lazy_alloc.alloc(allocator, u8, @intCast(options.bytes_max));
        const transactions = options.transactions_max;
        return .{ .entries = entries, .arena = arena, .transactions_max = transactions };
    }

    pub fn deinit(ring: *Ring, allocator: std.mem.Allocator) void {
        allocator.free(ring.entries);
        lazy_alloc.free(allocator, ring.arena);
        ring.* = undefined;
    }

    /// Bytes one block takes in the arena.
    pub fn record_size(header_size: usize, transactions: []const []const u8) u64 {
        var size: u64 = 8 + 4 * @as(u64, transactions.len) + header_size;
        for (transactions) |transaction| size += transaction.len;
        return size;
    }

    pub fn clear(ring: *Ring) void {
        ring.first = 0;
        ring.count = 0;
        ring.bytes_used = 0;
        assert(ring.oldest_number() == null);
    }

    pub fn oldest_number(ring: *const Ring) ?u64 {
        if (ring.count == 0) return null;
        return ring.entries[ring.first].number;
    }

    pub fn newest_number(ring: *const Ring) ?u64 {
        if (ring.count == 0) return null;
        return ring.entry(ring.count - 1).number;
    }

    /// The `index`-th retained entry, oldest first.
    fn entry(ring: *const Ring, index: u32) *const Entry {
        assert(index < ring.count);
        const slot = (@as(u64, ring.first) + index) % ring.entries.len;
        return &ring.entries[@intCast(slot)];
    }

    fn index_of(ring: *const Ring, number: u64) ?u32 {
        const oldest = ring.oldest_number() orelse return null;
        if (number < oldest or number - oldest >= ring.count) return null;
        const index: u32 = @intCast(number - oldest);
        assert(ring.entry(index).number == number);
        return index;
    }

    pub fn hash_at(ring: *const Ring, number: u64) ?[32]u8 {
        const index = ring.index_of(number) orelse return null;
        return ring.entry(index).hash;
    }

    /// The number of the retained block `hash`; scans back from the newest block
    /// (`blocks_max` comparisons at most).
    pub fn number_of(ring: *const Ring, hash: [32]u8) ?u64 {
        var index = ring.count;
        while (index > 0) {
            index -= 1;
            const found = ring.entry(index);
            if (std.mem.eql(u8, &found.hash, &hash)) return found.number;
        }
        return null;
    }

    /// Stores `block` as the newest block, evicting the oldest ones past either bound.
    pub fn push(ring: *Ring, block: *const Block) error{BlockTooLarge}!void {
        assert(block.transactions.len <= ring.transactions_max);
        const size = record_size(block.header_rlp.len, block.transactions);
        if (size > ring.arena.len) {
            ring.too_large += 1;
            ring.clear();
            return error.BlockTooLarge;
        }
        if (ring.newest_number()) |newest| {
            if (block.number != newest + 1) {
                ring.restarts += 1;
                ring.clear();
            }
        }
        const arena_size: u64 = ring.arena.len;
        var start = ring.write_start;
        if (start % arena_size + size > arena_size) start += arena_size - start % arena_size;
        assert(start % arena_size + size <= arena_size);
        const end = start + size;
        while (ring.count > 0) {
            const oldest = ring.entries[ring.first];
            if (ring.count < ring.entries.len and end - oldest.start <= arena_size) break;
            ring.evict_oldest();
        }
        ring.write_record(start % arena_size, block);
        const slot = (@as(u64, ring.first) + ring.count) % ring.entries.len;
        ring.entries[@intCast(slot)] = .{
            .number = block.number,
            .hash = block.hash,
            .start = start,
            .size = size,
        };
        ring.count += 1;
        ring.write_start = end;
        ring.bytes_used += size;
        ring.pushed += 1;
        assert(ring.count <= ring.entries.len);
        assert(end - ring.entries[ring.first].start <= arena_size);
        assert(ring.newest_number().? == block.number);
    }

    fn evict_oldest(ring: *Ring) void {
        assert(ring.count > 0);
        const oldest = ring.entries[ring.first];
        assert(ring.bytes_used >= oldest.size);
        ring.bytes_used -= oldest.size;
        ring.first = @intCast((@as(u64, ring.first) + 1) % ring.entries.len);
        ring.count -= 1;
        ring.evicted += 1;
    }

    fn write_record(ring: *Ring, offset: u64, block: *const Block) void {
        const count: u32 = @intCast(block.transactions.len);
        var cursor: usize = @intCast(offset);
        const record = ring.arena;
        std.mem.writeInt(u32, record[cursor..][0..4], @intCast(block.header_rlp.len), .little);
        std.mem.writeInt(u32, record[cursor + 4 ..][0..4], count, .little);
        cursor += 8;
        for (block.transactions) |transaction| {
            std.mem.writeInt(u32, record[cursor..][0..4], @intCast(transaction.len), .little);
            cursor += 4;
        }
        @memcpy(record[cursor..][0..block.header_rlp.len], block.header_rlp);
        cursor += block.header_rlp.len;
        for (block.transactions) |transaction| {
            @memcpy(record[cursor..][0..transaction.len], transaction);
            cursor += transaction.len;
        }
        assert(cursor - offset == record_size(block.header_rlp.len, block.transactions));
    }

    /// Block `number` when retained; its transaction slices are written into `scratch`
    /// (at least `transactions_max` long) and borrow the arena until the next push.
    pub fn get(ring: *const Ring, number: u64, scratch: [][]const u8) ?Block {
        assert(scratch.len >= ring.transactions_max);
        const index = ring.index_of(number) orelse return null;
        const found = ring.entry(index);
        const offset: usize = @intCast(found.start % ring.arena.len);
        const record = ring.arena[offset..][0..@intCast(found.size)];
        const header_size = std.mem.readInt(u32, record[0..4], .little);
        const count = std.mem.readInt(u32, record[4..8], .little);
        assert(count <= ring.transactions_max);
        var cursor: usize = 8 + 4 * @as(usize, count);
        const header_rlp = record[cursor..][0..header_size];
        cursor += header_size;
        for (scratch[0..count], 0..) |*transaction, index_transaction| {
            const length_offset = 8 + 4 * index_transaction;
            const length = std.mem.readInt(u32, record[length_offset..][0..4], .little);
            transaction.* = record[cursor..][0..length];
            cursor += length;
        }
        assert(cursor == record.len);
        return .{
            .number = number,
            .hash = found.hash,
            .header_rlp = header_rlp,
            .transactions = scratch[0..count],
        };
    }
};

const testing = std.testing;
const Prng = base.testing.Prng;

/// Deterministic block contents for `number`: a header and up to `transactions_max` bytes
/// strings whose sizes and bytes depend only on the number and the size class.
const Model = struct {
    header: [96]u8 = undefined,
    storage: [8][300]u8 = undefined,
    transactions: [8][]const u8 = undefined,

    fn block(model: *Model, number: u64, size_class: u64) Block {
        var prng = Prng.init(number *% 0x9e3779b97f4a7c15 +% size_class);
        const header_size = 8 + prng.below(model.header.len - 8);
        prng.fill(model.header[0..header_size]);
        std.mem.writeInt(u64, model.header[0..8], number, .little);
        const count = prng.below(model.transactions.len + 1);
        for (0..count) |index| {
            const size = prng.below(@min(size_class, model.storage[index].len) + 1);
            prng.fill(model.storage[index][0..size]);
            model.transactions[index] = model.storage[index][0..size];
        }
        var hash: [32]u8 = @splat(0);
        std.mem.writeInt(u64, hash[0..8], number, .little);
        hash[31] = 0xab;
        return .{
            .number = number,
            .hash = hash,
            .header_rlp = model.header[0..header_size],
            .transactions = model.transactions[0..count],
        };
    }
};

fn expect_block(ring: *const Ring, number: u64, size_class: u64) !void {
    var model: Model = .{};
    const expected = model.block(number, size_class);
    var scratch: [8][]const u8 = undefined;
    const got = ring.get(number, &scratch) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &expected.hash, &got.hash);
    try testing.expectEqualSlices(u8, expected.header_rlp, got.header_rlp);
    try testing.expectEqual(expected.transactions.len, got.transactions.len);
    for (expected.transactions, got.transactions) |a, b| try testing.expectEqualSlices(u8, a, b);
    try testing.expectEqual(@as(?u64, number), ring.number_of(expected.hash));
}

test "el ring: eviction by count keeps the newest blocks" {
    var ring = try Ring.init(testing.allocator, .{
        .blocks_max = 4,
        .bytes_max = 1 << 20,
        .transactions_max = 8,
    });
    defer ring.deinit(testing.allocator);
    var model: Model = .{};
    for (100..110) |number| try ring.push(&model.block(number, 64));
    try testing.expectEqual(@as(u32, 4), ring.count);
    try testing.expectEqual(@as(?u64, 106), ring.oldest_number());
    try testing.expectEqual(@as(?u64, 109), ring.newest_number());
    try testing.expectEqual(@as(u64, 6), ring.evicted);
    var scratch: [8][]const u8 = undefined;
    try testing.expect(ring.get(105, &scratch) == null);
    try testing.expect(ring.get(110, &scratch) == null);
    for (106..110) |number| try expect_block(&ring, number, 64);
    // A gap restarts the ring.
    try ring.push(&model.block(200, 64));
    try testing.expectEqual(@as(u32, 1), ring.count);
    try testing.expectEqual(@as(u64, 1), ring.restarts);
    try expect_block(&ring, 200, 64);
}

test "el ring: eviction by bytes, wrap, and too-large blocks" {
    var ring = try Ring.init(testing.allocator, .{
        .blocks_max = 1000,
        .bytes_max = 4096,
        .transactions_max = 8,
    });
    defer ring.deinit(testing.allocator);
    var model: Model = .{};
    for (0..200) |number| {
        try ring.push(&model.block(number, 300));
        try testing.expect(ring.bytes_used <= 4096);
        const oldest = ring.oldest_number().?;
        for (oldest..number + 1) |kept| try expect_block(&ring, kept, 300);
    }
    try testing.expect(ring.count < 200);
    try testing.expect(ring.evicted > 0);
    try testing.expectEqual(@as(u64, 200), ring.count + ring.evicted);
    const huge = [_][]const u8{&(@as([5000]u8, @splat(1)))};
    var hash: [32]u8 = @splat(7);
    hash[0] = 1;
    const large: Block = .{ .number = 200, .hash = hash, .header_rlp = "h", .transactions = &huge };
    try testing.expectError(error.BlockTooLarge, ring.push(&large));
    try testing.expectEqual(@as(u32, 0), ring.count);
    try ring.push(&model.block(201, 300));
    try expect_block(&ring, 201, 300);
}

test "el ring: seeded fuzz against both bounds" {
    var prng = Prng.init(0xe1e1);
    for (0..24) |_| {
        const blocks_max: u32 = @intCast(prng.range(1, 64));
        const bytes_max = prng.range(4096, 16 * 1024);
        const size_class = prng.range(1, 300);
        var ring = try Ring.init(testing.allocator, .{
            .blocks_max = blocks_max,
            .bytes_max = bytes_max,
            .transactions_max = 8,
        });
        defer ring.deinit(testing.allocator);
        var model: Model = .{};
        const first = prng.below(1000);
        const total = prng.range(1, 300);
        for (first..first + total) |number| {
            try ring.push(&model.block(number, size_class));
            try testing.expect(ring.count <= blocks_max);
            try testing.expect(ring.bytes_used <= bytes_max);
            try testing.expectEqual(@as(?u64, number), ring.newest_number());
        }
        const oldest = ring.oldest_number().?;
        try testing.expectEqual(first + total - ring.count, oldest);
        for (oldest..first + total) |number| try expect_block(&ring, number, size_class);
        try testing.expectEqual(total, ring.count + ring.evicted);
        // Below the count bound, the last eviction was for bytes: the retained span plus the
        // evicted record and its padding (each under 2600 bytes here) exceeded the arena.
        if (ring.count < blocks_max and ring.evicted > 0) {
            const span = ring.write_start - ring.entries[ring.first].start;
            try testing.expect(span + 2 * 2600 > bytes_max);
        }
    }
}
