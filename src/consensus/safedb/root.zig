//! Safe head database: for each L1 block that advanced the safe head, the L2 safe head
//! derived from L1 data up to and including it. Serves `optimism_safeHeadAtL1Block`.
//! Mirrors base/base `crates/consensus/safedb`.
//!
//! Entries live in memory, sorted by L1 block number, with a fixed capacity (oldest
//! evicted). `encode_record` / `decode_record` give a fixed 80-byte record so the node can
//! persist entries through the storage engine and replay them at startup.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");

const BlockId = protocol.block.BlockId;
const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;

pub const record_size_bytes = 80;

pub const Entry = struct {
    l1_block: BlockId,
    safe_head: BlockId,
    /// False for the record a pipeline reset writes (the reset head at its L1 origin, as
    /// base/base does): it is weaker evidence that L1 up to `l1_block` derived
    /// `safe_head`. In memory only; loaded records count as derived.
    derived: bool = true,
};

pub const Error = error{ NotFound, OutOfMemory };

pub fn encode_record(entry: Entry) [record_size_bytes]u8 {
    var out: [record_size_bytes]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], entry.l1_block.number, .big);
    @memcpy(out[8..40], &entry.l1_block.hash.bytes);
    @memcpy(out[40..72], &entry.safe_head.hash.bytes);
    std.mem.writeInt(u64, out[72..80], entry.safe_head.number, .big);
    assert(std.mem.readInt(u64, out[0..8], .big) == entry.l1_block.number);
    return out;
}

pub fn decode_record(record: *const [record_size_bytes]u8) Entry {
    const entry: Entry = .{
        .l1_block = .{
            .number = std.mem.readInt(u64, record[0..8], .big),
            .hash = .{ .bytes = record[8..40].* },
        },
        .safe_head = .{
            .number = std.mem.readInt(u64, record[72..80], .big),
            .hash = .{ .bytes = record[40..72].* },
        },
    };
    assert(entry.l1_block.hash.eql(.{ .bytes = record[8..40].* }));
    return entry;
}

pub const SafeDB = struct {
    /// Sorted by `l1_block.number`, unique keys.
    entries: []Entry,
    count: u32 = 0,
    /// Bumped on every change, so a persister can tell whether to write.
    version: u64 = 0,

    pub fn init(allocator: Allocator, capacity: u32) Allocator.Error!SafeDB {
        assert(capacity > 0);
        return .{ .entries = try allocator.alloc(Entry, capacity) };
    }

    pub fn deinit(db: *SafeDB, allocator: Allocator) void {
        allocator.free(db.entries);
        db.* = undefined;
    }

    fn items(db: *const SafeDB) []Entry {
        return db.entries[0..db.count];
    }

    /// Index of the first entry with `l1_block.number >= number`.
    fn lower_bound(db: *const SafeDB, number: u64) u32 {
        var low: u32 = 0;
        var high: u32 = db.count;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (db.entries[middle].l1_block.number < number) low = middle + 1 else high = middle;
        }
        assert(low <= db.count);
        return low;
    }

    /// Inserts or replaces the entry for `entry.l1_block.number`.
    pub fn insert(db: *SafeDB, entry: Entry) void {
        db.version +%= 1;
        const index = db.lower_bound(entry.l1_block.number);
        if (index < db.count and db.entries[index].l1_block.number == entry.l1_block.number) {
            db.entries[index] = entry;
            return;
        }
        const position = index;
        if (db.count == db.entries.len) {
            // Full: evict the oldest entry, unless the new one would be the oldest. Shifting
            // the prefix left frees the slot just before `position`.
            if (position == 0) return;
            std.mem.copyForwards(Entry, db.entries[0 .. position - 1], db.entries[1..position]);
            db.entries[position - 1] = entry;
            return;
        }
        std.mem.copyBackwards(
            Entry,
            db.entries[position + 1 .. db.count + 1],
            db.entries[position..db.count],
        );
        db.entries[position] = entry;
        db.count += 1;
        assert(db.count <= db.entries.len);
    }

    /// Records that L1 data up to `l1_block` derived `safe_head`.
    pub fn safe_head_updated(db: *SafeDB, safe_head: L2BlockInfo, l1_block: BlockInfo) void {
        db.insert(.{ .l1_block = l1_block.id(), .safe_head = safe_head.block_info.id() });
    }

    /// After a pipeline reset to `reset_safe_head`: from the first entry at or after its L1
    /// origin whose safe head is at or beyond it, drop that entry and all later ones and
    /// record the reset head at its L1 origin. No-op when no entry qualifies (base/base).
    pub fn safe_head_reset(db: *SafeDB, reset_safe_head: L2BlockInfo) void {
        var index = db.lower_bound(reset_safe_head.l1_origin.number);
        while (index < db.count) : (index += 1) {
            const entry = db.entries[index];
            if (entry.safe_head.number >= reset_safe_head.block_info.number) break;
        }
        if (index == db.count) return;
        db.count = index;
        db.version +%= 1;
        db.insert(.{
            .l1_block = reset_safe_head.l1_origin,
            .safe_head = reset_safe_head.block_info.id(),
            .derived = false,
        });
    }

    /// The latest entry at or before `l1_number`.
    pub fn safe_head_at_l1(db: *const SafeDB, l1_number: u64) Error!Entry {
        if (l1_number == std.math.maxInt(u64)) {
            if (db.count == 0) return error.NotFound;
            return db.entries[db.count - 1];
        }
        const index = db.lower_bound(l1_number + 1);
        if (index == 0) return error.NotFound;
        return db.entries[index - 1];
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn hash_of(byte: u8) Hash {
    return .{ .bytes = @splat(byte) };
}

fn test_l2_block(number: u64, l1_number: u64) L2BlockInfo {
    return .{
        .block_info = .{ .number = number, .hash = hash_of(@truncate(number)) },
        .l1_origin = .{ .number = l1_number, .hash = hash_of(@truncate(l1_number + 100)) },
    };
}

fn test_l1_block(number: u64) BlockInfo {
    return .{ .number = number, .hash = hash_of(@truncate(number + 100)) };
}

test "safedb: lookup, reset, and record roundtrip" {
    var db = try SafeDB.init(testing.allocator, 16);
    defer db.deinit(testing.allocator);
    try testing.expectError(error.NotFound, db.safe_head_at_l1(5));
    db.safe_head_updated(test_l2_block(10, 1), test_l1_block(2));
    db.safe_head_updated(test_l2_block(20, 3), test_l1_block(4));
    db.safe_head_updated(test_l2_block(30, 5), test_l1_block(6));
    try testing.expectError(error.NotFound, db.safe_head_at_l1(1));
    try testing.expectEqual(@as(u64, 10), (try db.safe_head_at_l1(3)).safe_head.number);
    try testing.expectEqual(@as(u64, 30), (try db.safe_head_at_l1(100)).safe_head.number);

    // Reset to block 15 (origin 3): entries from L1 4 onward go, the reset head is added.
    db.safe_head_reset(test_l2_block(15, 3));
    try testing.expectEqual(@as(u32, 2), db.count);
    const entry = try db.safe_head_at_l1(100);
    try testing.expectEqual(@as(u64, 15), entry.safe_head.number);
    try testing.expectEqual(@as(u64, 3), entry.l1_block.number);
    // Reset beyond every entry: no-op.
    db.safe_head_reset(test_l2_block(99, 50));
    try testing.expectEqual(@as(u32, 2), db.count);

    // That entry is the reset record; the flag is not persisted.
    try testing.expect(!entry.derived);
    const record = encode_record(entry);
    const decoded = decode_record(&record);
    try testing.expect(decoded.derived);
    try testing.expectEqualDeep(entry.l1_block, decoded.l1_block);
    try testing.expectEqualDeep(entry.safe_head, decoded.safe_head);
}

test "safedb: capacity evicts oldest; seeded fuzz against a reference" {
    var prng = Prng.init(0x53414645);
    var db = try SafeDB.init(testing.allocator, 8);
    defer db.deinit(testing.allocator);
    var reference: [64]?u64 = @splat(null); // l1 number -> l2 number
    for (0..2_000) |_| {
        const l1_number = prng.below(reference.len);
        const l2_number = prng.int(u32);
        db.safe_head_updated(test_l2_block(l2_number, 0), test_l1_block(l1_number));
        reference[l1_number] = l2_number;
        const items = db.items();
        for (items[1..], items[0 .. items.len - 1]) |next, previous| {
            try testing.expect(previous.l1_block.number < next.l1_block.number);
        }
        // The newest stored keys match the reference.
        for (items) |item| {
            try testing.expectEqual(reference[item.l1_block.number].?, item.safe_head.number);
        }
    }
}
