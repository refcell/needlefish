//! Bounded in-memory block store: the most recent blocks (canonical and side branches)
//! as opaque records in a byte ring, indexed by hash, plus a canonical number index.
//! Records are evicted oldest-first when either the entry ring or the byte ring is full,
//! so memory is fixed at init. Persistent storage replaces this with the db lane.

const std = @import("std");
const assert = std.debug.assert;

const Hash = [32]u8;

pub const Config = struct {
    blocks_max: u32 = 1 << 14,
    bytes_max: u64 = 256 << 20,
};

pub const Ref = struct {
    hash: Hash,
    parent_hash: Hash,
    number: u64,
    timestamp: u64,
};

const Entry = struct {
    ref: Ref,
    /// Monotonic byte-ring position of the record start.
    offset: u64,
    len: u32,
};

pub const Error = error{RecordTooLarge};

pub const BlockStore = struct {
    entries: []Entry,
    /// Entries `[tail, head)` (monotonic sequence numbers) are live.
    head: u64 = 0,
    tail: u64 = 0,
    by_hash: std.AutoHashMapUnmanaged(Hash, u64),
    bytes: []u8,
    bytes_head: u64 = 0,
    canonical: []Hash,
    canonical_numbers: []?u64,

    pub fn init(allocator: std.mem.Allocator, config: Config) !BlockStore {
        assert(config.blocks_max > 0);
        assert(config.bytes_max > 0);
        const entries = try allocator.alloc(Entry, config.blocks_max);
        errdefer allocator.free(entries);
        var by_hash: std.AutoHashMapUnmanaged(Hash, u64) = .empty;
        try by_hash.ensureTotalCapacity(allocator, config.blocks_max);
        errdefer by_hash.deinit(allocator);
        const bytes = try allocator.alloc(u8, @intCast(config.bytes_max));
        errdefer allocator.free(bytes);
        const canonical = try allocator.alloc(Hash, config.blocks_max);
        errdefer allocator.free(canonical);
        const canonical_numbers = try allocator.alloc(?u64, config.blocks_max);
        @memset(canonical_numbers, null);
        return .{
            .entries = entries,
            .by_hash = by_hash,
            .bytes = bytes,
            .canonical = canonical,
            .canonical_numbers = canonical_numbers,
        };
    }

    pub fn deinit(store: *BlockStore, allocator: std.mem.Allocator) void {
        allocator.free(store.canonical_numbers);
        allocator.free(store.canonical);
        allocator.free(store.bytes);
        store.by_hash.deinit(allocator);
        allocator.free(store.entries);
        store.* = undefined;
    }

    pub fn count(store: *const BlockStore) u32 {
        return @intCast(store.head - store.tail);
    }

    /// Stores a copy of `bytes` under `block_ref.hash`; a known hash is left unchanged.
    pub fn put(store: *BlockStore, block_ref: Ref, bytes: []const u8) Error!void {
        if (bytes.len > store.bytes.len or bytes.len > std.math.maxInt(u32)) {
            return error.RecordTooLarge;
        }
        if (store.by_hash.contains(block_ref.hash)) return;
        const len: u64 = bytes.len;
        const physical = store.bytes_head % store.bytes.len;
        // Records are contiguous: skip the tail of the ring when the record does not fit.
        if (physical + len > store.bytes.len) store.bytes_head += store.bytes.len - physical;
        const end = store.bytes_head + len;
        while (store.head > store.tail) {
            const oldest = &store.entries[store.tail % store.entries.len];
            const ring_full = store.head - store.tail == store.entries.len;
            // The new record covers ring positions [bytes_head, end); the oldest record
            // starts again one lap later, so they overlap once `end` passes that point.
            const overlaps = len > 0 and oldest.offset + store.bytes.len < end;
            if (!ring_full and !overlaps) break;
            store.evict_oldest();
        }
        const start: usize = @intCast(store.bytes_head % store.bytes.len);
        @memcpy(store.bytes[start..][0..bytes.len], bytes);
        store.entries[store.head % store.entries.len] = .{
            .ref = block_ref,
            .offset = store.bytes_head,
            .len = @intCast(bytes.len),
        };
        store.by_hash.putAssumeCapacityNoClobber(block_ref.hash, store.head);
        store.head += 1;
        store.bytes_head = end;
        assert(store.head - store.tail <= store.entries.len);
    }

    fn evict_oldest(store: *BlockStore) void {
        assert(store.head > store.tail);
        const oldest = &store.entries[store.tail % store.entries.len];
        assert(store.by_hash.remove(oldest.ref.hash));
        store.tail += 1;
    }

    pub fn ref(store: *const BlockStore, hash: Hash) ?Ref {
        const sequence = store.by_hash.get(hash) orelse return null;
        return store.entries[sequence % store.entries.len].ref;
    }

    /// The record stored for `hash`; valid until the next `put`.
    pub fn record(store: *const BlockStore, hash: Hash) ?[]const u8 {
        const sequence = store.by_hash.get(hash) orelse return null;
        const entry = &store.entries[sequence % store.entries.len];
        const start: usize = @intCast(entry.offset % store.bytes.len);
        return store.bytes[start..][0..entry.len];
    }

    pub fn set_canonical(store: *BlockStore, number: u64, hash: Hash) void {
        const index = number % store.canonical.len;
        store.canonical[index] = hash;
        store.canonical_numbers[index] = number;
    }

    pub fn canonical_hash(store: *const BlockStore, number: u64) ?Hash {
        const index = number % store.canonical.len;
        if (store.canonical_numbers[index] != number) return null;
        return store.canonical[index];
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn test_ref(n: u64) Ref {
    var hash: Hash = @splat(0);
    std.mem.writeInt(u64, hash[0..8], n + 1, .little);
    return .{ .hash = hash, .parent_hash = @splat(0), .number = n, .timestamp = n };
}

test "block_store: put, get and canonical index" {
    var store = try BlockStore.init(testing.allocator, .{ .blocks_max = 4, .bytes_max = 64 });
    defer store.deinit(testing.allocator);
    try store.put(test_ref(1), "abc");
    try testing.expectEqualSlices(u8, "abc", store.record(test_ref(1).hash).?);
    try testing.expectEqual(@as(u64, 1), store.ref(test_ref(1).hash).?.number);
    try testing.expect(store.ref(test_ref(2).hash) == null);
    store.set_canonical(1, test_ref(1).hash);
    try testing.expectEqualSlices(u8, &test_ref(1).hash, &store.canonical_hash(1).?);
    try testing.expect(store.canonical_hash(5) == null);
    try testing.expectError(error.RecordTooLarge, store.put(test_ref(9), &@as([65]u8, @splat(0))));
}

test "block_store: records survive until their bytes are reused" {
    var store = try BlockStore.init(testing.allocator, .{ .blocks_max = 4, .bytes_max = 64 });
    defer store.deinit(testing.allocator);
    const ten: [10]u8 = @splat(1);
    for (0..4) |n| try store.put(test_ref(n), &ten);
    try testing.expectEqual(@as(u32, 4), store.count());
    try store.put(test_ref(4), &ten);
    try testing.expectEqual(@as(u32, 4), store.count());
    try testing.expect(store.ref(test_ref(0).hash) == null);
    var other = try BlockStore.init(testing.allocator, .{ .blocks_max = 4, .bytes_max = 64 });
    defer other.deinit(testing.allocator);
    const thirty: [30]u8 = @splat(2);
    try other.put(test_ref(0), &thirty);
    try other.put(test_ref(1), &thirty);
    // 10 bytes do not fit at 60: skip to the next lap, reusing record 0's bytes only.
    try other.put(test_ref(2), &ten);
    try testing.expect(other.ref(test_ref(0).hash) == null);
    try testing.expectEqualSlices(u8, &thirty, other.record(test_ref(1).hash).?);
    try testing.expectEqual(@as(u32, 2), other.count());
}

/// Random records against a model of which recent records must survive.
fn random_store(prng: *Prng) !void {
    const blocks_max = prng.range(1, 8);
    const bytes_max = prng.range(8, 128);
    var store = try BlockStore.init(testing.allocator, .{
        .blocks_max = @intCast(blocks_max),
        .bytes_max = bytes_max,
    });
    defer store.deinit(testing.allocator);
    var lengths: [64]usize = undefined;
    var buffer: [128]u8 = undefined;
    for (0..64) |n| {
        lengths[n] = prng.below(bytes_max + 1);
        @memset(buffer[0..lengths[n]], @truncate(n));
        try store.put(test_ref(n), buffer[0..lengths[n]]);
        // The newest record always survives, and every live record is intact.
        try testing.expectEqual(lengths[n], store.record(test_ref(n).hash).?.len);
        var live: usize = 0;
        for (0..n + 1) |m| {
            const stored = store.record(test_ref(m).hash) orelse continue;
            live += 1;
            try testing.expectEqual(lengths[m], stored.len);
            for (stored) |byte| try testing.expectEqual(@as(u8, @truncate(m)), byte);
        }
        try testing.expectEqual(@as(usize, store.count()), live);
        try testing.expect(live <= blocks_max);
        // Bytes alone never force eviction of the previous record when both fit twice.
        if (n > 0 and blocks_max > 1 and 2 * (lengths[n] + lengths[n - 1]) <= bytes_max) {
            try testing.expect(store.record(test_ref(n - 1).hash) != null);
        }
    }
}

test "block_store: seeded fuzz eviction keeps live records intact" {
    var prng = Prng.init(0xb10c);
    for (0..64) |_| try random_store(&prng);
}

fn fuzz_store(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try random_store(&prng);
}

test "block_store: fuzz" {
    try testing.fuzz({}, fuzz_store, .{});
}
