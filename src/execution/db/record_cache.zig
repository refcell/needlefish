//! Record cache: branch records `DiskState` resolved or wrote, kept across blocks, keyed by
//! the hash of the record's top node and the record's hang (its position in its trie).
//!
//! Content-addressed, so an entry is never stale: the top node's hash fixes its bytes, and
//! with them its children (an extension's branch is fixed by its hash too), which children are
//! records or leaves (a child's kind is fixed by its hash), and each leaf's path suffix; the
//! hang then fixes the leaf keys. So a (hash, hang) pair names exactly one record, whatever
//! the owner, the block, or the trees hold now: no invalidation is needed on write-back,
//! unwind, reorg, checkpoint, crash, or reopen. A lookup must still name the hash it wants
//! (the parent's reference), so the cache only answers for nodes of the trie being walked.
//! Only verified records go in: resolved ones after their top hashed to the reference, and
//! written ones from the post-state trie the root computation hashed.
//!
//! Shape: set-associative with CLOCK eviction per set (`table.zig`'s `BlockCache` shape), each
//! slot holding one encoded record of at most `branch_record.value_bytes_max` bytes. Static:
//! every slot is allocated at init.

const std = @import("std");
const assert = std.debug.assert;

const branch_record = @import("branch_record.zig");

const Hash = [32]u8;
const PathKey = [branch_record.path_key_bytes]u8;

pub const ways: u32 = 8;
const value_bytes_max = branch_record.value_bytes_max;

comptime {
    assert(ways <= std.math.maxInt(u8));
    assert(value_bytes_max <= std.math.maxInt(u16));
}

pub const Stats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    puts: u64 = 0,
    evictions: u64 = 0,
};

pub const RecordCache = struct {
    set_count: u32,
    /// Per slot: the top node's hash, the hang's path key, the value length (0: empty), the
    /// CLOCK reference bit, and the value.
    hashes: []Hash,
    hangs: []PathKey,
    lengths: []u16,
    referenced: []bool,
    /// Per set: the CLOCK hand.
    hands: []u8,
    values: []u8,
    stats: Stats = .{},

    /// Bytes `entries_max` entries take (sizing a node's memory).
    pub fn bytes_of(entries_max: u32) u64 {
        const slot = @sizeOf(Hash) + @sizeOf(PathKey) + 2 + 1 + value_bytes_max;
        return @as(u64, entries_max) * slot + entries_max / ways;
    }

    pub fn init(allocator: std.mem.Allocator, entries_max: u32) !RecordCache {
        assert(entries_max >= ways);
        const set_count = entries_max / ways;
        const slots: usize = @as(usize, set_count) * ways;
        const hashes = try allocator.alloc(Hash, slots);
        errdefer allocator.free(hashes);
        const hangs = try allocator.alloc(PathKey, slots);
        errdefer allocator.free(hangs);
        const lengths = try allocator.alloc(u16, slots);
        errdefer allocator.free(lengths);
        const referenced = try allocator.alloc(bool, slots);
        errdefer allocator.free(referenced);
        const hands = try allocator.alloc(u8, set_count);
        errdefer allocator.free(hands);
        const values = try allocator.alloc(u8, slots * value_bytes_max);
        @memset(lengths, 0);
        @memset(referenced, false);
        @memset(hands, 0);
        return .{
            .set_count = set_count,
            .hashes = hashes,
            .hangs = hangs,
            .lengths = lengths,
            .referenced = referenced,
            .hands = hands,
            .values = values,
        };
    }

    pub fn deinit(self: *RecordCache, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
        allocator.free(self.hands);
        allocator.free(self.referenced);
        allocator.free(self.lengths);
        allocator.free(self.hangs);
        allocator.free(self.hashes);
        self.* = undefined;
    }

    fn first_slot(self: *const RecordCache, hash: *const Hash) usize {
        // Hashes are uniform: their first bytes spread the sets.
        const mixed = std.mem.readInt(u64, hash[0..8], .little);
        const set: usize = @intCast(mixed % self.set_count);
        return set * ways;
    }

    fn find(self: *const RecordCache, hash: *const Hash, hang: *const PathKey) ?usize {
        const first = self.first_slot(hash);
        for (first..first + ways) |slot| {
            if (self.lengths[slot] == 0) continue;
            if (!std.mem.eql(u8, &self.hashes[slot], hash)) continue;
            if (!std.mem.eql(u8, &self.hangs[slot], hang)) continue;
            return slot;
        }
        return null;
    }

    fn value_at(self: *const RecordCache, slot: usize) []const u8 {
        const length = self.lengths[slot];
        assert(length > 0 and length <= value_bytes_max);
        return self.values[slot * value_bytes_max ..][0..length];
    }

    /// The record hanging at `hang` whose top node hashes to `hash`, or null. Valid until
    /// the next `put`.
    pub fn get(self: *RecordCache, hash: *const Hash, hang: []const u8) ?[]const u8 {
        assert(hang.len <= branch_record.hang_nibbles_max);
        const key = branch_record.path_key(hang);
        const slot = self.find(hash, &key) orelse {
            self.stats.misses += 1;
            return null;
        };
        self.referenced[slot] = true;
        self.stats.hits += 1;
        return self.value_at(slot);
    }

    /// Caches the verified record `value` hanging at `hang` with top node hash `hash`.
    pub fn put(self: *RecordCache, hash: *const Hash, hang: []const u8, value: []const u8) void {
        assert(hang.len <= branch_record.hang_nibbles_max);
        assert(value.len >= 1 and value.len <= value_bytes_max);
        const key = branch_record.path_key(hang);
        self.stats.puts += 1;
        const slot = self.find(hash, &key) orelse self.evict(self.first_slot(hash));
        self.hashes[slot] = hash.*;
        self.hangs[slot] = key;
        self.lengths[slot] = @intCast(value.len);
        self.referenced[slot] = false;
        @memcpy(self.values[slot * value_bytes_max ..][0..value.len], value);
        assert(std.mem.eql(u8, self.value_at(slot), value));
    }

    /// One cached record (for checks).
    pub const Entry = struct { hash: *const Hash, hang: *const PathKey, value: []const u8 };

    pub fn slot_count(self: *const RecordCache) usize {
        assert(self.lengths.len == @as(usize, self.set_count) * ways);
        return self.lengths.len;
    }

    /// The record in `slot`, or null when the slot is empty.
    pub fn entry(self: *const RecordCache, slot: usize) ?Entry {
        assert(slot < self.slot_count());
        if (self.lengths[slot] == 0) return null;
        return .{
            .hash = &self.hashes[slot],
            .hang = &self.hangs[slot],
            .value = self.value_at(slot),
        };
    }

    /// CLOCK: the first slot from the hand that is empty or not referenced, clearing
    /// reference bits on the way.
    fn evict(self: *RecordCache, first: usize) usize {
        assert(first % ways == 0);
        const set = first / ways;
        var step: u32 = 0;
        // Bounded: after one full turn every bit is clear.
        while (step <= 2 * ways) : (step += 1) {
            const slot = first + self.hands[set];
            self.hands[set] = @intCast((self.hands[set] + 1) % ways);
            if (self.lengths[slot] == 0) return slot;
            if (!self.referenced[slot]) {
                self.stats.evictions += 1;
                return slot;
            }
            self.referenced[slot] = false;
        }
        unreachable; // One turn clears every bit, the next finds a slot.
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "record cache: hits need the hash and the hang, CLOCK keeps referenced entries" {
    var cache = try RecordCache.init(testing.allocator, 2 * ways);
    defer cache.deinit(testing.allocator);
    var hash: Hash = @splat(0);
    const value = [_]u8{ 1, 2, 3 };
    cache.put(&hash, &.{ 1, 2 }, &value);
    try testing.expectEqualSlices(u8, &value, cache.get(&hash, &.{ 1, 2 }).?);
    try testing.expect(cache.get(&hash, &.{1}) == null);
    try testing.expect(cache.get(&hash, &.{ 1, 2, 0 }) == null);
    var other = hash;
    other[31] = 1;
    try testing.expect(cache.get(&other, &.{ 1, 2 }) == null);
    // The same key again replaces in place.
    cache.put(&hash, &.{ 1, 2 }, &.{9});
    try testing.expectEqualSlices(u8, &.{9}, cache.get(&hash, &.{ 1, 2 }).?);
    try testing.expectEqual(@as(u64, 0), cache.stats.evictions);
    // Fill the set (same first bytes): the referenced entry survives one turn of CLOCK.
    for (1..ways) |index| {
        var filler = hash;
        filler[31] = @intCast(index + 1);
        cache.put(&filler, &.{}, &value);
    }
    try testing.expect(cache.get(&hash, &.{ 1, 2 }) != null);
    var newcomer = hash;
    newcomer[30] = 1;
    cache.put(&newcomer, &.{}, &value);
    try testing.expectEqual(@as(u64, 1), cache.stats.evictions);
    try testing.expect(cache.get(&hash, &.{ 1, 2 }) != null);
    try testing.expect(cache.get(&newcomer, &.{}) != null);
}

test "record cache: seeded puts and gets match a model of the live entries" {
    var cache = try RecordCache.init(testing.allocator, 4 * ways);
    defer cache.deinit(testing.allocator);
    var prng = Prng.init(0x2ec0_cac3);
    var values: [64][value_bytes_max]u8 = undefined;
    var lengths: [64]u16 = undefined;
    for (&values, &lengths) |*bytes, *length| {
        prng.fill(bytes);
        length.* = @intCast(prng.range(1, value_bytes_max));
    }
    for (0..4096) |_| {
        // Keys from a small universe: hash index and hang length; value fixed per key.
        const id = prng.below(64);
        var hash: Hash = @splat(0);
        hash[0] = @intCast(id % 8);
        hash[1] = @intCast(id);
        const hang = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
        const hang_len: usize = @intCast(id % 7);
        const expected = values[@intCast(id)][0..lengths[@intCast(id)]];
        if (prng.chance(1, 2)) {
            cache.put(&hash, hang[0..hang_len], expected);
        } else if (cache.get(&hash, hang[0..hang_len])) |got| {
            try testing.expectEqualSlices(u8, expected, got);
        }
    }
    try testing.expect(cache.stats.hits > 0 and cache.stats.evictions > 0);
}
