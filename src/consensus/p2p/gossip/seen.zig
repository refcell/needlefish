//! Bounded set of recently seen gossipsub message ids with time-based expiry (gossipsub
//! `seen_ttl`; base/base: 130 heartbeats = 65 s). Open addressing with linear probing
//! and backward-shift deletion (no tombstones), plus a FIFO of insertions so expiry is
//! O(expired). When full, the oldest id is evicted early: a re-delivered duplicate costs
//! bandwidth, never correctness, because validation runs again.

const std = @import("std");
const assert = std.debug.assert;

pub const id_length = 20;
pub const Id = [id_length]u8;

pub fn SeenCache(comptime capacity: u32) type {
    comptime assert(std.math.isPowerOfTwo(capacity));
    // Keep load factor <= 1/2 so probe sequences stay short.
    const slots = capacity * 2;
    return struct {
        const Self = @This();
        const empty_slot: u32 = std.math.maxInt(u32);

        ids: [capacity]Id = undefined,
        inserted_ns: [capacity]u64 = undefined,
        /// Slot table: index into `ids`, or `empty_slot`.
        table: [slots]u32 = @splat(empty_slot),
        /// FIFO over `ids`: entries `head .. head+count` (mod capacity) are live.
        head: u32 = 0,
        count: u32 = 0,

        fn home(id: *const Id) u32 {
            // Ids are hash outputs already: their prefix is uniformly distributed.
            return std.mem.readInt(u32, id[0..4], .little) & (slots - 1);
        }

        fn find_slot(cache: *const Self, id: *const Id) ?u32 {
            var slot = home(id);
            var probes: u32 = 0;
            while (probes < slots) : (probes += 1) {
                const entry = cache.table[slot];
                if (entry == empty_slot) return null;
                if (std.mem.eql(u8, &cache.ids[entry], id)) return slot;
                slot = (slot + 1) & (slots - 1);
            }
            unreachable; // Load factor <= 1/2 guarantees an empty slot.
        }

        pub fn contains(cache: *const Self, id: *const Id) bool {
            return cache.find_slot(id) != null;
        }

        /// Inserts `id`. Returns false if it was already present (a duplicate).
        pub fn insert(cache: *Self, id: *const Id, now_ns: u64) bool {
            if (cache.contains(id)) return false;
            if (cache.count == capacity) cache.evict_oldest();
            const index = (cache.head + cache.count) % capacity;
            cache.ids[index] = id.*;
            cache.inserted_ns[index] = now_ns;
            cache.count += 1;
            var slot = home(id);
            while (cache.table[slot] != empty_slot) slot = (slot + 1) & (slots - 1);
            cache.table[slot] = index;
            assert(cache.count <= capacity);
            return true;
        }

        fn evict_oldest(cache: *Self) void {
            assert(cache.count > 0);
            const slot = cache.find_slot(&cache.ids[cache.head]) orelse unreachable;
            cache.delete_slot(slot);
            cache.head = (cache.head + 1) % capacity;
            cache.count -= 1;
        }

        /// Backward-shift deletion keeps every remaining entry reachable from its home.
        fn delete_slot(cache: *Self, removed: u32) void {
            var hole = removed;
            var slot = (hole + 1) & (slots - 1);
            var probes: u32 = 0;
            while (probes < slots) : (probes += 1) {
                const entry = cache.table[slot];
                if (entry == empty_slot) break;
                const entry_home = home(&cache.ids[entry]);
                // Move `entry` into the hole unless its home lies cyclically in (hole, slot].
                const distance_home = (slot -% entry_home) & (slots - 1);
                const distance_hole = (slot -% hole) & (slots - 1);
                if (distance_home >= distance_hole) {
                    cache.table[hole] = entry;
                    hole = slot;
                }
                slot = (slot + 1) & (slots - 1);
            }
            cache.table[hole] = empty_slot;
        }

        /// Drops ids inserted at or before `now_ns - ttl_ns`.
        pub fn expire(cache: *Self, now_ns: u64, ttl_ns: u64) void {
            while (cache.count > 0) {
                if (now_ns -| cache.inserted_ns[cache.head] < ttl_ns) break;
                cache.evict_oldest();
            }
        }
    };
}

const Prng = @import("../../../testing/prng.zig").Prng;

test "seen: insert, duplicate, expiry, eviction" {
    const Cache = SeenCache(8);
    var cache: Cache = .{};
    var ids: [12]Id = undefined;
    var prng = Prng.init(5);
    for (&ids) |*id| prng.fill(id);
    for (ids[0..8], 0..) |*id, index| try std.testing.expect(cache.insert(id, index));
    try std.testing.expect(!cache.insert(&ids[3], 100));
    try std.testing.expect(cache.insert(&ids[8], 9));
    try std.testing.expect(!cache.contains(&ids[0]));
    try std.testing.expect(cache.contains(&ids[1]));
    cache.expire(10, 5);
    try std.testing.expect(!cache.contains(&ids[5]));
    try std.testing.expect(cache.contains(&ids[6]));
    cache.expire(1000, 5);
    try std.testing.expectEqual(@as(u32, 0), cache.count);
}

test "seen: seeded model check against a linear list" {
    const capacity = 64;
    var cache: SeenCache(capacity) = .{};
    var model: [capacity]Id = undefined;
    var model_count: usize = 0;
    var prng = Prng.init(0x7365_656e);
    var pool: [96]Id = undefined;
    // Colliding prefixes stress probing and backward-shift deletion.
    for (&pool, 0..) |*id, index| {
        prng.fill(id);
        if (index % 3 == 0) @memset(id[0..4], 0);
    }
    for (0..5000) |_| {
        const id = &pool[prng.below(pool.len)];
        const in_model = for (model[0..model_count]) |*other| {
            if (std.mem.eql(u8, other, id)) break true;
        } else false;
        try std.testing.expectEqual(in_model, cache.contains(id));
        if (!in_model) {
            if (model_count == capacity) {
                std.mem.copyForwards(Id, model[0 .. capacity - 1], model[1..capacity]);
                model_count -= 1;
            }
            model[model_count] = id.*;
            model_count += 1;
        }
        try std.testing.expectEqual(!in_model, cache.insert(id, 0));
        try std.testing.expectEqual(@as(u32, @intCast(model_count)), cache.count);
    }
}
