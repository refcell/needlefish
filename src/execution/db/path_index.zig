//! Open-addressing index from a history path key to its path id (`history.Store`).
//!
//! The index stores only a 32-bit key hash and the path id per slot (8 bytes); the keys
//! themselves live in the store's path records, which a lookup loads anyway (they hold the
//! path's newest version). A lookup touches one slot line plus the matching path record,
//! where a `std.HashMap(Key, u32)` touches metadata, a key, a value, and then the record.
//!
//! Linear probing with backward-shift deletion: no tombstones, so probe lengths never grow
//! with churn and no periodic rehash is needed. Capacity is fixed at init (load at most
//! 2/3 of the slots); the slot array is allocated and filled once at `clear`.

const std = @import("std");
const assert = std.debug.assert;

const lazy_alloc = @import("../../utilities/lazy_alloc/root.zig");

pub const none: u32 = std.math.maxInt(u32);

pub const Slot = struct {
    hash: u32,
    /// `none` marks an empty slot.
    id: u32,
};

comptime {
    assert(@sizeOf(Slot) == 8);
}

const empty: Slot = .{ .hash = 0, .id = none };

pub const PathIndex = struct {
    slots: []Slot,
    count: u32,
    count_max: u32,

    pub fn init(allocator: std.mem.Allocator, count_max: u32) !PathIndex {
        assert(count_max < none / 2);
        const capacity: u32 = @max(8, count_max + count_max / 2 + 1);
        assert(capacity > count_max);
        const slots = try lazy_alloc.alloc(allocator, Slot, capacity);
        var self: PathIndex = .{ .slots = slots, .count = 0, .count_max = count_max };
        self.clear();
        return self;
    }

    pub fn deinit(self: *PathIndex, allocator: std.mem.Allocator) void {
        lazy_alloc.free(allocator, self.slots);
        self.* = undefined;
    }

    pub fn clear(self: *PathIndex) void {
        @memset(self.slots, empty);
        self.count = 0;
    }

    /// The slot a hash starts probing at (multiply-shift range reduction).
    fn home(self: *const PathIndex, hash: u32) u32 {
        const length: u64 = self.slots.len;
        const index: u32 = @intCast((@as(u64, hash) * length) >> 32);
        assert(index < self.slots.len);
        return index;
    }

    fn next(self: *const PathIndex, index: u32) u32 {
        assert(index < self.slots.len);
        return if (index + 1 == self.slots.len) 0 else index + 1;
    }

    /// The id whose key has `hash` and satisfies `matcher.eql(id)`, or null.
    pub fn find(self: *const PathIndex, hash: u32, matcher: anytype) ?u32 {
        var index = self.home(hash);
        var probes: u32 = 0;
        while (probes < self.slots.len) : (probes += 1) {
            const slot = self.slots[index];
            if (slot.id == none) return null;
            if (slot.hash == hash and matcher.eql(slot.id)) return slot.id;
            index = self.next(index);
        }
        // Load stays at most 2/3, so an empty slot always ends the probe.
        unreachable;
    }

    /// Adds `id` under `hash`; its key must be absent.
    pub fn insert(self: *PathIndex, hash: u32, id: u32) void {
        assert(id != none);
        assert(self.count < self.count_max);
        var index = self.home(hash);
        var probes: u32 = 0;
        while (self.slots[index].id != none) : (probes += 1) {
            assert(probes < self.slots.len);
            assert(self.slots[index].id != id);
            index = self.next(index);
        }
        self.slots[index] = .{ .hash = hash, .id = id };
        self.count += 1;
    }

    /// Removes `id`, stored under `hash`; it must be present.
    pub fn remove(self: *PathIndex, hash: u32, id: u32) void {
        assert(id != none);
        assert(self.count > 0);
        var index = self.home(hash);
        var probes: u32 = 0;
        while (self.slots[index].id != id) : (probes += 1) {
            assert(probes < self.slots.len);
            assert(self.slots[index].id != none);
            index = self.next(index);
        }
        assert(self.slots[index].hash == hash);
        self.shift_back(index);
        self.count -= 1;
    }

    /// Backward-shift deletion: empties `hole`, then moves each later entry of the run back
    /// into the hole when the hole lies on its probe path (between its home and its slot).
    fn shift_back(self: *PathIndex, start: u32) void {
        var hole = start;
        var index = self.next(start);
        var steps: u32 = 0;
        while (self.slots[index].id != none) : (steps += 1) {
            assert(steps < self.slots.len);
            const slot_home = self.home(self.slots[index].hash);
            if (self.distance(slot_home, index) >= self.distance(hole, index)) {
                self.slots[hole] = self.slots[index];
                hole = index;
            }
            index = self.next(index);
        }
        self.slots[hole] = empty;
    }

    /// Probe steps from `from` forward (wrapping) to `to`.
    fn distance(self: *const PathIndex, from: u32, to: u32) u32 {
        assert(from < self.slots.len and to < self.slots.len);
        if (to >= from) return to - from;
        return @as(u32, @intCast(self.slots.len)) - from + to;
    }

    /// Calls `visitor.visit(id)` for every stored id (slot order).
    pub fn for_each(self: *const PathIndex, visitor: anytype) void {
        var seen: u32 = 0;
        for (self.slots) |slot| {
            if (slot.id == none) continue;
            visitor.visit(slot.id);
            seen += 1;
        }
        assert(seen == self.count);
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// Keys are `u64`s in `keys[id]`; hashes are deliberately weak to force long runs.
const Model = struct {
    keys: []const u64,
    key: u64,

    fn eql(self: Model, id: u32) bool {
        return self.keys[id] == self.key;
    }
};

fn weak_hash(key: u64, bits: u5) u32 {
    const mixed: u32 = @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&key)));
    if (bits == 0) return mixed;
    // Few distinct hashes: many full collisions and long clusters.
    return mixed & ~((@as(u32, 1) << (31 - @as(u5, @min(bits, 30)))) - 1);
}

fn check_against_model(seed: u64) !void {
    var prng = Prng.init(seed);
    const count_max: u32 = @intCast(prng.range(1, 200));
    const bits: u5 = @intCast(prng.below(8));
    var index = try PathIndex.init(testing.allocator, count_max);
    defer index.deinit(testing.allocator);
    const keys = try testing.allocator.alloc(u64, count_max);
    defer testing.allocator.free(keys);
    var model: std.AutoHashMapUnmanaged(u64, u32) = .empty;
    defer model.deinit(testing.allocator);
    // Free ids, like the store's path free stack.
    var free_ids = try testing.allocator.alloc(u32, count_max);
    defer testing.allocator.free(free_ids);
    for (free_ids, 0..) |*id, offset| id.* = @intCast(count_max - 1 - offset);
    var free_len: u32 = count_max;
    for (0..prng.range(1, 2000)) |_| {
        const key = prng.below(count_max * 2);
        const hash = weak_hash(key, bits);
        const found = index.find(hash, Model{ .keys = keys, .key = key });
        try testing.expectEqual(model.get(key), found);
        if (found) |id| {
            if (prng.chance(1, 2)) {
                index.remove(hash, id);
                _ = model.remove(key);
                free_ids[free_len] = id;
                free_len += 1;
            }
        } else if (free_len > 0) {
            free_len -= 1;
            const id = free_ids[free_len];
            keys[id] = key;
            index.insert(hash, id);
            try model.put(testing.allocator, key, id);
        }
        try testing.expectEqual(model.count(), index.count);
    }
    var it = model.iterator();
    while (it.next()) |entry| {
        const hash = weak_hash(entry.key_ptr.*, bits);
        const found = index.find(hash, Model{ .keys = keys, .key = entry.key_ptr.* });
        try testing.expectEqual(entry.value_ptr.*, found.?);
    }
    if (prng.chance(1, 4)) {
        index.clear();
        try testing.expectEqual(@as(u32, 0), index.count);
    }
}

test "path index: seeded fuzz against a hash map model (weak hashes, churn)" {
    for (0..64) |seed| try check_against_model(0x9a7e + seed);
}

fn fuzz_index(_: void, smith: *testing.Smith) anyerror!void {
    try check_against_model(smith.value(u64));
}

test "path index: fuzz" {
    try testing.fuzz({}, fuzz_index, .{});
}
