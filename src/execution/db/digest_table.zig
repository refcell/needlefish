//! Digest table: a hash table keyed by keccak digests (`DiskState`'s locator memo), allocated
//! at init from its bound, that stays dense while it holds few entries.
//!
//! Entries (key and value) are appended in insertion order to arrays of `entries_max`. An
//! index of `u64` slots (a fingerprint of the key and the entry's number) is probed linearly
//! from the key's first word: digests are uniform, so their bytes are the hash. Only the
//! first `slots_active` slots are in use. The index doubles (rebuilt from the keys, in
//! order) when the count would pass half of it, up to twice `entries_max`, so a table
//! holding thousands of entries touches kilobytes of index and a few contiguous runs of
//! entries, not the whole reservation its bound sizes (`lazy_alloc`: never-touched pages
//! stay uncommitted). `clear` resets the smallest index only.
//!
//! No removal: entries live until `clear`, and value pointers stay valid until then.

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../utilities/lazy_alloc/root.zig");

pub const Hash = [32]u8;

/// The smallest index (slots), the one `clear` returns to.
pub const slots_active_min: u32 = 1024;

/// An index slot: `fingerprint << 32 | (entry + 1)`, 0 when empty.
const fingerprint_mask: u64 = 0xffff_ffff_0000_0000;

comptime {
    assert(std.math.isPowerOfTwo(slots_active_min));
}

pub fn DigestTableType(comptime Value: type) type {
    return struct {
        const Table = @This();

        keys: []Hash,
        values: []Value,
        slots: []u64,
        /// A power of two; `slots[0..slots_active]` is the index, at most half full.
        slots_active: u32,
        entries_count: u32 = 0,

        pub const GetOrPut = struct { value_ptr: *Value, found_existing: bool };

        const Probe = struct { slot: u32, entry: ?u32 };

        pub fn init(allocator: std.mem.Allocator, entries_max: u32) !Table {
            assert(entries_max > 0 and entries_max < std.math.maxInt(u32) / 2);
            const slots_max = std.math.ceilPowerOfTwoAssert(
                u32,
                @max(2 * entries_max, slots_active_min),
            );
            const keys = try lazy.alloc(allocator, Hash, entries_max);
            errdefer lazy.free(allocator, keys);
            const values = try lazy.alloc(allocator, Value, entries_max);
            errdefer lazy.free(allocator, values);
            const slots = try lazy.alloc(allocator, u64, slots_max);
            var table: Table = .{
                .keys = keys,
                .values = values,
                .slots = slots,
                .slots_active = slots_active_min,
            };
            table.clear();
            assert(table.slots.len >= 2 * table.keys.len);
            return table;
        }

        pub fn deinit(self: *Table, allocator: std.mem.Allocator) void {
            lazy.free(allocator, self.slots);
            lazy.free(allocator, self.values);
            lazy.free(allocator, self.keys);
            self.* = undefined;
        }

        pub fn count(self: *const Table) u32 {
            return self.entries_count;
        }

        pub fn capacity(self: *const Table) u32 {
            return @intCast(self.keys.len);
        }

        /// Forgets every entry.
        pub fn clear(self: *Table) void {
            self.entries_count = 0;
            self.slots_active = @min(slots_active_min, @as(u32, @intCast(self.slots.len)));
            @memset(self.slots[0..self.slots_active], 0);
            assert(self.entries_count == 0);
        }

        pub fn contains(self: *const Table, key: *const Hash) bool {
            return self.probe(key).entry != null;
        }

        pub fn get_ptr(self: *const Table, key: *const Hash) ?*Value {
            const entry = self.probe(key).entry orelse return null;
            assert(entry < self.entries_count);
            return &self.values[entry];
        }

        /// The value of `key`, added (undefined: the caller sets it) when absent; null when
        /// absent and the table holds `capacity` entries.
        pub fn get_or_put(self: *Table, key: *const Hash) ?GetOrPut {
            var found = self.probe(key);
            if (found.entry) |entry| {
                return .{ .value_ptr = &self.values[entry], .found_existing = true };
            }
            if (self.entries_count == self.keys.len) return null;
            if (2 * (self.entries_count + 1) > self.slots_active) {
                self.grow();
                found = self.probe(key);
                assert(found.entry == null);
            }
            const entry = self.entries_count;
            self.keys[entry] = key.*;
            self.slots[found.slot] = slot_of(key, entry);
            self.entries_count += 1;
            assert(2 * self.entries_count <= self.slots_active);
            return .{ .value_ptr = &self.values[entry], .found_existing = false };
        }

        fn slot_of(key: *const Hash, entry: u32) u64 {
            const fingerprint: u64 = std.mem.readInt(u32, key[8..12], .little);
            return fingerprint << 32 | (@as(u64, entry) + 1);
        }

        /// The slot holding `key`, else the empty slot where it goes. The index is at most
        /// half full, so the probe ends within `slots_active` steps.
        fn probe(self: *const Table, key: *const Hash) Probe {
            assert(std.math.isPowerOfTwo(self.slots_active));
            const mask = self.slots_active - 1;
            const fingerprint = slot_of(key, 0) & fingerprint_mask;
            var slot: u32 = @intCast(std.mem.readInt(u64, key[0..8], .little) & mask);
            var probes: u32 = 0;
            while (probes < self.slots_active) : (probes += 1) {
                const value = self.slots[slot];
                if (value == 0) return .{ .slot = slot, .entry = null };
                if (value & fingerprint_mask == fingerprint) {
                    const entry = @as(u32, @truncate(value)) - 1;
                    assert(entry < self.entries_count);
                    if (std.mem.eql(u8, &self.keys[entry], key)) {
                        return .{ .slot = slot, .entry = entry };
                    }
                }
                slot = (slot + 1) & mask;
            }
            unreachable; // At most half the active slots are taken: the probe met an empty one.
        }

        /// Doubles the index and reinserts every entry, in insertion order.
        fn grow(self: *Table) void {
            assert(2 * self.slots_active <= self.slots.len);
            self.slots_active *= 2;
            @memset(self.slots[0..self.slots_active], 0);
            for (self.keys[0..self.entries_count], 0..) |*key, entry| {
                const found = self.probe(key);
                assert(found.entry == null);
                self.slots[found.slot] = slot_of(key, @intCast(entry));
            }
            assert(2 * self.entries_count <= self.slots_active);
        }
    };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// A random key; with `narrow`, keys share their first word often (long probe runs, equal
/// fingerprints).
fn random_key(prng: *Prng, narrow: bool) Hash {
    var key: Hash = undefined;
    prng.fill(&key);
    if (narrow) {
        @memset(key[0..12], 0);
        key[0] = @intCast(prng.below(4));
        key[8] = @intCast(prng.below(2));
    }
    return key;
}

test "digest table: matches a hash map across growth, clears, and a full table" {
    const Table = DigestTableType(u64);
    var prng = Prng.init(0xd16e57);
    var model: std.AutoHashMapUnmanaged(Hash, u64) = .empty;
    defer model.deinit(testing.allocator);
    const entries_max: u32 = 3000;
    var table = try Table.init(testing.allocator, entries_max);
    defer table.deinit(testing.allocator);
    var keys: std.ArrayList(Hash) = .empty;
    defer keys.deinit(testing.allocator);
    var round: u32 = 0;
    while (round < 6) : (round += 1) {
        table.clear();
        model.clearRetainingCapacity();
        keys.clearRetainingCapacity();
        const narrow = round % 2 == 1;
        const operations = 1000 + prng.below(4 * entries_max);
        for (0..operations) |_| {
            const key = if (keys.items.len > 0 and prng.chance(1, 3))
                keys.items[prng.below(keys.items.len)]
            else
                random_key(&prng, narrow);
            const value = prng.int(u64);
            const full = model.count() == entries_max and !model.contains(key);
            const result = table.get_or_put(&key);
            if (full) {
                try testing.expect(result == null);
                continue;
            }
            const put = result.?;
            const existing = model.get(key);
            try testing.expectEqual(existing != null, put.found_existing);
            if (existing) |want| try testing.expectEqual(want, put.value_ptr.*);
            put.value_ptr.* = value;
            try model.put(testing.allocator, key, value);
            if (existing == null) try keys.append(testing.allocator, key);
            try testing.expectEqual(model.count(), table.count());
        }
        for (keys.items) |*key| {
            try testing.expectEqual(model.get(key.*).?, table.get_ptr(key).?.*);
        }
        for (0..64) |_| {
            const key = random_key(&prng, narrow);
            try testing.expectEqual(model.contains(key), table.contains(&key));
        }
        try testing.expect(2 * table.count() <= table.slots_active);
    }
}
