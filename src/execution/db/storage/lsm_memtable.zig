//! LSM memtable: a fixed-capacity table of the newest writes, with fixed-size keys and either
//! fixed-size values or (variable mode) values of 1..`value_size_max` bytes.
//!
//! Writes go to parallel arrays (key, value, tombstone, and in variable mode a `u16` value
//! length) in arrival order; an open-addressing hash index (linear probing, at most half full)
//! finds a key's entry, so a repeated key overwrites its entry in place and the memtable holds
//! each key once. A full memtable refuses writes (`error.Busy`); nothing is ever allocated
//! after `init`. Variable values occupy a `value_size_max` slot each: static memory sized by
//! the largest value, as every other bound here.
//!
//! When the tree flushes a memtable it sorts it once (`sort`: `order` lists the entries in key
//! order) and streams it into level-0 tables, then `reset`s it. A tombstone is a delete: it
//! shadows older values of the key in the levels below until compaction drops it.

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../../utilities/lazy_alloc/root.zig");

const key_size_max = @import("table.zig").key_size_max;

/// `value_size`: the value size, or (`variable`) the largest value size.
pub fn MemtableType(comptime key_size: u32, comptime value_size: u32, comptime varies: bool) type {
    const variable = varies;
    const value_size_max = value_size;
    comptime assert(key_size > 0 and key_size <= key_size_max);
    comptime assert(value_size_max > 0);
    comptime assert(!variable or value_size_max <= std.math.maxInt(u16));
    return struct {
        const Memtable = @This();
        pub const Key = [key_size]u8;
        pub const Value = [value_size_max]u8;

        keys: []Key,
        values: []Value,
        tombstones: []bool,
        /// Variable mode: each entry's value length (0 for a tombstone). Empty otherwise.
        lengths: []u16,
        /// Entry indices in key order, valid after `sort` until the next write.
        order: []u32,
        /// Hash index: entry index + 1, or 0 for an empty slot. Power-of-two length.
        slots: []u32,
        count: u32 = 0,
        /// Sum of the entries' value lengths (tombstones count 0).
        value_bytes_total: u64 = 0,
        sorted: bool = false,

        pub fn init(allocator: std.mem.Allocator, entries_max: u32) !Memtable {
            assert(entries_max > 0);
            assert(entries_max < std.math.maxInt(u32) / 4);
            const keys = try lazy.alloc(allocator, Key, entries_max);
            errdefer lazy.free(allocator, keys);
            const values = try lazy.alloc(allocator, Value, entries_max);
            errdefer lazy.free(allocator, values);
            const tombstones = try allocator.alloc(bool, entries_max);
            errdefer allocator.free(tombstones);
            const lengths = try allocator.alloc(u16, if (variable) entries_max else 0);
            errdefer allocator.free(lengths);
            const order = try lazy.alloc(allocator, u32, entries_max);
            errdefer lazy.free(allocator, order);
            const slot_count = std.math.ceilPowerOfTwo(u32, 2 * entries_max) catch unreachable;
            const slots = try allocator.alloc(u32, slot_count);
            @memset(slots, 0);
            @memset(tombstones, false);
            @memset(lengths, 0);
            return .{
                .keys = keys,
                .values = values,
                .tombstones = tombstones,
                .lengths = lengths,
                .order = order,
                .slots = slots,
            };
        }

        pub fn deinit(self: *Memtable, allocator: std.mem.Allocator) void {
            lazy.free(allocator, self.keys);
            lazy.free(allocator, self.values);
            allocator.free(self.tombstones);
            allocator.free(self.lengths);
            lazy.free(allocator, self.order);
            allocator.free(self.slots);
            self.* = undefined;
        }

        pub fn capacity(self: *const Memtable) u32 {
            return @intCast(self.keys.len);
        }

        pub fn reset(self: *Memtable) void {
            assert(self.count <= self.capacity());
            @memset(self.slots, 0);
            self.count = 0;
            self.value_bytes_total = 0;
            self.sorted = false;
        }

        /// The value bytes of `entry`: empty for a tombstone.
        pub fn value(self: *const Memtable, entry: u32) []const u8 {
            assert(entry < self.count);
            if (self.tombstones[entry]) return &.{};
            const length: u32 = if (variable) self.lengths[entry] else value_size_max;
            assert(length > 0 and length <= value_size_max);
            return self.values[entry][0..length];
        }

        fn slot_first(self: *const Memtable, key: *const Key) usize {
            const mask = self.slots.len - 1;
            return @intCast(std.hash.Wyhash.hash(0x6d74_626c, key) & mask);
        }

        /// The entry holding `key`, or null.
        pub fn find(self: *const Memtable, key: *const Key) ?u32 {
            const mask = self.slots.len - 1;
            var slot = self.slot_first(key);
            var probes: usize = 0;
            // Bounded: at most half the slots are used, so an empty slot comes first.
            while (probes < self.slots.len) : (probes += 1) {
                const entry = self.slots[slot];
                if (entry == 0) return null;
                if (std.mem.eql(u8, &self.keys[entry - 1], key)) return entry - 1;
                slot = (slot + 1) & mask;
            }
            unreachable; // The index is never full.
        }

        /// Writes `key` (a delete when `value_bytes` is null). Fixed mode: exactly
        /// `value_size_max` bytes; variable mode: 1..`value_size_max`. `error.Busy` when the
        /// memtable is full and the key is new.
        pub fn put(self: *Memtable, key: *const Key, value_bytes: ?[]const u8) error{Busy}!void {
            if (value_bytes) |bytes| {
                assert(bytes.len > 0 and bytes.len <= value_size_max);
                assert(variable or bytes.len == value_size_max);
            }
            const mask = self.slots.len - 1;
            var slot = self.slot_first(key);
            var probes: usize = 0;
            const entry: u32 = while (probes < self.slots.len) : (probes += 1) {
                const existing = self.slots[slot];
                if (existing == 0) {
                    if (self.count == self.capacity()) return error.Busy;
                    self.keys[self.count] = key.*;
                    self.tombstones[self.count] = true; // No value yet: counts 0 bytes below.
                    self.count += 1;
                    self.slots[slot] = self.count;
                    break self.count - 1;
                }
                if (std.mem.eql(u8, &self.keys[existing - 1], key)) break existing - 1;
                slot = (slot + 1) & mask;
            } else unreachable; // The index is never full.
            self.value_bytes_total -= self.value(entry).len;
            self.tombstones[entry] = value_bytes == null;
            const length: usize = if (value_bytes) |bytes| bytes.len else 0;
            if (value_bytes) |bytes| @memcpy(self.values[entry][0..length], bytes);
            // Zeroed past the value: checkpoint bytes and lookups never see stale bytes.
            @memset(self.values[entry][length..], 0);
            if (variable) self.lengths[entry] = @intCast(length);
            self.value_bytes_total += length;
            self.sorted = false;
            assert(self.count <= self.capacity());
        }

        /// Fills `order` with the entries in key order.
        pub fn sort(self: *Memtable) void {
            assert(self.count <= self.capacity());
            const order = self.order[0..self.count];
            for (order, 0..) |*index, position| index.* = @intCast(position);
            std.mem.sortUnstable(u32, order, self, less);
            self.sorted = true;
        }

        fn less(self: *Memtable, a: u32, b: u32) bool {
            return std.mem.order(u8, &self.keys[a], &self.keys[b]) == .lt;
        }
    };
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "lsm memtable: overwrite in place, deletes, Busy when full, sorted order" {
    const Memtable = MemtableType(32, 8, false);
    var memtable = try Memtable.init(testing.allocator, 64);
    defer memtable.deinit(testing.allocator);
    var model = std.AutoHashMap([32]u8, ?u64).init(testing.allocator);
    defer model.deinit();
    var prng = Prng.init(3);
    var keys: [80][32]u8 = undefined;
    for (&keys) |*key| prng.fill(key);
    for (0..2000) |_| {
        const key = &keys[prng.below(keys.len)];
        const value: u64 = prng.int(u64);
        const delete = prng.chance(1, 4);
        const bytes = std.mem.toBytes(value);
        const result = memtable.put(key, if (delete) null else @as([]const u8, &bytes));
        if (result) |_| {
            try model.put(key.*, if (delete) null else value);
        } else |err| {
            try testing.expectEqual(error.Busy, err);
            try testing.expect(!model.contains(key.*));
            try testing.expectEqual(@as(u32, 64), memtable.count);
        }
    }
    try testing.expectEqual(model.count(), memtable.count);
    var iterator = model.iterator();
    while (iterator.next()) |item| {
        const entry = memtable.find(item.key_ptr).?;
        const expected = item.value_ptr.*;
        try testing.expectEqual(expected == null, memtable.tombstones[entry]);
        if (expected) |value| {
            try testing.expectEqual(value, std.mem.readInt(u64, &memtable.values[entry], .little));
        }
    }
    memtable.sort();
    for (1..memtable.count) |position| {
        const a = &memtable.keys[memtable.order[position - 1]];
        const b = &memtable.keys[memtable.order[position]];
        try testing.expect(std.mem.order(u8, a, b) == .lt);
    }
    memtable.reset();
    try testing.expect(memtable.find(&keys[0]) == null);
}
