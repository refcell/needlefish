//! Memo of the trie key hashes a `SparseState` computes: keccak256 of 32-byte big-endian
//! storage slots and of 20-byte addresses.
//!
//! A cold evm storage read hashes its address and slot; committing the block
//! (`SparseState.apply_evm`) hashes every dirty key again, twice: once to read the old value
//! and once to write the trie. The memo makes the later hashes table lookups.
//!
//! Direct-mapped and fixed-size: one probe, a colliding key overwrites, no allocation after
//! `init`. Entries are tagged with a generation, so `clear` is O(1). keccak256 is a pure
//! function, so a hit is bit-identical to hashing (keys are compared in full).

const std = @import("std");
const assert = std.debug.assert;

const lazy = @import("../../utilities/lazy_alloc/root.zig");
const trie = @import("../trie/root.zig");

const node = trie.node;
const sparse = trie.sparse;

pub const Hash = [32]u8;
pub const Address = [20]u8;

pub const slots_count_default = 1 << 13;
pub const addresses_count_default = 1 << 11;
/// Keys hashed per `keccak256_many` call by `prefetch_slots`.
const batch_max = 64;

fn Table(comptime key_bytes: comptime_int) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: [key_bytes]u8, hash: Hash, generation: u32 };

        entries: []Entry,
        /// log2 of `entries.len`.
        shift: u6,

        fn init(allocator: std.mem.Allocator, count: u32) !Self {
            assert(count >= 2 and std.math.isPowerOfTwo(count));
            const entries = try lazy.alloc(allocator, Entry, count);
            // Generation 0 is never current: every entry starts empty.
            for (entries) |*entry| entry.generation = 0;
            const bits: u6 = @intCast(std.math.log2_int(u32, count));
            assert(bits >= 1 and bits < 64);
            return .{ .entries = entries, .shift = @intCast(64 - @as(u7, bits)) };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            lazy.free(allocator, self.entries);
            self.* = undefined;
        }

        fn slot_of(self: *const Self, key: *const [key_bytes]u8) *Entry {
            const head = std.mem.readInt(u64, key[0..8], .little);
            const tail = std.mem.readInt(u64, key[key_bytes - 8 ..][0..8], .little);
            const mixed = (head ^ std.math.rotl(u64, tail, 29)) *% 0x9e3779b97f4a7c15;
            const index: usize = @intCast(mixed >> self.shift);
            assert(index < self.entries.len);
            return &self.entries[index];
        }

        fn get(self: *const Self, key: *const [key_bytes]u8, generation: u32) ?Hash {
            assert(generation != 0);
            const entry = self.slot_of(key);
            if (entry.generation != generation) return null;
            if (!std.mem.eql(u8, &entry.key, key)) return null;
            return entry.hash;
        }

        fn put(self: *Self, key: *const [key_bytes]u8, hash: *const Hash, generation: u32) void {
            assert(generation != 0);
            const entry = self.slot_of(key);
            entry.* = .{ .key = key.*, .hash = hash.*, .generation = generation };
        }

        fn wipe(self: *Self) void {
            for (self.entries) |*entry| entry.generation = 0;
        }
    };
}

pub const KeyMemo = struct {
    pub const Config = struct {
        slots_count: u32 = slots_count_default,
        addresses_count: u32 = addresses_count_default,
    };

    slots: Table(32),
    addresses: Table(20),
    generation: u32 = 1,
    /// Off: every call hashes (the differential tests' reference).
    enabled: bool = true,

    pub fn init(allocator: std.mem.Allocator, config: Config) !KeyMemo {
        var slots = try Table(32).init(allocator, config.slots_count);
        errdefer slots.deinit(allocator);
        const addresses = try Table(20).init(allocator, config.addresses_count);
        return .{ .slots = slots, .addresses = addresses };
    }

    pub fn deinit(self: *KeyMemo, allocator: std.mem.Allocator) void {
        self.addresses.deinit(allocator);
        self.slots.deinit(allocator);
        self.* = undefined;
    }

    /// Forgets every entry (O(1) except once per 2^32 clears).
    pub fn clear(self: *KeyMemo) void {
        self.generation +%= 1;
        if (self.generation == 0) {
            self.slots.wipe();
            self.addresses.wipe();
            self.generation = 1;
        }
        assert(self.generation != 0);
    }

    /// keccak256 of `slot` as 32 big-endian bytes.
    pub fn slot_hash(self: *KeyMemo, slot: u256) Hash {
        var key: [32]u8 = undefined;
        std.mem.writeInt(u256, &key, slot, .big);
        if (!self.enabled) return node.keccak256(&key);
        if (self.slots.get(&key, self.generation)) |hash| return hash;
        const hash = node.keccak256(&key);
        self.slots.put(&key, &hash, self.generation);
        return hash;
    }

    pub fn address_hash(self: *KeyMemo, address: *const Address) Hash {
        if (!self.enabled) return node.keccak256(address);
        if (self.addresses.get(address, self.generation)) |hash| return hash;
        const hash = node.keccak256(address);
        self.addresses.put(address, &hash, self.generation);
        return hash;
    }

    /// The memoized hash of a 32-byte big-endian slot key, or null (never hashes).
    pub fn slot_key_cached(self: *const KeyMemo, key: *const [32]u8) ?Hash {
        if (!self.enabled) return null;
        return self.slots.get(key, self.generation);
    }

    pub fn put_slot_key(self: *KeyMemo, key: *const [32]u8, hash: *const Hash) void {
        if (self.enabled) self.slots.put(key, hash, self.generation);
    }

    pub fn address_cached(self: *const KeyMemo, address: *const Address) ?Hash {
        if (!self.enabled) return null;
        return self.addresses.get(address, self.generation);
    }

    pub fn put_address(self: *KeyMemo, address: *const Address, hash: *const Hash) void {
        if (self.enabled) self.addresses.put(address, hash, self.generation);
    }

    /// Hashes the slots of `slots` not memoized yet, `batch_max` keys per batched keccak.
    pub fn prefetch_slots(self: *KeyMemo, slots: []const u256) void {
        if (!self.enabled) return;
        var keys: [batch_max][32]u8 = undefined;
        var inputs: [batch_max][]const u8 = undefined;
        var hashes: [batch_max]Hash = undefined;
        var misses: usize = 0;
        for (slots, 0..) |slot, index| {
            std.mem.writeInt(u256, &keys[misses], slot, .big);
            if (self.slots.get(&keys[misses], self.generation) == null) {
                inputs[misses] = &keys[misses];
                misses += 1;
            }
            if (misses == batch_max or (index + 1 == slots.len and misses > 0)) {
                sparse.keccak256_many(inputs[0..misses], hashes[0..misses]);
                for (keys[0..misses], hashes[0..misses]) |*key, *hash| {
                    self.slots.put(key, hash, self.generation);
                }
                misses = 0;
            }
        }
        assert(misses == 0);
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "KeyMemo: hits equal keccak256, collisions overwrite, clear forgets" {
    var memo = try KeyMemo.init(testing.allocator, .{ .slots_count = 4, .addresses_count = 2 });
    defer memo.deinit(testing.allocator);
    var prng = Prng.init(11);
    for (0..200) |_| {
        const slot: u256 = if (prng.below(2) == 0) prng.below(16) else prng.int(u256);
        var key: [32]u8 = undefined;
        std.mem.writeInt(u256, &key, slot, .big);
        try testing.expectEqual(node.keccak256(&key), memo.slot_hash(slot));
        var address: Address = undefined;
        prng.fill(&address);
        address[0] = @intCast(prng.below(4));
        try testing.expectEqual(node.keccak256(&address), memo.address_hash(&address));
        try testing.expectEqual(node.keccak256(&address), memo.address_cached(&address).?);
        if (prng.below(8) == 0) {
            memo.clear();
            try testing.expect(memo.slot_key_cached(&key) == null);
            try testing.expect(memo.address_cached(&address) == null);
        }
    }
}

test "KeyMemo: prefetch_slots fills the memo; disabled memo stores nothing" {
    var memo = try KeyMemo.init(testing.allocator, .{ .slots_count = 256, .addresses_count = 2 });
    defer memo.deinit(testing.allocator);
    var slots: [150]u256 = undefined;
    for (&slots, 0..) |*slot, index| slot.* = index * 7;
    memo.prefetch_slots(&slots);
    var hits: u32 = 0;
    for (slots) |slot| {
        var key: [32]u8 = undefined;
        std.mem.writeInt(u256, &key, slot, .big);
        if (memo.slot_key_cached(&key)) |hash| {
            hits += 1;
            try testing.expectEqual(node.keccak256(&key), hash);
        }
    }
    try testing.expect(hits > 0);
    memo.enabled = false;
    memo.clear();
    memo.prefetch_slots(&slots);
    const zero: [32]u8 = @splat(0);
    try testing.expectEqual(node.keccak256(&zero), memo.slot_hash(0));
    memo.enabled = true;
    try testing.expect(memo.slot_key_cached(&zero) == null);
}
