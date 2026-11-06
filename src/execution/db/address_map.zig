//! Hash map context for 20-byte account addresses.
//!
//! Same Wyhash as `std.AutoHashMap` (so the same distribution for attacker-chosen
//! addresses), but equality compares the address as one `u160` instead of byte by byte,
//! which `std.meta.eql` does for arrays. Account maps sit on every cold account load.

const std = @import("std");
const assert = std.debug.assert;

pub const Address = [20]u8;

comptime {
    assert(@sizeOf(Address) == 20);
    assert(@bitSizeOf(u160) == @bitSizeOf(Address));
}

pub const Context = struct {
    pub fn hash(_: Context, address: Address) u64 {
        return std.hash.Wyhash.hash(0, &address);
    }

    pub fn eql(_: Context, a: Address, b: Address) bool {
        return @as(u160, @bitCast(a)) == @as(u160, @bitCast(b));
    }
};

/// An unmanaged hash map keyed by address, with the default load factor.
pub fn Map(comptime V: type) type {
    return std.HashMapUnmanaged(Address, V, Context, std.hash_map.default_max_load_percentage);
}

test "address map: context matches the auto context" {
    var prng = std.Random.DefaultPrng.init(0x20);
    const auto_hash = std.hash_map.getAutoHashFn(Address, void);
    for (0..256) |_| {
        var a: Address = undefined;
        prng.random().bytes(&a);
        var b = a;
        const context: Context = .{};
        try std.testing.expectEqual(auto_hash({}, a), context.hash(a));
        try std.testing.expect(context.eql(a, b));
        b[prng.random().uintLessThan(usize, 20)] ^= 1;
        try std.testing.expect(!context.eql(a, b));
    }
}

test "address map: put, get and remove" {
    var map: Map(u32) = .empty;
    defer map.deinit(std.testing.allocator);
    var a: Address = @splat(0);
    for (0..64) |i| {
        a[19] = @intCast(i);
        try map.put(std.testing.allocator, a, @intCast(i));
    }
    a[19] = 7;
    try std.testing.expectEqual(@as(?u32, 7), map.get(a));
    try std.testing.expect(map.remove(a));
    try std.testing.expectEqual(@as(?u32, null), map.get(a));
    try std.testing.expectEqual(@as(u32, 63), map.count());
}
