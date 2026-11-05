//! Identify peerstore (base/base gossip driver `peerstore`, `max_identify_peerstore_peers`
//! = 1024): what each peer last told us over identify, kept after it disconnects so the
//! admin RPC can still describe it. Fixed capacity; when full, a new peer evicts the least
//! recently updated disconnected peer, or the least recently updated peer when every entry
//! is connected (base/base `peerstore_eviction_candidate`).
//!
//! Lookups scan linearly: identify and disconnect events are rare and the scan is bounded
//! by the capacity.

const std = @import("std");
const assert = std.debug.assert;
const peer_id = @import("peer_id.zig");

pub const capacity_default = 1024;

pub fn Peerstore(comptime Info: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct {
            used: bool = false,
            connected: bool = false,
            /// Update sequence number: larger is more recent.
            touched: u64 = 0,
            peer: peer_id.PeerId = undefined,
            info: Info = undefined,
        };

        entries: []Entry,
        count: u32 = 0,
        sequence: u64 = 0,
        evictions: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, capacity: u32) !Self {
            assert(capacity > 0);
            const entries = try allocator.alloc(Entry, capacity);
            @memset(entries, .{});
            return .{ .entries = entries };
        }

        pub fn deinit(store: *Self, allocator: std.mem.Allocator) void {
            allocator.free(store.entries);
            store.* = undefined;
        }

        pub fn get(store: *const Self, peer: peer_id.PeerId) ?*const Entry {
            const index = store.find(peer) orelse return null;
            return &store.entries[index];
        }

        /// Stores the identify info of a connected peer, replacing what it said before.
        pub fn put(store: *Self, peer: peer_id.PeerId, info: *const Info) void {
            const index = store.find(peer) orelse store.free_or_evict();
            const entry = &store.entries[index];
            if (!entry.used) store.count += 1;
            store.sequence += 1;
            entry.* = .{
                .used = true,
                .connected = true,
                .touched = store.sequence,
                .peer = peer,
                .info = info.*,
            };
            assert(store.count <= store.entries.len);
            assert(store.get(peer) != null);
        }

        /// Marks a known peer connected or not; unknown peers are ignored.
        pub fn set_connected(store: *Self, peer: peer_id.PeerId, connected: bool) void {
            const index = store.find(peer) orelse return;
            store.entries[index].connected = connected;
            assert(store.entries[index].used);
        }

        fn find(store: *const Self, peer: peer_id.PeerId) ?u32 {
            for (store.entries, 0..) |*entry, index| {
                if (entry.used and entry.peer.eql(&peer)) return @intCast(index);
            }
            return null;
        }

        fn free_or_evict(store: *Self) u32 {
            var oldest_disconnected: ?u32 = null;
            var oldest: u32 = 0;
            for (store.entries, 0..) |*entry, index_usize| {
                const index: u32 = @intCast(index_usize);
                if (!entry.used) return index;
                if (entry.touched < store.entries[oldest].touched) oldest = index;
                if (entry.connected) continue;
                const best = oldest_disconnected orelse index;
                if (entry.touched <= store.entries[best].touched) oldest_disconnected = index;
            }
            assert(store.count == store.entries.len);
            const victim = oldest_disconnected orelse oldest;
            store.entries[victim] = .{};
            store.count -= 1;
            store.evictions += 1;
            return victim;
        }
    };
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

fn test_peer(value: u8) peer_id.PeerId {
    var key: [33]u8 = @splat(value);
    key[0] = 0x02;
    return peer_id.from_public_key(key);
}

test "peerstore: put, replace, evicts the oldest disconnected peer first" {
    var store = try Peerstore(u32).init(testing.allocator, 3);
    defer store.deinit(testing.allocator);
    store.put(test_peer(1), &10);
    store.put(test_peer(2), &20);
    store.put(test_peer(3), &30);
    store.put(test_peer(1), &11); // Replace: still three entries, 1 is now the newest.
    try testing.expectEqual(@as(u32, 3), store.count);
    try testing.expectEqual(@as(u32, 11), store.get(test_peer(1)).?.info);
    store.set_connected(test_peer(3), false);
    store.set_connected(test_peer(9), false); // Unknown: ignored.
    store.put(test_peer(4), &40);
    // Peer 2 is older, but connected: the disconnected peer 3 goes.
    try testing.expect(store.get(test_peer(3)) == null);
    try testing.expect(store.get(test_peer(2)) != null);
    // All connected now: the least recently updated (2) goes.
    store.put(test_peer(5), &50);
    try testing.expect(store.get(test_peer(2)) == null);
    try testing.expectEqual(@as(u64, 2), store.evictions);
}

test "peerstore: seeded fuzz against a reference model" {
    var prng = Prng.init(0x9ee5);
    const random = prng.random();
    const capacity = 8;
    var store = try Peerstore(u32).init(testing.allocator, capacity);
    defer store.deinit(testing.allocator);
    // Reference: per peer value, connected flag and touch order (0 = absent).
    var touched: [32]u64 = @splat(0);
    var connected: [32]bool = @splat(false);
    var values: [32]u32 = @splat(0);
    var clock: u64 = 0;
    for (0..4000) |_| {
        const peer: u8 = random.uintLessThan(u8, 32);
        if (random.uintLessThan(u8, 3) == 0) {
            const value = !connected[peer];
            store.set_connected(test_peer(peer), value);
            if (touched[peer] != 0) connected[peer] = value;
            continue;
        }
        const value = random.int(u32);
        if (touched[peer] == 0 and count_present(&touched) == capacity) {
            touched[reference_victim(&touched, &connected)] = 0;
        }
        clock += 1;
        touched[peer] = clock;
        connected[peer] = true;
        values[peer] = value;
        store.put(test_peer(peer), &value);
        try testing.expectEqual(count_present(&touched), store.count);
        for (touched, 0..) |time, index| {
            const entry = store.get(test_peer(@intCast(index)));
            try testing.expectEqual(time != 0, entry != null);
            if (entry) |found| try testing.expectEqual(values[index], found.info);
        }
    }
}

fn count_present(touched: []const u64) u32 {
    var count: u32 = 0;
    for (touched) |time| count += @intFromBool(time != 0);
    return count;
}

fn reference_victim(touched: []const u64, connected: []const bool) usize {
    var best: ?usize = null;
    for (touched, 0..) |time, index| {
        if (time == 0 or connected[index]) continue;
        if (best == null or time < touched[best.?]) best = index;
    }
    if (best) |index| return index;
    for (touched, 0..) |time, index| {
        if (time == 0) continue;
        if (best == null or time < touched[best.?]) best = index;
    }
    return best.?;
}

test "peerstore: fuzz bytes drive put and set_connected without breaking bounds" {
    const fuzz = @import("../../../testing/fuzz.zig");
    try fuzz.run_bytes({}, fuzz_operations, .{});
}

fn fuzz_operations(_: void, bytes: []const u8) anyerror!void {
    var store = try Peerstore(u8).init(testing.allocator, 4);
    defer store.deinit(testing.allocator);
    for (bytes) |byte| {
        const peer = test_peer(byte & 0x0f);
        if (byte & 0x80 != 0) {
            store.set_connected(peer, byte & 0x40 != 0);
        } else {
            store.put(peer, &byte);
        }
        try testing.expect(store.count <= 4);
    }
}
