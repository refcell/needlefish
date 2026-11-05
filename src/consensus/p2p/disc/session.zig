//! discv5 session cache (devp2p `discv5-theory.md`, "Session Cache"): established
//! AES-GCM keys keyed by `(node id, UDP endpoint)`, so a node that changes endpoint must
//! handshake again. Fixed capacity with least-recently-used eviction.
//!
//! Nonces are `counter (32 bits) || random (64 bits)`, as the spec recommends, so a
//! session never reuses a nonce for its first 2^32 messages; the session is retired
//! before the counter wraps.

const std = @import("std");
const assert = std.debug.assert;
const packet = @import("packet.zig");
const table = @import("table.zig");

pub const Session = struct {
    node_id: packet.NodeId,
    endpoint: table.Endpoint,
    write_key: packet.Key,
    read_key: packet.Key,
    nonce_counter: u32,
    last_used_ns: u64,
};

pub const Cache = struct {
    sessions: []Session,
    count: u32,

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !Cache {
        assert(capacity > 0);
        const sessions = try allocator.alloc(Session, capacity);
        return .{ .sessions = sessions, .count = 0 };
    }

    pub fn deinit(cache: *Cache, allocator: std.mem.Allocator) void {
        allocator.free(cache.sessions);
        cache.* = undefined;
    }

    pub fn get(cache: *Cache, node_id: packet.NodeId, endpoint: table.Endpoint) ?*Session {
        assert(cache.count <= cache.sessions.len);
        for (cache.sessions[0..cache.count]) |*session| {
            if (!std.mem.eql(u8, &session.node_id, &node_id)) continue;
            if (!session.endpoint.eql(endpoint)) continue;
            return session;
        }
        return null;
    }

    /// Installs keys for `(node_id, endpoint)`, replacing an existing session or evicting
    /// the least recently used one.
    pub fn put(
        cache: *Cache,
        node_id: packet.NodeId,
        endpoint: table.Endpoint,
        write_key: packet.Key,
        read_key: packet.Key,
        now_ns: u64,
    ) *Session {
        const slot = cache.get(node_id, endpoint) orelse cache.claim();
        slot.* = .{
            .node_id = node_id,
            .endpoint = endpoint,
            .write_key = write_key,
            .read_key = read_key,
            .nonce_counter = 0,
            .last_used_ns = now_ns,
        };
        assert(cache.get(node_id, endpoint) == slot);
        return slot;
    }

    fn claim(cache: *Cache) *Session {
        if (cache.count < cache.sessions.len) {
            cache.count += 1;
            return &cache.sessions[cache.count - 1];
        }
        var oldest = &cache.sessions[0];
        for (cache.sessions[1..]) |*session| {
            if (session.last_used_ns < oldest.last_used_ns) oldest = session;
        }
        assert(cache.count == cache.sessions.len);
        return oldest;
    }

    pub fn remove(cache: *Cache, session: *Session) void {
        const index = (@intFromPtr(session) - @intFromPtr(cache.sessions.ptr)) / @sizeOf(Session);
        assert(index < cache.count);
        cache.sessions[index] = cache.sessions[cache.count - 1];
        cache.count -= 1;
    }
};

/// Next message nonce for `session`, or null when the counter is exhausted (the caller
/// drops the session and handshakes again).
pub fn next_nonce(session: *Session, random: std.Random, now_ns: u64) ?packet.Nonce {
    if (session.nonce_counter == std.math.maxInt(u32)) return null;
    var nonce: packet.Nonce = undefined;
    std.mem.writeInt(u32, nonce[0..4], session.nonce_counter, .big);
    random.bytes(nonce[4..]);
    session.nonce_counter += 1;
    session.last_used_ns = now_ns;
    assert(session.nonce_counter > 0);
    return nonce;
}

const Prng = @import("../../../testing/prng.zig").Prng;

test "session: put, get by endpoint, LRU eviction" {
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit(std.testing.allocator);
    const a: table.Endpoint = .{ .address = .{ .ip4 = .{ 1, 1, 1, 1 } }, .port = 1 };
    const b: table.Endpoint = .{ .address = .{ .ip4 = .{ 2, 2, 2, 2 } }, .port = 1 };
    const id_one: packet.NodeId = @splat(1);
    const id_two: packet.NodeId = @splat(2);
    const id_three: packet.NodeId = @splat(3);
    _ = cache.put(id_one, a, @splat(1), @splat(2), 10);
    _ = cache.put(id_two, a, @splat(3), @splat(4), 20);
    try std.testing.expect(cache.get(id_one, b) == null);
    try std.testing.expect(cache.get(id_one, a) != null);
    _ = cache.put(id_three, b, @splat(5), @splat(6), 30);
    try std.testing.expect(cache.get(id_one, a) == null);
    try std.testing.expect(cache.get(id_two, a) != null);
    cache.remove(cache.get(id_two, a).?);
    try std.testing.expectEqual(@as(u32, 1), cache.count);
}

test "session: nonces are unique and counter-prefixed" {
    var prng = Prng.init(1);
    var session: Session = .{
        .node_id = @splat(0),
        .endpoint = .{ .address = .{ .ip4 = @splat(0) }, .port = 0 },
        .write_key = @splat(0),
        .read_key = @splat(0),
        .nonce_counter = 0,
        .last_used_ns = 0,
    };
    const first = next_nonce(&session, prng.random(), 1).?;
    const second = next_nonce(&session, prng.random(), 2).?;
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, first[0..4], .big));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, second[0..4], .big));
    session.nonce_counter = std.math.maxInt(u32);
    try std.testing.expect(next_nonce(&session, prng.random(), 3) == null);
}
