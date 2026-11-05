//! Gossipsub message cache (`mcache`): the last `history_length` heartbeat windows of
//! messages, of which the newest `history_gossip` are advertised in IHAVE. Payloads live
//! in a byte ring arena allocated once at init. Messages enter in time order and leave
//! in time order, so the arena is a FIFO: allocation appends at the tail and expiry (or
//! arena pressure) frees from the head. No per-message allocation.

const std = @import("std");
const assert = std.debug.assert;
const seen = @import("seen.zig");

pub const Id = seen.Id;

pub const Config = struct {
    history_length: u8 = 12,
    history_gossip: u8 = 3,
    entries_max: u32 = 1024,
    arena_bytes: u32 = 64 * (1 << 20),
};

pub const Entry = struct {
    id: Id,
    topic: u8,
    window: u64,
    /// Validated messages are forwarded and gossiped; pending ones are only stored.
    validated: bool,
    /// Offset of the payload in the arena; payloads never wrap.
    offset: u32,
    length: u32,
};

pub const Cache = struct {
    config: Config,
    entries: []Entry,
    head: u32 = 0,
    count: u32 = 0,
    arena: []u8,
    /// Arena bytes in use start at `arena_head` and end at `arena_tail` (cyclically).
    arena_head: u32 = 0,
    arena_tail: u32 = 0,
    arena_used: u32 = 0,
    window: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Cache {
        assert(config.history_gossip <= config.history_length);
        assert(config.entries_max > 0 and config.arena_bytes > 0);
        const entries = try allocator.alloc(Entry, config.entries_max);
        errdefer allocator.free(entries);
        const arena = try allocator.alloc(u8, config.arena_bytes);
        return .{ .config = config, .entries = entries, .arena = arena };
    }

    pub fn deinit(cache: *Cache, allocator: std.mem.Allocator) void {
        allocator.free(cache.arena);
        allocator.free(cache.entries);
        cache.* = undefined;
    }

    pub fn at(cache: *const Cache, index: u32) *Entry {
        assert(index < cache.count);
        return &cache.entries[(cache.head + index) % @as(u32, @intCast(cache.entries.len))];
    }

    pub fn data(cache: *const Cache, entry: *const Entry) []const u8 {
        return cache.arena[entry.offset..][0..entry.length];
    }

    pub fn find(cache: *const Cache, id: *const Id) ?*Entry {
        var index: u32 = 0;
        while (index < cache.count) : (index += 1) {
            const entry = cache.at(index);
            if (std.mem.eql(u8, &entry.id, id)) return entry;
        }
        return null;
    }

    /// Stores a copy of `payload`. Evicts the oldest entries if space is needed. Returns
    /// null only when `payload` cannot fit even in an empty arena.
    pub fn put(
        cache: *Cache,
        id: *const Id,
        topic: u8,
        payload: []const u8,
        validated: bool,
    ) ?*Entry {
        if (payload.len > cache.arena.len) return null;
        const length: u32 = @intCast(payload.len);
        var guard: u32 = 0;
        const offset = while (guard <= cache.entries.len) : (guard += 1) {
            if (cache.count < cache.entries.len) {
                if (cache.reserve(length)) |offset| break offset;
            }
            if (cache.count == 0) unreachable; // An empty arena always fits `payload`.
            cache.pop_oldest();
        } else unreachable;
        const slot_index = (cache.head + cache.count) % @as(u32, @intCast(cache.entries.len));
        cache.count += 1;
        const entry = &cache.entries[slot_index];
        entry.* = .{
            .id = id.*,
            .topic = topic,
            .window = cache.window,
            .validated = validated,
            .offset = offset,
            .length = length,
        };
        @memcpy(cache.arena[offset..][0..length], payload);
        assert(cache.arena_used <= cache.arena.len);
        return entry;
    }

    /// Reserves `length` contiguous bytes at the tail; skips the end gap when wrapping.
    fn reserve(cache: *Cache, length: u32) ?u32 {
        const size: u32 = @intCast(cache.arena.len);
        if (cache.arena_used == 0) {
            cache.arena_head = 0;
            cache.arena_tail = 0;
        }
        const tail = cache.arena_tail;
        if (cache.arena_used == 0 or tail > cache.arena_head) {
            if (size - tail >= length) return cache.commit(tail, length, 0);
            // Wrap: the gap at the end counts as used until the head passes it.
            if (cache.arena_head >= length) return cache.commit(0, length, size - tail);
            return null;
        }
        // tail <= head with live data: free space is [tail, head).
        if (cache.arena_head - tail >= length) return cache.commit(tail, length, 0);
        return null;
    }

    fn commit(cache: *Cache, offset: u32, length: u32, gap: u32) u32 {
        cache.arena_tail = offset + length;
        cache.arena_used += length + gap;
        assert(cache.arena_used <= cache.arena.len);
        return offset;
    }

    fn pop_oldest(cache: *Cache) void {
        assert(cache.count > 0);
        const entry = &cache.entries[cache.head];
        cache.head = (cache.head + 1) % @as(u32, @intCast(cache.entries.len));
        cache.count -= 1;
        const size: u32 = @intCast(cache.arena.len);
        // Account for a skipped end gap before this payload.
        const freed = if (entry.offset < cache.arena_head)
            (size - cache.arena_head) + entry.length
        else
            (entry.offset - cache.arena_head) + entry.length;
        cache.arena_used -= freed;
        cache.arena_head = entry.offset + entry.length;
        if (cache.count == 0) assert(cache.arena_used == 0);
    }

    /// Removes a pending entry that failed validation by clearing its id; its bytes are
    /// reclaimed when it reaches the head.
    pub fn forget(cache: *const Cache, entry: *Entry) void {
        assert(cache.count > 0);
        entry.id = @splat(0);
        entry.validated = false;
    }

    /// Advances one heartbeat window and drops windows older than `history_length`.
    pub fn shift(cache: *Cache) void {
        cache.window += 1;
        while (cache.count > 0) {
            const oldest = &cache.entries[cache.head];
            if (cache.window - oldest.window < cache.config.history_length) break;
            cache.pop_oldest();
        }
    }

    /// Writes ids of validated messages for `topic` in the gossip windows.
    pub fn gossip_ids(cache: *const Cache, topic: u8, output: []Id) []Id {
        var found: usize = 0;
        var index: u32 = 0;
        while (index < cache.count and found < output.len) : (index += 1) {
            const entry = cache.at(index);
            if (!entry.validated or entry.topic != topic) continue;
            if (cache.window - entry.window >= cache.config.history_gossip) continue;
            output[found] = entry.id;
            found += 1;
        }
        return output[0..found];
    }
};

const Prng = @import("../../../testing/prng.zig").Prng;

test "mcache: windows, gossip ids, expiry" {
    var cache = try Cache.init(std.testing.allocator, .{
        .history_length = 3,
        .history_gossip = 2,
        .entries_max = 16,
        .arena_bytes = 1024,
    });
    defer cache.deinit(std.testing.allocator);
    var ids: [4]Id = undefined;
    for (&ids, 0..) |*id, index| id.* = @splat(@intCast(index + 1));
    _ = cache.put(&ids[0], 0, "zero", true).?;
    cache.shift();
    _ = cache.put(&ids[1], 0, "one", true).?;
    _ = cache.put(&ids[2], 1, "two", true).?;
    _ = cache.put(&ids[3], 0, "pending", false).?;
    var output: [8]Id = undefined;
    try std.testing.expectEqual(@as(usize, 2), cache.gossip_ids(0, &output).len);
    cache.shift();
    try std.testing.expectEqual(@as(usize, 1), cache.gossip_ids(0, &output).len);
    try std.testing.expectEqualStrings("zero", cache.data(cache.find(&ids[0]).?));
    cache.shift();
    try std.testing.expect(cache.find(&ids[0]) == null);
    try std.testing.expectEqualStrings("one", cache.data(cache.find(&ids[1]).?));
}

test "mcache: arena pressure evicts oldest and payloads stay intact" {
    var cache = try Cache.init(std.testing.allocator, .{ .entries_max = 64, .arena_bytes = 4096 });
    defer cache.deinit(std.testing.allocator);
    var prng = Prng.init(0x6d63);
    var payload: [1500]u8 = undefined;
    for (0..2000) |round| {
        const length: usize = @intCast(prng.range(1, payload.len));
        @memset(payload[0..length], @truncate(round));
        var id: Id = @splat(0);
        std.mem.writeInt(u64, id[0..8], round, .little);
        const entry = cache.put(&id, 0, payload[0..length], true).?;
        try std.testing.expectEqual(@as(u32, @intCast(length)), entry.length);
        var index: u32 = 0;
        var bytes: u64 = 0;
        while (index < cache.count) : (index += 1) {
            const stored = cache.at(index);
            const tag: u8 = @truncate(std.mem.readInt(u64, stored.id[0..8], .little));
            for (cache.data(stored)) |byte| try std.testing.expectEqual(tag, byte);
            bytes += stored.length;
        }
        try std.testing.expect(bytes <= cache.arena_used);
        if (prng.chance(1, 8)) cache.shift();
    }
    try std.testing.expect(cache.put(&@as(Id, @splat(9)), 0, &.{}, true) != null);
}
