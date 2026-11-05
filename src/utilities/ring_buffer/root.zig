//! A bounded ring buffer of `(position, value)` entries with ordered lookups.
//!
//! Mirrors base/base `RingBuffer`: storage is fixed at comptime, pushing at capacity evicts
//! the oldest entry, and positions must be non-decreasing so `entries_after` can binary
//! search (asserted here, not just documented). Used for flashblock/payload history where
//! subscribers ask for "everything after position N".

const std = @import("std");
const assert = std.debug.assert;

pub fn RingBuffer(comptime Position: type, comptime Value: type, comptime capacity: u32) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();

        positions: [capacity]Position = undefined,
        values: [capacity]Value = undefined,
        /// Index of the oldest entry.
        head: u32 = 0,
        count: u32 = 0,

        pub const Entry = struct { position: Position, value: *const Value };

        pub fn push(ring: *Self, position: Position, value: Value) void {
            if (ring.count > 0) assert(position >= ring.position_at(ring.count - 1));
            if (ring.count == capacity) {
                ring.head = (ring.head + 1) % capacity;
                ring.count -= 1;
            }
            const slot = (ring.head + ring.count) % capacity;
            ring.positions[slot] = position;
            ring.values[slot] = value;
            ring.count += 1;
            assert(ring.count <= capacity);
        }

        pub fn len(ring: *const Self) u32 {
            return ring.count;
        }

        pub fn oldest_position(ring: *const Self) ?Position {
            return if (ring.count == 0) null else ring.position_at(0);
        }

        pub fn newest_position(ring: *const Self) ?Position {
            return if (ring.count == 0) null else ring.position_at(ring.count - 1);
        }

        /// The `index`-th oldest entry.
        pub fn get(ring: *const Self, index: u32) Entry {
            assert(index < ring.count);
            const slot = (ring.head + index) % capacity;
            return .{ .position = ring.positions[slot], .value = &ring.values[slot] };
        }

        pub fn clear(ring: *Self) void {
            ring.head = 0;
            ring.count = 0;
        }

        /// Index of the first entry with position strictly greater than `cutoff`; iterate
        /// with `get(i)` for `i` in `[first_after(cutoff), len())`. O(log n).
        pub fn first_after(ring: *const Self, cutoff: Position) u32 {
            var low: u32 = 0;
            var high: u32 = ring.count;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (ring.position_at(middle) <= cutoff) low = middle + 1 else high = middle;
            }
            assert(low == ring.count or ring.position_at(low) > cutoff);
            assert(low == 0 or ring.position_at(low - 1) <= cutoff);
            return low;
        }

        fn position_at(ring: *const Self, index: u32) Position {
            return ring.positions[(ring.head + index) % capacity];
        }
    };
}

test "ring_buffer: eviction and lookups" {
    var ring: RingBuffer(u64, u32, 3) = .{};
    try std.testing.expectEqual(@as(?u64, null), ring.oldest_position());
    try std.testing.expectEqual(@as(u32, 0), ring.first_after(5));
    ring.push(1, 10);
    ring.push(2, 20);
    ring.push(2, 21);
    ring.push(4, 40); // Evicts position 1.
    try std.testing.expectEqual(@as(u32, 3), ring.len());
    try std.testing.expectEqual(@as(?u64, 2), ring.oldest_position());
    try std.testing.expectEqual(@as(?u64, 4), ring.newest_position());
    try std.testing.expectEqual(@as(u32, 0), ring.first_after(1));
    try std.testing.expectEqual(@as(u32, 2), ring.first_after(2));
    try std.testing.expectEqual(@as(u32, 2), ring.first_after(3));
    try std.testing.expectEqual(@as(u32, 3), ring.first_after(4));
    try std.testing.expectEqual(@as(u32, 40), ring.get(2).value.*);
    ring.clear();
    try std.testing.expectEqual(@as(u32, 0), ring.len());
}

test "ring_buffer: seeded fuzz against a model" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x41b6);
    var ring: RingBuffer(u32, u32, 7) = .{};
    var model: [4096]u32 = undefined;
    var model_count: usize = 0;
    var position: u32 = 0;
    for (0..4096) |step| {
        position += @intCast(prng.below(3));
        ring.push(position, @intCast(step));
        model[model_count] = position;
        model_count += 1;
        const live = model[model_count - ring.len() .. model_count];
        try std.testing.expectEqual(@as(usize, @min(model_count, 7)), live.len);
        const cutoff: u32 = @intCast(prng.range(live[0] -| 2, position + 2));
        var expected: u32 = 0;
        while (expected < live.len and live[expected] <= cutoff) expected += 1;
        try std.testing.expectEqual(expected, ring.first_after(cutoff));
    }
}
