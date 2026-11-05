//! The replay ring: the most recent encoded flashblocks, keyed by position, so a
//! subscriber that reconnects with `?block_number=N&flashblock_index=I` gets everything it
//! missed. Mirrors the `RingBuffer<FlashblockPosition, Utf8Bytes>` in base/base
//! `publisher.rs`, with static memory: `entries_max` slots and one `bytes_max` byte arena
//! allocated at init. Pushing evicts the oldest entries until the new payload fits, so the
//! ring holds at most `entries_max` messages and `bytes_max` bytes.
//!
//! Payloads are stored contiguously in a circular arena. `span_bytes` counts the occupied
//! span from the oldest payload's offset to the write cursor, including the unused tail
//! skipped when a payload wraps to offset 0, so "wrapped" is never inferred from offsets
//! (which coincide for zero-length payloads).

const std = @import("std");
const assert = std.debug.assert;

/// Where a flashblock sits in the chain: ordered by block, then index.
pub const Position = struct {
    block_number: u64,
    flashblock_index: u64,

    pub fn key(position: Position) u128 {
        return (@as(u128, position.block_number) << 64) | position.flashblock_index;
    }

    pub fn less_than(a: Position, b: Position) bool {
        return a.key() < b.key();
    }
};

pub const Entry = struct { position: Position, payload: []const u8 };

const Slot = struct { position: Position, offset: u32, length: u32 };

pub const Ring = struct {
    slots: []Slot,
    arena: []u8,
    /// Index into `slots` of the oldest entry.
    head: u32 = 0,
    count: u32 = 0,
    bytes_used: u64 = 0,
    span_bytes: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, entries_max: u32, bytes_max: u32) !Ring {
        assert(entries_max > 0);
        assert(bytes_max > 0);
        const slots = try allocator.alloc(Slot, entries_max);
        errdefer allocator.free(slots);
        const arena = try allocator.alloc(u8, bytes_max);
        return .{ .slots = slots, .arena = arena };
    }

    pub fn deinit(ring: *Ring, allocator: std.mem.Allocator) void {
        allocator.free(ring.arena);
        allocator.free(ring.slots);
        ring.* = undefined;
    }

    pub fn len(ring: *const Ring) u32 {
        return ring.count;
    }

    pub fn clear(ring: *Ring) void {
        ring.head = 0;
        ring.count = 0;
        ring.bytes_used = 0;
        ring.span_bytes = 0;
    }

    pub fn oldest_position(ring: *const Ring) ?Position {
        return if (ring.count == 0) null else ring.slot(0).position;
    }

    pub fn newest_position(ring: *const Ring) ?Position {
        return if (ring.count == 0) null else ring.slot(ring.count - 1).position;
    }

    /// The `index`-th oldest entry; the payload is valid until the next `push`.
    pub fn get(ring: *const Ring, index: u32) Entry {
        assert(index < ring.count);
        const entry = ring.slot(index);
        assert(entry.offset + entry.length <= ring.arena.len);
        return .{
            .position = entry.position,
            .payload = ring.arena[entry.offset..][0..entry.length],
        };
    }

    /// Copies `payload` in at `position`, evicting the oldest entries as needed. Positions
    /// are non-decreasing; a position older than the newest means the builder restarted
    /// the block (a new payload job), so the stale history is dropped first. Returns how
    /// many entries were evicted (the clear counts).
    pub fn push(ring: *Ring, position: Position, payload: []const u8) u32 {
        assert(payload.len <= ring.arena.len);
        var evicted: u32 = 0;
        if (ring.newest_position()) |newest| {
            if (position.less_than(newest)) {
                evicted = ring.count;
                ring.clear();
            }
        }
        const length: u32 = @intCast(payload.len);
        const offset = ring.reserve(length, &evicted);
        assert(ring.count < ring.slots.len);
        assert(offset + length <= ring.arena.len);
        @memcpy(ring.arena[offset..][0..length], payload);
        const index = (ring.head + ring.count) % @as(u32, @intCast(ring.slots.len));
        ring.slots[index] = .{ .position = position, .offset = offset, .length = length };
        ring.count += 1;
        ring.bytes_used += length;
        assert(ring.bytes_used <= ring.arena.len);
        return evicted;
    }

    /// Index of the first entry strictly after `cutoff`; iterate `get(i)` up to `len()`.
    pub fn first_after(ring: *const Ring, cutoff: Position) u32 {
        var low: u32 = 0;
        var high: u32 = ring.count;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (cutoff.less_than(ring.slot(middle).position)) high = middle else low = middle + 1;
        }
        assert(low == ring.count or cutoff.less_than(ring.slot(low).position));
        assert(low == 0 or !cutoff.less_than(ring.slot(low - 1).position));
        return low;
    }

    fn slot(ring: *const Ring, index: u32) Slot {
        assert(index < ring.count);
        return ring.slots[(ring.head + index) % ring.slots.len];
    }

    fn evict_oldest(ring: *Ring) void {
        assert(ring.count > 0);
        const oldest = ring.slot(0);
        ring.bytes_used -= oldest.length;
        ring.head = (ring.head + 1) % @as(u32, @intCast(ring.slots.len));
        ring.count -= 1;
        if (ring.count == 0) {
            ring.span_bytes = 0;
            return;
        }
        const next = ring.slot(0).offset;
        // A later payload sits at or after the oldest one, unless it wrapped to offset 0.
        const distance = if (next >= oldest.offset)
            next - oldest.offset
        else
            @as(u32, @intCast(ring.arena.len)) - oldest.offset + next;
        assert(distance <= ring.span_bytes);
        ring.span_bytes -= distance;
    }

    /// Finds `length` contiguous free bytes, evicting from the oldest end until they exist,
    /// and advances the span over them. Each iteration either returns or evicts one entry,
    /// so it runs at most `entries_max + 1` times.
    fn reserve(ring: *Ring, length: u32, evicted: *u32) u32 {
        const arena_bytes: u32 = @intCast(ring.arena.len);
        for (0..ring.slots.len + 1) |_| {
            if (ring.count == ring.slots.len) {
                ring.evict_oldest();
                evicted.* += 1;
                continue;
            }
            if (ring.count == 0) {
                ring.span_bytes = length;
                return 0;
            }
            const begin = ring.slot(0).offset;
            assert(ring.span_bytes <= arena_bytes);
            if (begin + ring.span_bytes <= arena_bytes) {
                // Not wrapped: free space is [tail, arena_bytes) and [0, begin).
                const tail = begin + ring.span_bytes;
                if (arena_bytes - tail >= length) {
                    ring.span_bytes += length;
                    return tail;
                }
                if (begin >= length) {
                    ring.span_bytes += arena_bytes - tail + length;
                    return 0;
                }
            } else {
                // Wrapped: free space is [tail, begin).
                const tail = begin + ring.span_bytes - arena_bytes;
                assert(tail <= begin);
                if (begin - tail >= length) {
                    ring.span_bytes += length;
                    return tail;
                }
            }
            ring.evict_oldest();
            evicted.* += 1;
        }
        unreachable; // After evicting every entry, `count == 0` returns offset 0.
    }
};

test {
    _ = @import("ring_test.zig");
}
