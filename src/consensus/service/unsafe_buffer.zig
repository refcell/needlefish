//! Unsafe payload buffer: gossiped blocks that arrive ahead of the unsafe head wait here
//! until their parent is inserted (base/base keeps unsafe payloads in a bounded
//! `UnsafePayloadQueue` ordered by number). Fixed capacity; each slot owns an arena that
//! holds its payload copy. When full, the highest-numbered block is evicted, because the
//! blocks nearest the head unblock progress first.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const task_queue = @import("../engine/task_queue.zig");
const Envelope = @import("../engine/insert_task.zig").Envelope;

pub const PutResult = enum { stored, replaced, evicted_other, dropped, out_of_memory };

const Slot = struct {
    used: bool = false,
    number: u64 = 0,
    arena: std.heap.ArenaAllocator,
    envelope: Envelope = undefined,
};

pub const UnsafeBuffer = struct {
    slots: []Slot,
    count: u32 = 0,
    retain_bytes: usize,

    pub fn init(
        allocator: Allocator,
        capacity: u32,
        retain_bytes: usize,
    ) Allocator.Error!UnsafeBuffer {
        assert(capacity > 0);
        const slots = try allocator.alloc(Slot, capacity);
        for (slots) |*slot| slot.* = .{ .arena = .init(allocator) };
        assert(slots.len == capacity);
        return .{ .slots = slots, .retain_bytes = retain_bytes };
    }

    pub fn deinit(buffer: *UnsafeBuffer, allocator: Allocator) void {
        assert(buffer.count <= buffer.slots.len);
        for (buffer.slots) |*slot| slot.arena.deinit();
        allocator.free(buffer.slots);
        buffer.* = undefined;
    }

    /// Stores a copy of `envelope`. A block with the same number replaces the stored one
    /// (the newest gossip wins). When full, the highest number is evicted if it is above
    /// `envelope`'s; otherwise `envelope` is dropped.
    pub fn put(buffer: *UnsafeBuffer, envelope: *const Envelope) PutResult {
        const number = envelope.payload.block_number;
        var result: PutResult = .stored;
        const index = if (buffer.find(number)) |found| blk: {
            result = .replaced;
            buffer.release(found);
            break :blk found;
        } else buffer.free_slot() orelse blk: {
            const top = buffer.highest().?; // Proof: full, so count > 0.
            if (buffer.slots[top].number < number) return .dropped;
            buffer.release(top);
            result = .evicted_other;
            break :blk top;
        };
        const slot = &buffer.slots[index];
        assert(!slot.used);
        slot.envelope = task_queue.copy_envelope(slot.arena.allocator(), envelope) catch {
            _ = slot.arena.reset(.{ .retain_with_limit = buffer.retain_bytes });
            return .out_of_memory;
        };
        slot.used = true;
        slot.number = number;
        buffer.count += 1;
        assert(buffer.count <= buffer.slots.len);
        return result;
    }

    pub fn find(buffer: *const UnsafeBuffer, number: u64) ?u32 {
        for (buffer.slots, 0..) |*slot, index| {
            if (slot.used and slot.number == number) return @intCast(index);
        }
        return null;
    }

    pub fn get(buffer: *const UnsafeBuffer, index: u32) *const Envelope {
        assert(buffer.slots[index].used);
        return &buffer.slots[index].envelope;
    }

    /// Frees slot `index` (after the queue copied its payload).
    pub fn remove(buffer: *UnsafeBuffer, index: u32) void {
        assert(buffer.slots[index].used);
        buffer.release(index);
    }

    /// Drops every block at or below `number` (already part of the chain).
    pub fn prune_through(buffer: *UnsafeBuffer, number: u64) void {
        for (buffer.slots, 0..) |*slot, index| {
            if (slot.used and slot.number <= number) buffer.release(@intCast(index));
        }
        assert(buffer.lowest() == null or buffer.slots[buffer.lowest().?].number > number);
    }

    pub fn clear(buffer: *UnsafeBuffer) void {
        for (buffer.slots, 0..) |*slot, index| {
            if (slot.used) buffer.release(@intCast(index));
        }
        assert(buffer.count == 0);
    }

    /// The lowest buffered number, if any.
    pub fn lowest_number(buffer: *const UnsafeBuffer) ?u64 {
        const index = buffer.lowest() orelse return null;
        return buffer.slots[index].number;
    }

    fn release(buffer: *UnsafeBuffer, index: u32) void {
        const slot = &buffer.slots[index];
        assert(slot.used);
        assert(buffer.count > 0);
        slot.used = false;
        slot.envelope = undefined;
        _ = slot.arena.reset(.{ .retain_with_limit = buffer.retain_bytes });
        buffer.count -= 1;
    }

    fn free_slot(buffer: *const UnsafeBuffer) ?u32 {
        for (buffer.slots, 0..) |*slot, index| if (!slot.used) return @intCast(index);
        return null;
    }

    fn highest(buffer: *const UnsafeBuffer) ?u32 {
        var best: ?u32 = null;
        for (buffer.slots, 0..) |*slot, index| {
            if (!slot.used) continue;
            if (best == null or slot.number > buffer.slots[best.?].number) best = @intCast(index);
        }
        return best;
    }

    fn lowest(buffer: *const UnsafeBuffer) ?u32 {
        var best: ?u32 = null;
        for (buffer.slots, 0..) |*slot, index| {
            if (!slot.used) continue;
            if (best == null or slot.number < buffer.slots[best.?].number) best = @intCast(index);
        }
        return best;
    }
};

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn envelope_at(number: u64, transactions: []const []const u8) Envelope {
    return .{ .payload = .{
        .parent_hash = .zero,
        .fee_recipient = .zero,
        .state_root = .zero,
        .receipts_root = .zero,
        .logs_bloom = .zero,
        .prev_randao = .zero,
        .block_number = number,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = number * 2,
        .extra_data = "x",
        .base_fee_per_gas = 1,
        .block_hash = .{ .bytes = @splat(@truncate(number)) },
        .transactions = transactions,
    } };
}

test "unsafe buffer: stores copies, replaces, evicts the highest, prunes" {
    var buffer = try UnsafeBuffer.init(testing.allocator, 3, 4096);
    defer buffer.deinit(testing.allocator);
    var bytes = [_]u8{ 1, 2, 3 };
    const transactions = [_][]const u8{&bytes};
    try testing.expectEqual(PutResult.stored, buffer.put(&envelope_at(12, &transactions)));
    bytes[0] = 9; // The buffer holds its own copy.
    const stored = buffer.get(buffer.find(12).?);
    try testing.expectEqual(@as(u8, 1), stored.payload.transactions[0][0]);
    try testing.expectEqual(PutResult.replaced, buffer.put(&envelope_at(12, &transactions)));
    try testing.expectEqual(@as(u8, 9), buffer.get(buffer.find(12).?).payload.transactions[0][0]);
    try testing.expectEqual(PutResult.stored, buffer.put(&envelope_at(14, &.{})));
    try testing.expectEqual(PutResult.stored, buffer.put(&envelope_at(13, &.{})));
    try testing.expectEqual(PutResult.dropped, buffer.put(&envelope_at(20, &.{})));
    try testing.expectEqual(PutResult.evicted_other, buffer.put(&envelope_at(11, &.{})));
    try testing.expect(buffer.find(14) == null);
    try testing.expectEqual(@as(?u64, 11), buffer.lowest_number());
    buffer.prune_through(12);
    try testing.expectEqual(@as(u32, 1), buffer.count);
    try testing.expectEqual(@as(?u64, 13), buffer.lowest_number());
    buffer.remove(buffer.find(13).?);
    try testing.expect(buffer.lowest_number() == null);
}

test "unsafe buffer: seeded fuzz keeps numbers unique and bounded" {
    var prng = Prng.init(0xb0ff);
    var buffer = try UnsafeBuffer.init(testing.allocator, 8, 1024);
    defer buffer.deinit(testing.allocator);
    var floor: u64 = 0;
    for (0..4096) |_| {
        switch (prng.below(4)) {
            0, 1 => _ = buffer.put(&envelope_at(floor + 1 + prng.below(32), &.{})),
            2 => if (buffer.find(floor + 1)) |index| {
                buffer.remove(index);
                floor += 1;
            },
            else => {
                floor += prng.below(3);
                buffer.prune_through(floor);
            },
        }
        try testing.expect(buffer.count <= 8);
        var seen: u32 = 0;
        for (buffer.slots, 0..) |*slot, index| {
            if (!slot.used) continue;
            seen += 1;
            try testing.expectEqual(@as(?u32, @intCast(index)), buffer.find(slot.number));
            try testing.expectEqual(slot.number, slot.envelope.payload.block_number);
        }
        try testing.expectEqual(buffer.count, seen);
    }
}

fn fuzz_buffer(_: void, smith: *std.testing.Smith) anyerror!void {
    var buffer = try UnsafeBuffer.init(testing.allocator, 4, 256);
    defer buffer.deinit(testing.allocator);
    var bytes: [64]u8 = undefined;
    const len = smith.slice(&bytes);
    for (bytes[0..len]) |byte| {
        const number: u64 = byte & 0x3f;
        switch (byte >> 6) {
            0, 1 => _ = buffer.put(&envelope_at(number, &.{})),
            2 => if (buffer.find(number)) |index| buffer.remove(index),
            else => buffer.prune_through(number),
        }
        try testing.expect(buffer.count <= 4);
    }
}

test "unsafe buffer: fuzz" {
    try testing.fuzz({}, fuzz_buffer, .{});
}
