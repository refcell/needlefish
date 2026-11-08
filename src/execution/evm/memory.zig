//! Shared, statically allocated EVM memory for the whole frame stack.
//!
//! Frames are strictly nested, so each child frame's memory starts where its parent's
//! ends (a checkpoint). The buffer never moves, so slices into a parent's memory (the
//! child's calldata) stay valid while the child runs. Growing past capacity is
//! reported as out-of-gas: the configured capacity is far above what any
//! realistic gas limit can pay for.

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const gas = @import("gas.zig");

pub const SharedMemory = struct {
    buffer: []u8,

    pub fn init(allocator: std.mem.Allocator, capacity_bytes: u32) !SharedMemory {
        assert(capacity_bytes % 32 == 0);
        assert(capacity_bytes > 0);
        return .{ .buffer = try lazy.alloc(allocator, u8, capacity_bytes) };
    }

    pub fn deinit(shared: *SharedMemory, allocator: std.mem.Allocator) void {
        lazy.free(allocator, shared.buffer);
        shared.* = undefined;
    }

    pub fn frame(shared: *SharedMemory, base: u32) Memory {
        assert(base <= shared.buffer.len);
        assert(base % 32 == 0);
        return .{ .bytes = shared.buffer[base..], .len = 0 };
    }
};

/// One frame's view: `bytes` is the rest of the shared buffer from the frame's base,
/// `len` is the active size (a multiple of 32), always zero-filled beyond writes.
pub const Memory = struct {
    bytes: []u8,
    len: u32,

    /// Grow to cover `[offset, offset + size)`. Returns the gas to charge, or null if
    /// the range cannot be paid for or exceeds capacity. `size` must be non-zero.
    pub fn expansion_cost(memory: *const Memory, offset: u64, size: u64) ?u64 {
        assert(size > 0);
        assert(memory.len % 32 == 0);
        const end = std.math.add(u64, offset, size) catch return null;
        if (end <= memory.len) return 0;
        if (end > memory.bytes.len) return null;
        const words_new = gas.words_for(end);
        const words_old: u64 = memory.len / 32;
        return gas.memory_cost(words_new) - gas.memory_cost(words_old);
    }

    /// Commit a growth previously priced by `expansion_cost`.
    pub fn grow(memory: *Memory, end: u64) void {
        assert(end <= memory.bytes.len);
        if (end <= memory.len) return;
        const len_new: u32 = @intCast(gas.words_for(end) * 32);
        assert(len_new <= memory.bytes.len);
        @memset(memory.bytes[memory.len..len_new], 0);
        memory.len = len_new;
    }

    pub inline fn slice(memory: *const Memory, offset: u64, size: u64) []u8 {
        assert(offset + size <= memory.len);
        const start: usize = @intCast(offset);
        return memory.bytes[start..][0..@intCast(size)];
    }

    pub inline fn word(memory: *const Memory, offset: u64) *[32]u8 {
        assert(offset + 32 <= memory.len);
        return memory.bytes[@intCast(offset)..][0..32];
    }
};

/// Copy `source[offset..offset+destination.len]` into `destination`, zero-filling
/// past the end of `source` (CALLDATACOPY, CODECOPY, EXTCODECOPY semantics).
pub fn copy_padded(destination: []u8, source: []const u8, offset: u256) void {
    if (offset >= source.len) {
        @memset(destination, 0);
        return;
    }
    const start: usize = @intCast(offset);
    const available = source.len - start;
    const count = @min(available, destination.len);
    @memcpy(destination[0..count], source[start..][0..count]);
    @memset(destination[count..], 0);
    assert(count <= destination.len);
}

test "memory: expansion cost and growth" {
    var shared = try SharedMemory.init(std.testing.allocator, 4096);
    defer shared.deinit(std.testing.allocator);
    var memory = shared.frame(0);
    try std.testing.expectEqual(@as(?u64, 3), memory.expansion_cost(0, 1));
    memory.grow(1);
    try std.testing.expectEqual(@as(u32, 32), memory.len);
    try std.testing.expectEqual(@as(u8, 0), memory.slice(0, 32)[31]);
    try std.testing.expectEqual(@as(?u64, 0), memory.expansion_cost(0, 32));
    try std.testing.expectEqual(@as(?u64, 3), memory.expansion_cost(32, 32));
    try std.testing.expectEqual(@as(?u64, null), memory.expansion_cost(4096, 1));
    try std.testing.expectEqual(@as(?u64, null), memory.expansion_cost(std.math.maxInt(u64), 2));
}

test "memory: child frames start at parent end and re-zero" {
    var shared = try SharedMemory.init(std.testing.allocator, 4096);
    defer shared.deinit(std.testing.allocator);
    var child = shared.frame(64);
    child.grow(32);
    child.word(0).* = @splat(0xff);
    var again = shared.frame(64);
    again.grow(32);
    try std.testing.expectEqual(@as(u8, 0), again.word(0)[0]);
}

test "memory: copy_padded" {
    var out: [4]u8 = undefined;
    copy_padded(&out, "abc", 1);
    try std.testing.expectEqualSlices(u8, &.{ 'b', 'c', 0, 0 }, &out);
    copy_padded(&out, "abc", 1 << 200);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &out);
}
