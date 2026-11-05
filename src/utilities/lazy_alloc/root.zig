//! Lazily committed allocations for large, statically sized buffers.
//!
//! `std.mem.Allocator.alloc` fills every new allocation with `undefined`, which Debug and
//! ReleaseSafe builds implement as a real 0xAA memset. For buffers sized from configured
//! upper bounds (block stores, scratch arenas, staging areas) that memset makes the whole
//! reservation resident at startup: a ReleaseSafe node measured 766 MiB RSS against 55 MiB
//! in ReleaseFast. These helpers call `rawAlloc`/`rawFree` directly, so the operating
//! system commits pages only when they are first written. Contents are undefined exactly
//! as with `alloc`; only the debug fill is skipped. Free with `free`/`destroy` here, not
//! `allocator.free` (which would touch every page to fill it again).

const std = @import("std");
const assert = std.debug.assert;

/// Allocations below this size are not worth the special case.
pub const lazy_bytes_min = 64 * 1024;

pub fn alloc(allocator: std.mem.Allocator, comptime T: type, count: usize) error{OutOfMemory}![]T {
    const size_bytes = std.math.mul(usize, @sizeOf(T), count) catch return error.OutOfMemory;
    if (size_bytes < lazy_bytes_min) return allocator.alloc(T, count);
    const alignment: std.mem.Alignment = .of(T);
    const bytes = allocator.rawAlloc(size_bytes, alignment, @returnAddress()) orelse
        return error.OutOfMemory;
    const items: [*]T = @ptrCast(@alignCast(bytes));
    assert(@intFromPtr(items) % @alignOf(T) == 0);
    return items[0..count];
}

pub fn free(allocator: std.mem.Allocator, items: anytype) void {
    const T = @typeInfo(@TypeOf(items)).pointer.child;
    const size_bytes = @sizeOf(T) * items.len;
    if (size_bytes < lazy_bytes_min) return allocator.free(items);
    const bytes: [*]u8 = @ptrCast(@constCast(items.ptr));
    allocator.rawFree(bytes[0..size_bytes], .of(T), @returnAddress());
}

pub fn create(allocator: std.mem.Allocator, comptime T: type) error{OutOfMemory}!*T {
    const items = try alloc(allocator, T, 1);
    return &items[0];
}

pub fn destroy(allocator: std.mem.Allocator, pointer: anytype) void {
    const T = @typeInfo(@TypeOf(pointer)).pointer.child;
    free(allocator, @as([*]T, @ptrCast(pointer))[0..1]);
}

test "lazy: small and large allocations round-trip through the testing allocator" {
    const allocator = std.testing.allocator;
    const small = try alloc(allocator, u32, 16);
    defer free(allocator, small);
    const large = try alloc(allocator, u64, 1 << 16);
    defer free(allocator, large);
    try std.testing.expectEqual(@as(usize, 1 << 16), large.len);
    large[0] = 1;
    large[large.len - 1] = 2;
    small[15] = 3;
    const Big = struct { bytes: [1 << 17]u8 };
    const big = try create(allocator, Big);
    defer destroy(allocator, big);
    big.bytes[0] = 4;
    try std.testing.expectEqual(@as(u8, 4), big.bytes[0]);
}

test "lazy: zero-length and overflowing requests" {
    const allocator = std.testing.allocator;
    const empty = try alloc(allocator, u8, 0);
    free(allocator, empty);
    try std.testing.expectError(error.OutOfMemory, alloc(allocator, u64, std.math.maxInt(usize)));
}
