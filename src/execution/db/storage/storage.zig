//! The sector storage interface every engine component is written against.
//!
//! `Storage` is a comptime duck type, so the engine compiles against the deterministic
//! simulator in tests (`SimStorage`) and against a real io_uring/kqueue backend in
//! production with no dynamic dispatch. A backend provides:
//!
//!   read_sectors(self, callback: *const fn (*Read) void, read: *Read,
//!       buffer: []u8, offset: u64) void
//!   write_sectors(self, callback: *const fn (*Write) void, write: *Write,
//!       buffer: []const u8, offset: u64) void
//!   sync(self, callback: *const fn (*Sync) void, sync: *Sync) void
//!   tick(self) void
//!   size_bytes(self) u64
//!
//! Rules:
//! - Offsets and lengths are multiples of `sector_size`; lengths are non-zero.
//! - Completions (`Read`, `Write`, `Sync`) are owned by the caller, embedded in the caller's
//!   own state (intrusive), and recovered in the callback with `@fieldParentPtr`. A
//!   completion and its buffer stay untouched until the callback fires.
//! - Callbacks are delivered only from `tick()`, never re-entrantly from a submit call. A
//!   callback may submit new operations.
//! - `sync` is a barrier: every write whose callback fired before the sync was submitted is
//!   durable when the sync callback fires. A completed but unsynced write may be lost, kept,
//!   or torn by a crash.
//! - Concurrent operations must not overlap a pending write (the simulator asserts this).

const std = @import("std");
const assert = std.debug.assert;

pub const sector_size: u32 = 4096;

pub const Operation = enum(u8) { read, write, sync };

/// Backend bookkeeping embedded in every completion. Only the backend touches it.
pub const Completion = struct {
    next: ?*Completion = null,
    operation: Operation = .read,
    /// Backend-defined: the simulator stores the tick at which the operation completes.
    tick_ready: u64 = 0,
};

pub const Read = struct {
    completion: Completion = .{},
    callback: *const fn (*Read) void = undefined,
    buffer: []u8 = &.{},
    offset: u64 = 0,
};

pub const Write = struct {
    completion: Completion = .{},
    callback: *const fn (*Write) void = undefined,
    buffer: []const u8 = &.{},
    offset: u64 = 0,
};

pub const Sync = struct {
    completion: Completion = .{},
    callback: *const fn (*Sync) void = undefined,
};

/// Rounds `size` up to a whole number of sectors.
pub fn sector_ceil(size: u64) u64 {
    const result = std.mem.alignForward(u64, size, sector_size);
    assert(result >= size);
    assert(result - size < sector_size);
    return result;
}

pub fn assert_aligned(offset: u64, length: u64) void {
    assert(offset % sector_size == 0);
    assert(length % sector_size == 0);
    assert(length > 0);
}

/// Compile-time check that `Storage` provides the interface above.
pub fn assert_interface(comptime Storage: type) void {
    comptime {
        assert(@hasDecl(Storage, "read_sectors"));
        assert(@hasDecl(Storage, "write_sectors"));
        assert(@hasDecl(Storage, "sync"));
        assert(@hasDecl(Storage, "tick"));
        assert(@hasDecl(Storage, "size_bytes"));
    }
}

test "storage: sector_ceil" {
    try std.testing.expectEqual(@as(u64, 0), sector_ceil(0));
    try std.testing.expectEqual(@as(u64, sector_size), sector_ceil(1));
    try std.testing.expectEqual(@as(u64, sector_size), sector_ceil(sector_size));
    try std.testing.expectEqual(@as(u64, 2 * sector_size), sector_ceil(sector_size + 1));
}
