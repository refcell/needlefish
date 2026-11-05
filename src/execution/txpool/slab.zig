//! Fixed size-class byte slab for raw pooled transactions. All memory is allocated in
//! `init`; `alloc`/`free` never touch the allocator. A transaction is stored in the
//! smallest class that fits it, so a 120 byte transfer does not pin a 1 MiB blob slot.

const std = @import("std");
const assert = std.debug.assert;

pub const Class = struct {
    size_bytes: u32,
    count: u32,
};

pub const classes_max = 8;

pub const Config = struct {
    /// Strictly increasing by `size_bytes`.
    classes: []const Class,
};

/// A stored byte string: class index and slot within the class.
pub const Handle = struct {
    class: u8,
    slot: u32,
    len: u32,
};

pub const Slab = struct {
    class_count: u8,
    sizes: [classes_max]u32,
    counts: [classes_max]u32,
    memory: [classes_max][]u8,
    /// Per class, a stack of free slot indices.
    free: [classes_max][]u32,
    free_len: [classes_max]u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Slab {
        assert(config.classes.len > 0);
        assert(config.classes.len <= classes_max);
        var slab: Slab = .{
            .class_count = @intCast(config.classes.len),
            .sizes = @splat(0),
            .counts = @splat(0),
            .memory = @splat(&.{}),
            .free = @splat(&.{}),
            .free_len = @splat(0),
        };
        errdefer slab.deinit(allocator);
        var previous: u32 = 0;
        for (config.classes, 0..) |class, i| {
            assert(class.size_bytes > previous);
            assert(class.count > 0);
            previous = class.size_bytes;
            slab.sizes[i] = class.size_bytes;
            slab.counts[i] = class.count;
            slab.memory[i] = try allocator.alloc(u8, @as(usize, class.size_bytes) * class.count);
            slab.free[i] = try allocator.alloc(u32, class.count);
            for (slab.free[i], 0..) |*slot, j| slot.* = class.count - 1 - @as(u32, @intCast(j));
            slab.free_len[i] = class.count;
        }
        return slab;
    }

    pub fn deinit(slab: *Slab, allocator: std.mem.Allocator) void {
        for (0..slab.class_count) |i| {
            if (slab.memory[i].len > 0) allocator.free(slab.memory[i]);
            if (slab.free[i].len > 0) allocator.free(slab.free[i]);
        }
        slab.* = undefined;
    }

    pub fn max_size_bytes(slab: *const Slab) u32 {
        assert(slab.class_count > 0);
        return slab.sizes[slab.class_count - 1];
    }

    /// Copies `bytes` into the smallest class with a free slot that fits.
    pub fn alloc(slab: *Slab, bytes: []const u8) error{ TooLarge, Full }!Handle {
        if (bytes.len > slab.max_size_bytes()) return error.TooLarge;
        for (0..slab.class_count) |i| {
            if (bytes.len > slab.sizes[i]) continue;
            if (slab.free_len[i] == 0) continue;
            slab.free_len[i] -= 1;
            const slot = slab.free[i][slab.free_len[i]];
            assert(slot < slab.counts[i]);
            const handle: Handle = .{
                .class = @intCast(i),
                .slot = slot,
                .len = @intCast(bytes.len),
            };
            @memcpy(slab.slice_mut(handle), bytes);
            return handle;
        }
        return error.Full;
    }

    pub fn free_handle(slab: *Slab, handle: Handle) void {
        assert(handle.class < slab.class_count);
        assert(slab.free_len[handle.class] < slab.counts[handle.class]);
        slab.free[handle.class][slab.free_len[handle.class]] = handle.slot;
        slab.free_len[handle.class] += 1;
    }

    pub fn slice(slab: *const Slab, handle: Handle) []const u8 {
        assert(handle.class < slab.class_count);
        assert(handle.len <= slab.sizes[handle.class]);
        const start = @as(usize, handle.slot) * slab.sizes[handle.class];
        return slab.memory[handle.class][start..][0..handle.len];
    }

    fn slice_mut(slab: *Slab, handle: Handle) []u8 {
        const start = @as(usize, handle.slot) * slab.sizes[handle.class];
        return slab.memory[handle.class][start..][0..handle.len];
    }

    pub fn free_count(slab: *const Slab) u64 {
        var total: u64 = 0;
        for (slab.free_len[0..slab.class_count]) |n| total += n;
        return total;
    }
};

const testing = std.testing;

test "slab: smallest fitting class, spill over, free" {
    const classes = [_]Class{ .{ .size_bytes = 8, .count = 1 }, .{ .size_bytes = 32, .count = 2 } };
    var slab = try Slab.init(testing.allocator, .{ .classes = &classes });
    defer slab.deinit(testing.allocator);
    const a = try slab.alloc("abc");
    try testing.expectEqual(@as(u8, 0), a.class);
    const b = try slab.alloc("def"); // class 0 full: spills to class 1
    try testing.expectEqual(@as(u8, 1), b.class);
    try testing.expectEqualStrings("abc", slab.slice(a));
    try testing.expectEqualStrings("def", slab.slice(b));
    try testing.expectError(error.TooLarge, slab.alloc(&@as([33]u8, @splat(1))));
    _ = try slab.alloc("x");
    try testing.expectError(error.Full, slab.alloc("y"));
    slab.free_handle(a);
    try testing.expectEqual(@as(u64, 1), slab.free_count());
    _ = try slab.alloc("z");
}

test "slab: seeded fuzz alloc/free keeps contents" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x51ab);
    const classes = [_]Class{
        .{ .size_bytes = 16, .count = 8 },
        .{ .size_bytes = 64, .count = 4 },
    };
    var slab = try Slab.init(testing.allocator, .{ .classes = &classes });
    defer slab.deinit(testing.allocator);
    var live: [12]Handle = undefined;
    var tags: [12]u8 = undefined;
    var live_len: usize = 0;
    for (0..5_000) |_| {
        if (live_len > 0 and prng.chance(1, 2)) {
            const i = prng.below(live_len);
            for (slab.slice(live[i])) |byte| try testing.expectEqual(tags[i], byte);
            slab.free_handle(live[i]);
            live_len -= 1;
            live[i] = live[live_len];
            tags[i] = tags[live_len];
            continue;
        }
        var buffer: [64]u8 = undefined;
        const tag: u8 = @intCast(prng.below(256));
        const data = buffer[0..prng.range(0, 64)];
        @memset(data, tag);
        const handle = slab.alloc(data) catch continue;
        live[live_len] = handle;
        tags[live_len] = tag;
        live_len += 1;
    }
    try testing.expectEqual(@as(u64, 12 - live_len), slab.free_count());
}
