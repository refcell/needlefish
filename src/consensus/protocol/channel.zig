//! A channel reassembles frames (possibly out of order) into compressed batch data.
//!
//! Frame data is copied into memory owned by the channel because L1 payloads are
//! transient. The channel bank above bounds the total bytes across all channels.
//! Mirrors base/base `crates/consensus/protocol/src/channel.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const frame_module = @import("frame.zig");
const Frame = frame_module.Frame;
const ChannelId = frame_module.ChannelId;
const BlockInfo = @import("block.zig").BlockInfo;

/// Maximum size of a decompressed channel's RLP stream (pre-Fjord limit).
pub const rlp_bytes_max_bedrock: u64 = 10_000_000;
/// Maximum size of a decompressed channel's RLP stream from Fjord on.
pub const rlp_bytes_max_fjord: u64 = 100_000_000;

pub const AddFrameError = error{
    FrameIdMismatch,
    ChannelClosed,
    FrameNumberExists,
    FrameBeyondEndFrame,
} || Allocator.Error;

pub const Channel = struct {
    id: ChannelId,
    open_block: BlockInfo,
    /// Sum of `Frame.size()` over stored frames.
    estimated_size: u64 = 0,
    closed: bool = false,
    highest_frame_number: u16 = 0,
    last_frame_number: u16 = 0,
    /// Frame number to owned frame data.
    inputs: std.AutoHashMapUnmanaged(u16, []u8) = .empty,
    highest_l1_inclusion_block: BlockInfo = .{},

    pub fn init(id: ChannelId, open_block: BlockInfo) Channel {
        return .{ .id = id, .open_block = open_block };
    }

    pub fn deinit(channel: *Channel, allocator: Allocator) void {
        var iterator = channel.inputs.valueIterator();
        while (iterator.next()) |data| allocator.free(data.*);
        channel.inputs.deinit(allocator);
        channel.* = undefined;
    }

    pub fn frame_count(channel: *const Channel) u32 {
        return channel.inputs.count();
    }

    /// Adds a frame. On error the channel is unchanged.
    pub fn add_frame(
        channel: *Channel,
        allocator: Allocator,
        frame: Frame,
        l1_inclusion_block: BlockInfo,
    ) AddFrameError!void {
        if (!std.mem.eql(u8, &frame.id, &channel.id)) return error.FrameIdMismatch;
        if (frame.is_last and channel.closed) return error.ChannelClosed;
        if (channel.inputs.contains(frame.number)) return error.FrameNumberExists;
        if (channel.closed and frame.number >= channel.last_frame_number) {
            return error.FrameBeyondEndFrame;
        }

        // Reserve and copy before mutating so failure leaves the channel intact.
        try channel.inputs.ensureUnusedCapacity(allocator, 1);
        const data = try allocator.dupe(u8, frame.data);

        if (frame.is_last) {
            channel.last_frame_number = frame.number;
            channel.closed = true;
            if (channel.last_frame_number < channel.highest_frame_number) {
                channel.prune_beyond_last(allocator);
                channel.highest_frame_number = channel.last_frame_number;
            }
        }
        if (frame.number > channel.highest_frame_number) {
            channel.highest_frame_number = frame.number;
        }
        if (channel.highest_l1_inclusion_block.number < l1_inclusion_block.number) {
            channel.highest_l1_inclusion_block = l1_inclusion_block;
        }
        channel.estimated_size += frame.size();
        channel.inputs.putAssumeCapacityNoClobber(frame.number, data);
        assert(!channel.closed or channel.highest_frame_number <= channel.last_frame_number);
    }

    /// Drops stored frames numbered at or beyond the closing frame.
    fn prune_beyond_last(channel: *Channel, allocator: Allocator) void {
        assert(channel.closed);
        // Removal during iteration is unsupported, so walk the bounded number range.
        var number: u32 = channel.last_frame_number;
        while (number <= channel.highest_frame_number) : (number += 1) {
            const removed = channel.inputs.fetchRemove(@intCast(number)) orelse continue;
            const size = @as(u64, removed.value.len) + Frame.size_overhead;
            assert(channel.estimated_size >= size);
            channel.estimated_size -= size;
            allocator.free(removed.value);
        }
    }

    /// True when the channel is closed and holds every frame `0..=last_frame_number`.
    pub fn is_ready(channel: *const Channel) bool {
        if (!channel.closed) return false;
        if (channel.inputs.count() != @as(u32, channel.last_frame_number) + 1) return false;
        var number: u32 = 0;
        while (number <= channel.last_frame_number) : (number += 1) {
            if (!channel.inputs.contains(@intCast(number))) return false;
        }
        return true;
    }

    /// Total data length of frames `0..=last_frame_number`, or null if any is missing.
    pub fn frame_data_length(channel: *const Channel) ?u64 {
        var total: u64 = 0;
        var number: u32 = 0;
        while (number <= channel.last_frame_number) : (number += 1) {
            const data = channel.inputs.get(@intCast(number)) orelse return null;
            total += data.len;
        }
        return total;
    }

    /// Concatenates frame data into `out` (sized by `frame_data_length`).
    pub fn frame_data(channel: *const Channel, out: []u8) []u8 {
        assert(channel.is_ready());
        var offset: usize = 0;
        var number: u32 = 0;
        while (number <= channel.last_frame_number) : (number += 1) {
            const data = channel.inputs.get(@intCast(number)).?;
            @memcpy(out[offset..][0..data.len], data);
            offset += data.len;
        }
        return out[0..offset];
    }

    /// Allocates and returns the concatenated frame data. Caller owns the result.
    pub fn frame_data_alloc(channel: *const Channel, allocator: Allocator) Allocator.Error![]u8 {
        assert(channel.is_ready());
        const length = channel.frame_data_length().?;
        const out = try allocator.alloc(u8, @intCast(length));
        const written = channel.frame_data(out);
        assert(written.len == out.len);
        return out;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const Case = struct {
    frames: []const Frame,
    should_error: []const bool,
    sizes: []const u64,
    data: ?[]const u8 = null,
};

fn run_case(case: Case) !void {
    const id = @as([16]u8, @splat(0xff));
    var channel = Channel.init(id, .{});
    defer channel.deinit(testing.allocator);
    for (case.frames, case.should_error, case.sizes) |frame, should_error, size| {
        const result = channel.add_frame(testing.allocator, frame, .{});
        try testing.expectEqual(should_error, std.meta.isError(result));
        try testing.expectEqual(size, channel.estimated_size);
    }
    if (case.data) |expected| {
        const data = try channel.frame_data_alloc(testing.allocator);
        defer testing.allocator.free(data);
        try testing.expectEqualSlices(u8, expected, data);
    }
}

test "channel: frame validity" {
    const id = @as([16]u8, @splat(0xff));
    const f = struct {
        fn make(number: u16, is_last: bool, data: []const u8) Frame {
            return .{ .id = @splat(0xff), .number = number, .is_last = is_last, .data = data };
        }
    }.make;
    const other: Frame = .{ .id = @splat(0xee), .number = 0, .is_last = false, .data = "" };
    try run_case(.{ .frames = &.{other}, .should_error = &.{true}, .sizes = &.{0} });
    // Double close.
    try run_case(.{
        .frames = &.{ f(2, true, "four"), f(1, true, "") },
        .should_error = &.{ false, true },
        .sizes = &.{ 204, 204 },
    });
    // Duplicate frame.
    try run_case(.{
        .frames = &.{ f(2, false, "four"), f(2, false, "seven") },
        .should_error = &.{ false, true },
        .sizes = &.{ 204, 204 },
    });
    // Frame past closing.
    try run_case(.{
        .frames = &.{ f(2, true, "four"), f(10, false, "seven") },
        .should_error = &.{ false, true },
        .sizes = &.{ 204, 204 },
    });
    try run_case(.{
        .frames = &.{ f(0, false, "seven"), f(1, true, "four") },
        .should_error = &.{ false, false },
        .sizes = &.{ 205, 409 },
        .data = "sevenfour",
    });
    // Prune future frames on out-of-order close.
    try run_case(.{
        .frames = &.{ f(2, false, "two"), f(0, false, "zero"), f(1, true, "one") },
        .should_error = &.{ false, false, false },
        .sizes = &.{ 203, 407, 407 },
        .data = "zeroone",
    });
    _ = id;
}

test "channel: seeded fuzz invariants" {
    var prng = Prng.init(0x4348414e);
    const id = @as([16]u8, @splat(7));
    var data: [64]u8 = undefined;
    for (0..300) |_| {
        var channel = Channel.init(id, .{});
        defer channel.deinit(testing.allocator);
        for (0..prng.range(1, 40)) |_| {
            const length = prng.below(data.len);
            prng.fill(data[0..length]);
            const frame: Frame = .{
                .id = if (prng.chance(1, 20)) @as([16]u8, @splat(8)) else id,
                .number = @intCast(prng.below(24)),
                .data = data[0..length],
                .is_last = prng.chance(1, 6),
            };
            const before = channel.estimated_size;
            const inclusion: BlockInfo = .{ .number = prng.below(100) };
            channel.add_frame(testing.allocator, frame, inclusion) catch |err| {
                if (err == error.OutOfMemory) return err;
                try testing.expectEqual(before, channel.estimated_size);
                continue;
            };
            // Invariant: estimated size equals the sum over stored frames.
            var total: u64 = 0;
            var iterator = channel.inputs.valueIterator();
            while (iterator.next()) |stored| total += stored.len + Frame.size_overhead;
            try testing.expectEqual(total, channel.estimated_size);
            if (channel.closed) {
                var keys = channel.inputs.keyIterator();
                while (keys.next()) |key| try testing.expect(key.* <= channel.last_frame_number);
            }
        }
        if (channel.is_ready()) {
            const out = try channel.frame_data_alloc(testing.allocator);
            testing.allocator.free(out);
        }
    }
}
