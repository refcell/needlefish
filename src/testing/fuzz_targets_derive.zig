//! Model-based fuzz targets for the derive lane's channel stages
//! (`consensus/derive/channel_stage.zig`).
//!
//! A fuzzed stream of frames (few channel ids, small frame numbers, duplicate and
//! conflicting closes), L1 origin advances, and reads drives the stage under a random
//! rollup config (channel timeouts, Granite on or off). An independent model written from
//! the OP Stack derivation spec predicts every result. The input picks the config and
//! seeds the operation stream, so every run is a full-length stream. Properties:
//!   - channel bank: each read returns exactly the model's outcome (nothing ready, a
//!     timed-out head dropped, or the bytes of the channel the spec selects), and the
//!     bank's size accounting and arrival queue match the model after every step;
//!   - channel assembler (Holocene): each frame yields exactly the model's channel data;
//!   - no leaks: every buffer the stages allocate is freed (testing allocator).

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const protocol = @import("../consensus/protocol/root.zig");
const derive = @import("../consensus/derive/root.zig");

const Frame = protocol.frame.Frame;
const BlockInfo = protocol.block.BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const ChannelBank = derive.channel_stage.ChannelBank;
const ChannelAssembler = derive.channel_stage.ChannelAssembler;

const operations_max = 128;
const ids_max = 4;
const frame_numbers_max = 8;
const data_bytes_max = 12;
const channel_bytes_max = frame_numbers_max * data_bytes_max;

/// A small selector; see `fuzz_targets.draw_below` for why not `valueRangeAtMost`.
fn draw_below(smith: *Smith, comptime n: u8) u8 {
    comptime assert(n > 0);
    return smith.value(u8) % n;
}

fn draw_config(smith: *Smith) RollupConfig {
    var config: RollupConfig = .{
        .channel_timeout = 1 + draw_below(smith, 6),
        .granite_channel_timeout = 1 + draw_below(smith, 6),
    };
    // Granite: never, from genesis, or partway through (timestamp = 2 * L1 number).
    switch (draw_below(smith, 3)) {
        0 => {},
        1 => config.upgrades.set(.granite, 0),
        else => config.upgrades.set(.granite, 2 * @as(u64, draw_below(smith, 40))),
    }
    assert(config.channel_timeout > 0 and config.granite_channel_timeout > 0);
    return config;
}

fn origin_at(number: u64) BlockInfo {
    assert(number > 0);
    return .{ .number = number, .hash = .zero, .parent_hash = .zero, .timestamp = 2 * number };
}

/// The spec's channel: frames by number, closed by its `is_last` frame.
const ModelChannel = struct {
    id: u8,
    open_number: u64,
    closed: bool = false,
    last: u16 = 0,
    highest: u16 = 0,
    present: [frame_numbers_max]bool = @splat(false),
    lengths: [frame_numbers_max]u8 = @splat(0),
    data: [frame_numbers_max][data_bytes_max]u8 = undefined,
    size: u64 = 0,

    fn frame_count(channel: *const ModelChannel) u32 {
        var count: u32 = 0;
        for (channel.present) |present| count += @intFromBool(present);
        return count;
    }

    /// Adds a frame per the spec; false when the spec drops it.
    fn add(channel: *ModelChannel, frame: Frame) bool {
        assert(frame.number < frame_numbers_max and frame.data.len <= data_bytes_max);
        if (frame.id[0] != channel.id) return false;
        if (frame.is_last and channel.closed) return false;
        if (channel.present[frame.number]) return false;
        if (channel.closed and frame.number >= channel.last) return false;
        if (frame.is_last) {
            channel.closed = true;
            channel.last = frame.number;
            // Frames past the end are discarded with their size.
            for (frame.number..frame_numbers_max) |number| {
                if (!channel.present[number]) continue;
                channel.present[number] = false;
                channel.size -= @as(u64, channel.lengths[number]) + Frame.size_overhead;
            }
            channel.highest = @min(channel.highest, channel.last);
        }
        channel.highest = @max(channel.highest, frame.number);
        channel.present[frame.number] = true;
        channel.lengths[frame.number] = @intCast(frame.data.len);
        @memcpy(channel.data[frame.number][0..frame.data.len], frame.data);
        channel.size += frame.size();
        assert(!channel.closed or channel.highest <= channel.last);
        return true;
    }

    fn ready(channel: *const ModelChannel) bool {
        if (!channel.closed) return false;
        for (channel.present[0 .. channel.last + 1]) |present| if (!present) return false;
        return channel.frame_count() == channel.last + 1;
    }

    fn concatenate(channel: *const ModelChannel, out: *[channel_bytes_max]u8) []const u8 {
        assert(channel.ready());
        var length: usize = 0;
        for (0..channel.last + 1) |number| {
            const part = channel.data[number][0..channel.lengths[number]];
            @memcpy(out[length..][0..part.len], part);
            length += part.len;
        }
        return out[0..length];
    }

    fn timed_out(channel: *const ModelChannel, config: *const RollupConfig, origin: u64) bool {
        return channel.open_number + config.channel_timeout_at(2 * origin) < origin;
    }
};

const Outcome = enum { eof, dropped, data };

/// The pre-Holocene bank: channels in arrival order; before Granite only the head
/// channel may be read, after it the first ready one in arrival order.
const ModelBank = struct {
    config: *const RollupConfig,
    channels: [ids_max]ModelChannel = undefined,
    count: u8 = 0,

    fn find(bank: *ModelBank, id: u8) ?*ModelChannel {
        for (bank.channels[0..bank.count]) |*channel| if (channel.id == id) return channel;
        return null;
    }

    fn remove(bank: *ModelBank, index: usize) void {
        assert(index < bank.count);
        for (index..bank.count - 1) |i| bank.channels[i] = bank.channels[i + 1];
        bank.count -= 1;
    }

    fn ingest(bank: *ModelBank, frame: Frame, origin: u64) void {
        const channel = bank.find(frame.id[0]) orelse channel: {
            assert(bank.count < ids_max); // Proof: one channel per id at a time.
            bank.channels[bank.count] = .{ .id = frame.id[0], .open_number = origin };
            bank.count += 1;
            break :channel &bank.channels[bank.count - 1];
        };
        if (channel.timed_out(bank.config, origin)) return;
        _ = channel.add(frame);
    }

    fn read(bank: *ModelBank, origin: u64, out: *[channel_bytes_max]u8) struct {
        Outcome,
        []const u8,
    } {
        if (bank.count == 0) return .{ .eof, &.{} };
        if (bank.channels[0].timed_out(bank.config, origin)) {
            bank.remove(0);
            return .{ .dropped, &.{} };
        }
        const any = bank.config.is_feature_active(.ready_channel_selection, 2 * origin);
        const candidates: usize = if (any) bank.count else 1;
        for (0..candidates) |index| {
            const channel = &bank.channels[index];
            if (channel.timed_out(bank.config, origin) or !channel.ready()) continue;
            const data = channel.concatenate(out);
            bank.remove(index);
            return .{ .data, data };
        }
        return .{ .eof, &.{} };
    }

    fn size(bank: *const ModelBank) u64 {
        var total: u64 = 0;
        for (bank.channels[0..bank.count]) |*channel| total += channel.size;
        return total;
    }
};

const FrameDraw = struct {
    id: [16]u8,
    data: [data_bytes_max]u8,
    frame: Frame,

    /// `hint` biases frame numbers toward the next in-order frame.
    fn draw(draw_buffer: *FrameDraw, prng: *Prng, hint: ?u16) void {
        draw_buffer.id = @splat(0);
        draw_buffer.id[0] = @intCast(prng.below(ids_max));
        const length: usize = @intCast(prng.below(data_bytes_max + 1));
        prng.fill(draw_buffer.data[0..length]);
        const number: u16 = if (hint != null and prng.chance(1, 2))
            @min(hint.?, frame_numbers_max - 1)
        else
            @intCast(prng.below(frame_numbers_max));
        draw_buffer.frame = .{
            .id = draw_buffer.id,
            .number = number,
            .data = draw_buffer.data[0..length],
            .is_last = prng.chance(1, 4),
        };
    }
};

fn expect_bank_matches(bank: *const ChannelBank, model: *const ModelBank) !void {
    try std.testing.expectEqual(model.size(), bank.size());
    try std.testing.expectEqual(@as(usize, model.count), bank.queue.items.len);
    for (bank.queue.items, model.channels[0..model.count]) |id, *channel| {
        try std.testing.expectEqual(channel.id, id[0]);
    }
}

fn fuzz_channel_bank(_: void, smith: *Smith) anyerror!void {
    const config = draw_config(smith);
    var bank = ChannelBank.init(std.testing.allocator, &config);
    defer bank.deinit();
    var model: ModelBank = .{ .config = &config };
    var origin: u64 = 1;
    var frame_draw: FrameDraw = undefined;
    var expected_buffer: [channel_bytes_max]u8 = undefined;
    var prng = Prng.init(smith.value(u64));
    for (0..operations_max) |_| {
        switch (prng.below(4)) {
            0, 1 => {
                frame_draw.draw(&prng, null);
                try bank.ingest_frame(frame_draw.frame, origin_at(origin));
                model.ingest(frame_draw.frame, origin);
            },
            2 => origin += prng.below(3),
            else => {
                const expected, const expected_data = model.read(origin, &expected_buffer);
                const actual = bank.read(origin_at(origin)) catch |err| switch (err) {
                    error.Eof => {
                        try std.testing.expectEqual(Outcome.eof, expected);
                        continue;
                    },
                    else => return err,
                };
                if (actual) |data| {
                    defer std.testing.allocator.free(data);
                    try std.testing.expectEqual(Outcome.data, expected);
                    try std.testing.expectEqualSlices(u8, expected_data, data);
                } else {
                    try std.testing.expectEqual(Outcome.dropped, expected);
                }
            },
        }
        try expect_bank_matches(&bank, &model);
    }
}

/// The Holocene assembler: one channel, frames strictly in order, a frame 0 restarts.
const ModelAssembler = struct {
    config: *const RollupConfig,
    channel: ?ModelChannel = null,

    fn next(
        assembler: *ModelAssembler,
        frame: Frame,
        origin: u64,
        out: *[channel_bytes_max]u8,
    ) ?[]const u8 {
        if (assembler.channel) |*channel| {
            if (channel.timed_out(assembler.config, origin)) assembler.channel = null;
        }
        if (frame.number == 0) {
            assembler.channel = .{ .id = frame.id[0], .open_number = origin };
        }
        const channel = &(assembler.channel orelse return null);
        if (frame.number != channel.frame_count()) return null;
        if (!channel.add(frame)) return null;
        // Proof: tiny frames never reach the max RLP bytes per channel.
        assert(channel.size <= assembler.config.max_rlp_bytes_per_channel(2 * origin));
        if (!channel.ready()) return null;
        const data = channel.concatenate(out);
        assembler.channel = null;
        return data;
    }
};

/// The stage's previous stage: one frame at a fixed origin.
const OneFrame = struct {
    origin_block: BlockInfo,
    frame: ?Frame,

    pub fn origin(stub: *const OneFrame) ?BlockInfo {
        return stub.origin_block;
    }

    pub fn next_frame(stub: *OneFrame) derive.errors.Error!Frame {
        defer stub.frame = null;
        return stub.frame orelse error.Eof;
    }
};

fn fuzz_channel_assembler(_: void, smith: *Smith) anyerror!void {
    const config = draw_config(smith);
    var assembler = ChannelAssembler.init(std.testing.allocator, &config);
    defer assembler.deinit();
    var model: ModelAssembler = .{ .config = &config };
    var origin: u64 = 1;
    var frame_draw: FrameDraw = undefined;
    var expected_buffer: [channel_bytes_max]u8 = undefined;
    var prng = Prng.init(smith.value(u64));
    for (0..operations_max) |_| {
        origin += @intFromBool(prng.chance(1, 4));
        const hint: u16 = if (model.channel) |*channel| @intCast(channel.frame_count()) else 0;
        frame_draw.draw(&prng, hint);
        // Keep in-order runs on the open channel's id.
        if (model.channel) |*channel| {
            if (!prng.chance(1, 4)) frame_draw.id[0] = channel.id;
        }
        frame_draw.frame.id = frame_draw.id;
        const expected = model.next(frame_draw.frame, origin, &expected_buffer);
        var stub: OneFrame = .{ .origin_block = origin_at(origin), .frame = frame_draw.frame };
        const actual = assembler.next_data(&stub) catch |err| switch (err) {
            error.NotEnoughData => {
                try std.testing.expect(expected == null);
                continue;
            },
            else => return err,
        };
        const data = actual orelse return error.TestUnexpectedResult;
        defer std.testing.allocator.free(data);
        try std.testing.expectEqualSlices(u8, expected orelse return error.TestExpectedEqual, data);
    }
}

test "fuzz_targets_derive: channel bank matches the spec model" {
    try fuzz.run({}, fuzz_channel_bank, .{ .iterations = 512 });
}

test "fuzz_targets_derive: channel assembler matches the spec model" {
    try fuzz.run({}, fuzz_channel_assembler, .{ .iterations = 512 });
}
