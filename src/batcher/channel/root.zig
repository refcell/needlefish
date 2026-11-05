//! Channel out: collects encoded batches, compresses them, and cuts frames.
//!
//! Mirrors op-batcher's `ChannelOut` with a ratio size estimate (op-batcher's
//! `RatioCompressor`): while open, a channel accepts batches until the estimated
//! compressed size would exceed `target_frames` full frames. On close the whole input
//! is compressed once and sliced into frames of at most `frame_size_max` bytes. The
//! estimate can be off; a channel then just produces a few more or fewer frames.
//!
//! Memory is allocated once in `init` from the config; `reset` reuses it.

const std = @import("std");
const assert = std.debug.assert;
const comp = @import("../comp/root.zig");
const frame_module = @import("../frame/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const Frame = frame_module.Frame;
pub const ChannelId = frame_module.ChannelId;

pub const Config = struct {
    /// Largest encoded frame, including the 23-byte frame overhead.
    frame_size_max: u32,
    /// Frames a channel aims to fill before it reports full.
    target_frames: u16 = 1,
    /// Expected compressed / uncompressed ratio, in percent (op-batcher default 0.6).
    compression_ratio_percent: u8 = 60,
    /// Hard cap on uncompressed batch bytes per channel (sizes the input buffer).
    input_bytes_max: u32 = 4 * 1024 * 1024,
    algorithm: comp.Algorithm = .zlib,
    /// Compressed bytes a channel aims for (base/base `--compressed-size-target`); 0 means
    /// `target_frames` full frames. Like the frame target it is met through the ratio
    /// estimate, since the channel compresses once at close.
    compressed_bytes_target: u32 = 0,
    /// Brotli match search effort, 0..=11 (base/base `--brotli-quality`).
    brotli_quality: u4 = comp.brotli.quality_default,

    pub fn validate(config: Config) void {
        assert(config.frame_size_max > Frame.encoded_overhead);
        assert(config.frame_size_max - Frame.encoded_overhead <= Frame.frame_data_length_max);
        assert(config.target_frames >= 1);
        assert(config.compression_ratio_percent >= 1);
        assert(config.compression_ratio_percent <= 100);
        assert(config.input_bytes_max >= 1);
        assert(config.brotli_quality <= comp.brotli.quality_max);
    }

    /// Uncompressed bytes at which the ratio estimate fills `target_frames` frames.
    pub fn input_bytes_target(config: Config) u64 {
        const data_per_frame: u64 = config.frame_size_max - Frame.encoded_overhead;
        const compressed_target: u64 = if (config.compressed_bytes_target > 0)
            config.compressed_bytes_target
        else
            data_per_frame * config.target_frames;
        const target = compressed_target * 100 / config.compression_ratio_percent;
        return @max(1, @min(target, config.input_bytes_max));
    }

    fn output_bytes_max(config: Config) u64 {
        const input_max = config.input_bytes_max;
        return @max(comp.zlib_bound(input_max), comp.brotli_bound(input_max));
    }
};

pub const AddError = error{ChannelFull};

pub const manager = @import("manager.zig");

pub const ChannelOut = struct {
    config: Config,
    id: ChannelId,
    input: []u8,
    input_length: u32,
    output: []u8,
    output_length: u32,
    /// Bytes of `output` already handed out as frames.
    output_cursor: u32,
    next_frame_number: u16,
    batch_count: u32,
    state: enum { open, closed, done },
    zlib: *comp.Zlib,
    /// Brotli channels only.
    brotli: ?*comp.brotli.Encoder,

    pub fn init(allocator: std.mem.Allocator, config: Config, id: ChannelId) !ChannelOut {
        config.validate();
        const input = try allocator.alloc(u8, config.input_bytes_max);
        errdefer allocator.free(input);
        const output = try allocator.alloc(u8, @intCast(config.output_bytes_max()));
        errdefer allocator.free(output);
        const zlib = try allocator.create(comp.Zlib);
        errdefer allocator.destroy(zlib);
        zlib.* = .{};
        const use_brotli = config.algorithm == .brotli;
        const brotli = if (use_brotli) try create_brotli(allocator, config) else null;
        var channel: ChannelOut = .{
            .config = config,
            .id = undefined,
            .input = input,
            .input_length = 0,
            .output = output,
            .output_length = 0,
            .output_cursor = 0,
            .next_frame_number = 0,
            .batch_count = 0,
            .state = .open,
            .zlib = zlib,
            .brotli = brotli,
        };
        channel.reset(id);
        return channel;
    }

    pub fn deinit(channel: *ChannelOut, allocator: std.mem.Allocator) void {
        allocator.free(channel.input);
        allocator.free(channel.output);
        allocator.destroy(channel.zlib);
        if (channel.brotli) |brotli| {
            brotli.deinit(allocator);
            allocator.destroy(brotli);
        }
        channel.* = undefined;
    }

    fn create_brotli(allocator: std.mem.Allocator, config: Config) !*comp.brotli.Encoder {
        const brotli = try allocator.create(comp.brotli.Encoder);
        errdefer allocator.destroy(brotli);
        brotli.* = try .init_quality(allocator, config.input_bytes_max, config.brotli_quality);
        return brotli;
    }

    /// Reopens the channel under a new id, reusing all buffers.
    pub fn reset(channel: *ChannelOut, id: ChannelId) void {
        channel.id = id;
        channel.input_length = 0;
        channel.output_length = 0;
        channel.output_cursor = 0;
        channel.next_frame_number = 0;
        channel.batch_count = 0;
        channel.state = .open;
    }

    /// Appends one encoded batch. A channel always takes its first batch if it fits
    /// the hard input cap, so oversized batches still make progress.
    pub fn add_batch(channel: *ChannelOut, batch: []const u8) AddError!void {
        assert(channel.state == .open);
        assert(batch.len > 0);
        const length_new = @as(u64, channel.input_length) + batch.len;
        if (length_new > channel.config.input_bytes_max) return error.ChannelFull;
        if (channel.batch_count > 0 and length_new > channel.config.input_bytes_target()) {
            return error.ChannelFull;
        }
        @memcpy(channel.input[channel.input_length..][0..batch.len], batch);
        channel.input_length = @intCast(length_new);
        channel.batch_count += 1;
        assert(channel.input_length <= channel.input.len);
    }

    /// True once the size estimate says the channel should close.
    pub fn is_full(channel: *const ChannelOut) bool {
        return channel.input_length >= channel.config.input_bytes_target();
    }

    pub fn input_bytes(channel: *const ChannelOut) u32 {
        return channel.input_length;
    }

    /// Compresses the collected batches. Afterwards, `next_frame` yields frames.
    pub fn close(channel: *ChannelOut) void {
        assert(channel.state == .open);
        assert(channel.batch_count > 0);
        const input = channel.input[0..channel.input_length];
        const encoded = switch (channel.config.algorithm) {
            .zlib => channel.zlib.compress(input, channel.output),
            .brotli => comp.brotli_compress(channel.brotli.?, input, channel.output),
        } catch unreachable; // Output buffer is sized by the algorithm's bound.
        assert(encoded.len > 0);
        channel.output_length = @intCast(encoded.len);
        channel.state = .closed;
    }

    /// Frames still to emit after `close`.
    pub fn frames_remaining(channel: *const ChannelOut) u32 {
        if (channel.state == .done) return 0;
        assert(channel.state == .closed);
        const data_per_frame = channel.config.frame_size_max - Frame.encoded_overhead;
        const left = channel.output_length - channel.output_cursor;
        return @intCast(@max(1, std.math.divCeil(u32, left, data_per_frame) catch unreachable));
    }

    /// Returns the next frame, or null when all frames are out. The frame borrows the
    /// channel's buffer and stays valid until `reset`.
    pub fn next_frame(channel: *ChannelOut) ?Frame {
        if (channel.state == .done) return null;
        assert(channel.state == .closed);
        const data_per_frame = channel.config.frame_size_max - Frame.encoded_overhead;
        const left = channel.output_length - channel.output_cursor;
        const length = @min(left, data_per_frame);
        const is_last = length == left;
        const frame: Frame = .{
            .id = channel.id,
            .number = channel.next_frame_number,
            .data = channel.output[channel.output_cursor..][0..length],
            .is_last = is_last,
        };
        assert(frame.encoded_length() <= channel.config.frame_size_max);
        channel.output_cursor += length;
        if (is_last) {
            assert(channel.output_cursor == channel.output_length);
            channel.state = .done;
        } else {
            // u16 frame numbers bound a channel to 65535 frames; the input cap keeps
            // channels far below that for any sane frame size.
            channel.next_frame_number += 1;
        }
        return frame;
    }

    /// Compressed channel bytes (after `close`).
    pub fn compressed(channel: *const ChannelOut) []const u8 {
        assert(channel.state != .open);
        return channel.output[0..channel.output_length];
    }
};

const testing = std.testing;
const protocol = @import("../../consensus/protocol/root.zig");

/// Feeds every frame of a closed channel through the consensus channel and returns
/// the reassembled compressed data (caller frees).
fn reassemble(channel: *ChannelOut) ![]u8 {
    var bank = protocol.Channel.init(channel.id, .{});
    defer bank.deinit(testing.allocator);
    const expected_frames = channel.frames_remaining();
    var count: u32 = 0;
    while (channel.next_frame()) |frame| : (count += 1) {
        try testing.expectEqual(@as(u16, @intCast(count)), frame.number);
        try testing.expectEqual(count + 1 == expected_frames, frame.is_last);
        try bank.add_frame(testing.allocator, frame, .{ .number = 1 });
    }
    try testing.expectEqual(expected_frames, count);
    try testing.expectEqual(@as(?Frame, null), channel.next_frame());
    try testing.expect(bank.is_ready());
    return bank.frame_data_alloc(testing.allocator);
}

test "channel: fills, closes, and frames reassemble" {
    const config: Config = .{ .frame_size_max = 23 + 100, .target_frames = 2 };
    var channel = try ChannelOut.init(testing.allocator, config, @splat(7));
    defer channel.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 333), config.input_bytes_target());
    var batch: [100]u8 = undefined;
    for (&batch, 0..) |*byte, i| byte.* = @truncate(i * 37);
    try channel.add_batch(&batch);
    try channel.add_batch(&batch);
    try channel.add_batch(&batch);
    try testing.expect(!channel.is_full());
    try testing.expectError(error.ChannelFull, channel.add_batch(&batch));
    channel.close();
    const data = try reassemble(&channel);
    defer testing.allocator.free(data);
    try testing.expectEqualSlices(u8, channel.compressed(), data);
}

test "channel: compressed size target overrides the frame target" {
    const frames: Config = .{ .frame_size_max = 23 + 100, .target_frames = 2 };
    var sized = frames;
    sized.compressed_bytes_target = 60;
    try testing.expectEqual(@as(u64, 333), frames.input_bytes_target());
    try testing.expectEqual(@as(u64, 100), sized.input_bytes_target());
    var channel = try ChannelOut.init(testing.allocator, sized, @splat(2));
    defer channel.deinit(testing.allocator);
    var batch: [60]u8 = @splat(9);
    try channel.add_batch(&batch);
    try testing.expectError(error.ChannelFull, channel.add_batch(&batch));
    sized.compressed_bytes_target = std.math.maxInt(u32);
    try testing.expectEqual(@as(u64, sized.input_bytes_max), sized.input_bytes_target());
}

test "channel: fuzz the input target" {
    try testing.fuzz({}, fuzz_input_target, .{});
}

fn fuzz_input_target(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [16]u8 = @splat(0);
    _ = smith.slice(&bytes);
    const config: Config = .{
        .frame_size_max = @max(24, std.mem.readInt(u32, bytes[0..4], .little) % 200_000),
        .target_frames = @max(1, std.mem.readInt(u16, bytes[4..6], .little)),
        .compression_ratio_percent = @max(1, bytes[6] % 101),
        .input_bytes_max = @max(1, std.mem.readInt(u32, bytes[8..12], .little)),
        .compressed_bytes_target = std.mem.readInt(u32, bytes[12..16], .little),
    };
    if (config.frame_size_max - Frame.encoded_overhead > Frame.frame_data_length_max) return;
    config.validate();
    const target = config.input_bytes_target();
    try testing.expect(target >= 1 and target <= config.input_bytes_max);
    if (config.compressed_bytes_target > 0 and config.compressed_bytes_target < 1000) {
        var bigger = config;
        bigger.compressed_bytes_target += 1;
        try testing.expect(bigger.input_bytes_target() >= target);
    }
}

test "channel: oversized first batch still accepted" {
    const config: Config = .{ .frame_size_max = 23 + 10, .input_bytes_max = 1000 };
    var channel = try ChannelOut.init(testing.allocator, config, @splat(1));
    defer channel.deinit(testing.allocator);
    var batch: [500]u8 = @splat(3);
    try channel.add_batch(&batch);
    try testing.expect(channel.is_full());
    try testing.expectError(error.ChannelFull, channel.add_batch(batch[0..1]));
    channel.close();
    try testing.expect(channel.frames_remaining() >= 1);
}

test "channel: seeded fuzz round trip through consensus channel" {
    var prng = Prng.init(0x6368616e);
    const window = try testing.allocator.alloc(u8, std.compress.flate.max_window_len);
    defer testing.allocator.free(window);
    const plain = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(plain);
    var batch: [2048]u8 = undefined;
    for (0..40) |round| {
        const config: Config = .{
            .frame_size_max = @intCast(prng.range(24, 4096)),
            .target_frames = @intCast(prng.range(1, 6)),
            .compression_ratio_percent = @intCast(prng.range(10, 100)),
            .input_bytes_max = 64 * 1024,
            .algorithm = if (round % 2 == 0) .zlib else .brotli,
            .compressed_bytes_target = if (prng.chance(1, 2)) 0 else @intCast(prng.range(1, 8192)),
            .brotli_quality = @intCast(prng.below(comp.brotli.quality_max + 1)),
        };
        var channel = try ChannelOut.init(testing.allocator, config, @splat(@truncate(round)));
        defer channel.deinit(testing.allocator);
        // Each add either fits or fills the channel, bounded by the batch count.
        for (0..64) |_| {
            const length = prng.range(1, batch.len);
            for (batch[0..length]) |*byte| byte.* = if (prng.chance(3, 4)) 'x' else prng.int(u8);
            channel.add_batch(batch[0..length]) catch break;
        }
        const input = channel.input[0..channel.input_length];
        channel.close();
        const data = try reassemble(&channel);
        defer testing.allocator.free(data);
        const decoded = switch (config.algorithm) {
            .zlib => try comp.zlib_decompress(data, window, plain),
            .brotli => try brotli_decode(data),
        };
        defer if (config.algorithm == .brotli) testing.allocator.free(decoded);
        try testing.expectEqualSlices(u8, input, decoded);
    }
}

fn brotli_decode(data: []const u8) ![]u8 {
    const consensus_brotli = @import("../../consensus/protocol/brotli.zig");
    try testing.expectEqual(comp.brotli_channel_version, data[0]);
    return consensus_brotli.decompress(testing.allocator, data[1..], 1 << 20);
}

test {
    std.testing.refAllDecls(@This());
}
