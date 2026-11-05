//! Channel frames: the unit of batch data posted to L1.
//!
//! Wire format (OP Stack derivation spec, "Frame Format"):
//!   frame = channel_id ++ frame_number ++ frame_data_length ++ frame_data ++ is_last
//!   channel_id        bytes16
//!   frame_number      uint16 big-endian
//!   frame_data_length uint32 big-endian
//!   frame_data        bytes
//!   is_last           bool (0 or 1, any other value is invalid)
//!
//! L1 batcher transaction data is `version_byte ++ frame*`; only version 0 exists.
//! Decoding is zero-copy: a decoded `Frame.data` borrows from the input buffer.
//! Mirrors base/base `crates/consensus/protocol/src/frame.rs`.

const std = @import("std");
const assert = std.debug.assert;

pub const channel_id_length: u32 = 16;
pub const ChannelId = [channel_id_length]u8;

/// The only derivation version defined by the spec.
pub const derivation_version_0: u8 = 0;

/// Maximum data bytes a blob carries after field-element packing.
pub const blob_max_data_size: u32 = (4 * 31 + 3) * 1024 - 4;
/// One version byte prefixes the frames inside a blob.
pub const blob_derivation_prefix_size: u32 = 1;
pub const max_blob_frame_size: u32 = blob_max_data_size - blob_derivation_prefix_size;

pub const DecodeError = error{
    /// Fewer than `encoded_overhead` bytes remain.
    FrameTooShort,
    /// The declared data length exceeds `frame_data_length_max` or the input.
    FrameDataTooLarge,
    /// The `is_last` byte is neither 0 nor 1.
    FrameInvalidIsLast,
};

pub const ParseError = DecodeError || error{
    NoFrames,
    UnsupportedVersion,
};

pub const Frame = struct {
    id: ChannelId,
    number: u16,
    data: []const u8,
    is_last: bool,

    /// Fixed bytes around `data`: id (16) + number (2) + length (4) + is_last (1).
    pub const encoded_overhead: u32 = channel_id_length + 2 + 4 + 1;
    /// Accounting overhead per frame used by the channel bank size limits.
    pub const size_overhead: u32 = 200;
    /// Largest data length a frame may declare.
    pub const frame_data_length_max: u32 = 1_000_000;

    comptime {
        assert(encoded_overhead == 23);
        assert(frame_data_length_max < std.math.maxInt(u32) - encoded_overhead);
    }

    pub fn encoded_length(frame: *const Frame) u32 {
        assert(frame.data.len <= frame_data_length_max);
        return encoded_overhead + @as(u32, @intCast(frame.data.len));
    }

    /// Size used for channel bank accounting (`frame.size()` in base/base).
    pub fn size(frame: *const Frame) u64 {
        return @as(u64, frame.data.len) + size_overhead;
    }

    /// Encodes the frame into `out`, returning the written prefix.
    pub fn encode(frame: *const Frame, out: []u8) []u8 {
        const length = frame.encoded_length();
        assert(out.len >= length);
        const data_length: u32 = @intCast(frame.data.len);
        @memcpy(out[0..16], &frame.id);
        std.mem.writeInt(u16, out[16..18], frame.number, .big);
        std.mem.writeInt(u32, out[18..22], data_length, .big);
        @memcpy(out[22..][0..frame.data.len], frame.data);
        out[22 + frame.data.len] = @intFromBool(frame.is_last);
        assert(out[length - 1] <= 1);
        return out[0..length];
    }

    pub const Decoded = struct {
        frame: Frame,
        /// Bytes consumed from the input.
        length: u32,
    };

    /// Decodes one frame from the front of `encoded`. `frame.data` borrows `encoded`.
    pub fn decode(encoded: []const u8) DecodeError!Decoded {
        if (encoded.len < encoded_overhead) return error.FrameTooShort;
        const data_length = std.mem.readInt(u32, encoded[18..22], .big);
        if (data_length > frame_data_length_max) return error.FrameDataTooLarge;
        if (data_length > encoded.len - encoded_overhead) return error.FrameDataTooLarge;
        const is_last_byte = encoded[22 + data_length];
        if (is_last_byte > 1) return error.FrameInvalidIsLast;

        const result: Decoded = .{
            .frame = .{
                .id = encoded[0..16].*,
                .number = std.mem.readInt(u16, encoded[16..18], .big),
                .data = encoded[22..][0..data_length],
                .is_last = is_last_byte == 1,
            },
            .length = encoded_overhead + data_length,
        };
        assert(result.length <= encoded.len);
        assert(result.frame.data.len == data_length);
        return result;
    }
};

/// Iterates the frames of one batcher transaction payload (`version ++ frame*`).
/// A payload is all-or-nothing: callers must collect every frame before using any,
/// because the spec drops the whole payload when any frame fails to decode.
pub const FrameIterator = struct {
    data: []const u8,
    offset: u32,

    pub fn init(encoded: []const u8) ParseError!FrameIterator {
        if (encoded.len == 0) return error.NoFrames;
        if (encoded[0] != derivation_version_0) return error.UnsupportedVersion;
        if (encoded.len == 1) return error.NoFrames;
        assert(encoded.len <= std.math.maxInt(u32));
        return .{ .data = encoded[1..], .offset = 0 };
    }

    pub fn next(iterator: *FrameIterator) DecodeError!?Frame {
        assert(iterator.offset <= iterator.data.len);
        if (iterator.offset == iterator.data.len) return null;
        const decoded = try Frame.decode(iterator.data[iterator.offset..]);
        assert(decoded.length >= Frame.encoded_overhead);
        iterator.offset += decoded.length;
        return decoded.frame;
    }
};

/// Parses every frame in a batcher payload into `out`. Fails the whole payload on any
/// error (matching the spec), or with `error.TooManyFrames` when `out` is full.
pub const ParseFramesError = ParseError || error{TooManyFrames};

pub fn parse_frames(encoded: []const u8, out: []Frame) ParseFramesError![]Frame {
    var iterator = try FrameIterator.init(encoded);
    var count: usize = 0;
    // Each frame consumes at least `encoded_overhead` bytes, bounding the loop.
    const iterations_max = encoded.len / Frame.encoded_overhead + 1;
    for (0..iterations_max) |_| {
        const frame = try iterator.next() orelse break;
        if (count == out.len) return error.TooManyFrames;
        out[count] = frame;
        count += 1;
    } else unreachable; // Proof: iterations_max exceeds the frame count bound above.
    if (count == 0) return error.NoFrames;
    assert(iterator.offset == iterator.data.len);
    return out[0..count];
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "frame: encode/decode roundtrip" {
    const data = @as([50]u8, @splat(0xdd));
    const frame: Frame = .{ .id = @splat(0xff), .number = 0xee, .data = &data, .is_last = true };
    var buffer: [128]u8 = undefined;
    const encoded = frame.encode(&buffer);
    try testing.expectEqual(@as(usize, 73), encoded.len);
    const decoded = try Frame.decode(encoded);
    try testing.expectEqual(@as(u32, 73), decoded.length);
    try testing.expectEqualSlices(u8, &frame.id, &decoded.frame.id);
    try testing.expectEqual(frame.number, decoded.frame.number);
    try testing.expectEqualSlices(u8, frame.data, decoded.frame.data);
    try testing.expect(decoded.frame.is_last);
}

test "frame: too short" {
    const data = @as([22]u8, @splat(0xdd));
    const frame: Frame = .{ .id = @splat(0xff), .number = 1, .data = &data, .is_last = true };
    var buffer: [64]u8 = undefined;
    const encoded = frame.encode(&buffer);
    try testing.expectError(error.FrameTooShort, Frame.decode(encoded[0..22]));
}

test "frame: malicious data length" {
    const data = @as([50]u8, @splat(0xdd));
    const frame: Frame = .{ .id = @splat(0xff), .number = 1, .data = &data, .is_last = false };
    var buffer: [128]u8 = undefined;
    const encoded = frame.encode(&buffer);
    // One more than the available bytes after the header: there is no is_last byte.
    std.mem.writeInt(u32, encoded[18..22], @intCast(encoded.len - 22), .big);
    try testing.expectError(error.FrameDataTooLarge, Frame.decode(encoded));
    std.mem.writeInt(u32, encoded[18..22], Frame.frame_data_length_max + 1, .big);
    try testing.expectError(error.FrameDataTooLarge, Frame.decode(encoded));
    std.mem.writeInt(u32, encoded[18..22], 50, .big);
    _ = try Frame.decode(encoded);
}

test "frame: is_last must be 0 or 1" {
    const frame: Frame = .{ .id = @splat(1), .number = 0, .data = "abc", .is_last = false };
    var buffer: [64]u8 = undefined;
    const encoded = frame.encode(&buffer);
    encoded[encoded.len - 1] = 2;
    try testing.expectError(error.FrameInvalidIsLast, Frame.decode(encoded));
}

test "frame: parse many" {
    const data = @as([50]u8, @splat(0xdd));
    const frame: Frame = .{ .id = @splat(0xff), .number = 0xee, .data = &data, .is_last = true };
    var payload: [1 + 5 * 73]u8 = undefined;
    payload[0] = derivation_version_0;
    for (0..5) |i| _ = frame.encode(payload[1 + i * 73 ..]);
    var frames: [8]Frame = undefined;
    const parsed = try parse_frames(&payload, &frames);
    try testing.expectEqual(@as(usize, 5), parsed.len);
    for (parsed) |f| try testing.expectEqualSlices(u8, &data, f.data);

    try testing.expectError(error.TooManyFrames, parse_frames(&payload, frames[0..4]));
    payload[0] = 1;
    try testing.expectError(error.UnsupportedVersion, parse_frames(&payload, &frames));
    try testing.expectError(error.NoFrames, parse_frames(&.{}, &frames));
    try testing.expectError(error.NoFrames, parse_frames(&.{0}, &frames));
    payload[0] = 0;
    const truncated = payload[0 .. payload.len - 1];
    try testing.expectError(error.FrameDataTooLarge, parse_frames(truncated, &frames));
    try testing.expectError(error.FrameTooShort, parse_frames(payload[0 .. 1 + 73 + 10], &frames));
}

fn check_decode(input: []const u8) !void {
    var frames: [64]Frame = undefined;
    const parsed = parse_frames(input, &frames) catch return;
    // Re-encoding every parsed frame reproduces the input exactly.
    var buffer: [4096]u8 = undefined;
    buffer[0] = derivation_version_0;
    var offset: usize = 1;
    for (parsed) |frame| offset += frame.encode(buffer[offset..]).len;
    try testing.expectEqualSlices(u8, input, buffer[0..offset]);
}

test "frame: seeded fuzz roundtrip and decode" {
    var prng = Prng.init(0x46524d45);
    var payload: [4096]u8 = undefined;
    var data: [256]u8 = undefined;
    for (0..2_000) |_| {
        // Valid payloads: random frames, then optionally corrupt one byte.
        payload[0] = derivation_version_0;
        var offset: usize = 1;
        const count = prng.range(1, 8);
        for (0..count) |_| {
            const length = prng.below(data.len);
            prng.fill(data[0..length]);
            var frame: Frame = .{
                .id = undefined,
                .number = prng.int(u16),
                .data = data[0..length],
                .is_last = prng.chance(1, 2),
            };
            prng.fill(&frame.id);
            offset += frame.encode(payload[offset..]).len;
        }
        if (prng.chance(1, 3)) payload[prng.below(offset)] = prng.int(u8);
        try check_decode(payload[0..offset]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "frame: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}
