//! Channel frames: the unit the batcher writes to L1 and derivation reads back.
//!
//! Wire format (OP Stack derivation spec, unchanged in Base):
//!
//!   tx_data = derivation_version_0 ++ frame ++ frame ++ ...
//!   frame   = channel_id(16) ++ frame_number(u16 BE) ++ frame_data_length(u32 BE)
//!             ++ frame_data ++ is_last(u8, 0 or 1)
//!
//! Frames borrow their data from the input buffer; decoding never allocates.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const channel_id_length = 16;
pub const ChannelId = [channel_id_length]u8;

/// Version byte that prefixes every batcher transaction's data.
pub const derivation_version_0: u8 = 0;

/// Fixed bytes per frame: id, number, data length, last flag.
pub const frame_overhead_bytes = channel_id_length + 2 + 4 + 1;

/// Largest frame_data accepted by derivation (`Frame::MAX_LEN` in base/base).
pub const frame_data_length_max = 1_000_000;

comptime {
    assert(frame_overhead_bytes == 23);
    assert(frame_data_length_max < std.math.maxInt(u32));
}

pub const Frame = struct {
    id: ChannelId,
    number: u16,
    data: []const u8,
    is_last: bool,

    pub fn encoded_length(frame: *const Frame) usize {
        assert(frame.data.len <= frame_data_length_max);
        return frame_overhead_bytes + frame.data.len;
    }

    /// Writes the frame into `out` and returns the number of bytes written.
    pub fn encode(frame: *const Frame, out: []u8) usize {
        const length = frame.encoded_length();
        assert(out.len >= length);
        @memcpy(out[0..channel_id_length], &frame.id);
        std.mem.writeInt(u16, out[16..18], frame.number, .big);
        std.mem.writeInt(u32, out[18..22], @intCast(frame.data.len), .big);
        @memcpy(out[22..][0..frame.data.len], frame.data);
        out[22 + frame.data.len] = @intFromBool(frame.is_last);
        assert(22 + frame.data.len + 1 == length);
        return length;
    }
};

pub const DecodeError = error{
    FrameTooShort,
    FrameDataTooLarge,
    FrameInvalidLastFlag,
};

pub const Decoded = struct {
    frame: Frame,
    consumed: usize,
};

/// Decodes one frame from the start of `bytes`. The frame borrows `bytes`.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len < frame_overhead_bytes) return error.FrameTooShort;
    const data_length = std.mem.readInt(u32, bytes[18..22], .big);
    if (data_length > frame_data_length_max) return error.FrameDataTooLarge;
    const total = frame_overhead_bytes + @as(usize, data_length);
    if (bytes.len < total) return error.FrameTooShort;
    const flag = bytes[22 + data_length];
    if (flag > 1) return error.FrameInvalidLastFlag;
    const frame: Frame = .{
        .id = bytes[0..channel_id_length].*,
        .number = std.mem.readInt(u16, bytes[16..18], .big),
        .data = bytes[22..][0..data_length],
        .is_last = flag == 1,
    };
    assert(frame.encoded_length() == total);
    assert(total <= bytes.len);
    return .{ .frame = frame, .consumed = total };
}

pub const ParseError = DecodeError || error{
    NoData,
    UnsupportedVersion,
    TooManyFrames,
};

/// Parses batcher transaction data into `frames_out`. All-or-nothing: any malformed
/// frame rejects the whole transaction, as the derivation spec requires.
pub fn parse_frames(tx_data: []const u8, frames_out: []Frame) ParseError![]Frame {
    assert(frames_out.len > 0);
    if (tx_data.len == 0) return error.NoData;
    if (tx_data[0] != derivation_version_0) return error.UnsupportedVersion;
    var offset: usize = 1;
    var count: usize = 0;
    // Each frame consumes at least frame_overhead_bytes, which bounds the loop.
    while (offset < tx_data.len) {
        if (count == frames_out.len) return error.TooManyFrames;
        const decoded = try decode(tx_data[offset..]);
        assert(decoded.consumed >= frame_overhead_bytes);
        frames_out[count] = decoded.frame;
        count += 1;
        offset += decoded.consumed;
    }
    assert(offset == tx_data.len);
    if (count == 0) return error.NoData;
    return frames_out[0..count];
}

/// Encodes `frames` as one batcher transaction payload into `out`; returns bytes used.
pub fn encode_tx_data(frames: []const Frame, out: []u8) usize {
    assert(frames.len > 0);
    assert(out.len >= tx_data_length(frames));
    out[0] = derivation_version_0;
    var offset: usize = 1;
    for (frames) |*frame| offset += frame.encode(out[offset..]);
    assert(offset == tx_data_length(frames));
    return offset;
}

pub fn tx_data_length(frames: []const Frame) usize {
    var total: usize = 1;
    for (frames) |*frame| total += frame.encoded_length();
    return total;
}

const testing = std.testing;

test "frame: encode/decode round trip" {
    const frame: Frame = .{
        .id = @splat(0xab),
        .number = 0x0102,
        .data = "hello frame",
        .is_last = true,
    };
    var buffer: [64]u8 = undefined;
    const n = frame.encode(&buffer);
    try testing.expectEqual(frame_overhead_bytes + 11, n);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, buffer[16..18]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 11 }, buffer[18..22]);
    try testing.expectEqual(@as(u8, 1), buffer[n - 1]);
    const decoded = try decode(buffer[0..n]);
    try testing.expectEqual(n, decoded.consumed);
    try testing.expectEqualSlices(u8, &frame.id, &decoded.frame.id);
    try testing.expectEqual(frame.number, decoded.frame.number);
    try testing.expectEqualStrings(frame.data, decoded.frame.data);
    try testing.expect(decoded.frame.is_last);
}

test "frame: decode rejects malformed input" {
    var buffer: [frame_overhead_bytes + 4]u8 = @splat(0);
    try testing.expectError(error.FrameTooShort, decode(buffer[0..22]));
    std.mem.writeInt(u32, buffer[18..22], 5, .big);
    try testing.expectError(error.FrameTooShort, decode(&buffer));
    std.mem.writeInt(u32, buffer[18..22], frame_data_length_max + 1, .big);
    try testing.expectError(error.FrameDataTooLarge, decode(&buffer));
    std.mem.writeInt(u32, buffer[18..22], 4, .big);
    buffer[26] = 2;
    try testing.expectError(error.FrameInvalidLastFlag, decode(&buffer));
    buffer[26] = 0;
    const decoded = try decode(&buffer);
    try testing.expect(!decoded.frame.is_last);
}

test "frame: parse_frames multiple frames and errors" {
    const frames = [_]Frame{
        .{ .id = @splat(1), .number = 0, .data = "abc", .is_last = false },
        .{ .id = @splat(1), .number = 1, .data = "", .is_last = true },
    };
    var buffer: [128]u8 = undefined;
    const n = encode_tx_data(&frames, &buffer);
    var out: [4]Frame = undefined;
    const parsed = try parse_frames(buffer[0..n], &out);
    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqualStrings("abc", parsed[0].data);
    try testing.expect(parsed[1].is_last);

    try testing.expectError(error.NoData, parse_frames(&.{}, &out));
    try testing.expectError(error.NoData, parse_frames(&.{0}, &out));
    try testing.expectError(error.UnsupportedVersion, parse_frames(&.{1}, &out));
    try testing.expectError(error.TooManyFrames, parse_frames(buffer[0..n], out[0..1]));
    try testing.expectError(error.FrameTooShort, parse_frames(buffer[0 .. n - 1], &out));
}

/// Shared fuzz body: arbitrary bytes must never crash parsing, and anything that
/// parses must re-encode to the identical bytes.
fn check_parse_roundtrip(input: []const u8) !void {
    var frames: [64]Frame = undefined;
    const parsed = parse_frames(input, &frames) catch return;
    var buffer: [4096]u8 = undefined;
    if (tx_data_length(parsed) > buffer.len) return;
    const n = encode_tx_data(parsed, &buffer);
    try testing.expectEqualSlices(u8, input, buffer[0..n]);
}

test "frame: seeded fuzz parse/encode" {
    var prng = Prng.init(0x6672616d65);
    var input: [512]u8 = undefined;
    for (0..2_000) |_| {
        // Mostly valid tx data with mutations, so the fuzz reaches deep states.
        const frame_count = prng.range(1, 4);
        var frames: [4]Frame = undefined;
        var payload: [4][32]u8 = undefined;
        for (0..frame_count) |i| {
            prng.fill(&payload[i]);
            frames[i] = .{
                .id = @splat(@truncate(prng.int(u8))),
                .number = @truncate(prng.int(u16)),
                .data = payload[i][0..prng.below(33)],
                .is_last = prng.chance(1, 2),
            };
        }
        var n = encode_tx_data(frames[0..frame_count], &input);
        if (prng.chance(1, 3)) input[prng.below(n)] = prng.int(u8);
        if (prng.chance(1, 4)) n = prng.below(n + 1);
        try check_parse_roundtrip(input[0..n]);
    }
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const n = smith.slice(&input);
    try check_parse_roundtrip(input[0..n]);
}

test "frame: fuzz parse" {
    try testing.fuzz({}, fuzz_parse, .{});
}
