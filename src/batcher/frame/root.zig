//! Batcher side of channel frames: packs frames into one L1 transaction payload.
//!
//! The frame type and its decoder live in `consensus/protocol/frame.zig` (as in
//! base/base, where the batcher depends on `base-protocol`). This module adds the
//! write path and fuzzes it against the consensus parser, so the batcher can never
//! emit a payload that derivation rejects.
//!
//!   tx_data = derivation_version_0 ++ frame ++ frame ++ ...

const std = @import("std");
const assert = std.debug.assert;
const protocol = @import("../../consensus/protocol/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const Frame = protocol.frame.Frame;
pub const ChannelId = protocol.frame.ChannelId;
pub const derivation_version_0 = protocol.frame.derivation_version_0;
pub const parse_frames = protocol.frame.parse_frames;

/// Bytes `encode_tx_data` writes for `frames`.
pub fn tx_data_length(frames: []const Frame) u64 {
    var total: u64 = 1;
    for (frames) |*frame| total += frame.encoded_length();
    assert(total >= 1 + @as(u64, frames.len) * Frame.encoded_overhead);
    return total;
}

/// Encodes `frames` as one batcher transaction payload into `out`; returns bytes used.
pub fn encode_tx_data(frames: []const Frame, out: []u8) []u8 {
    assert(frames.len > 0);
    const length = tx_data_length(frames);
    assert(out.len >= length);
    out[0] = derivation_version_0;
    var offset: usize = 1;
    for (frames) |*frame| offset += frame.encode(out[offset..]).len;
    assert(offset == length);
    return out[0..offset];
}

const testing = std.testing;

test "frame: encode_tx_data parses back" {
    const frames = [_]Frame{
        .{ .id = @splat(1), .number = 0, .data = "abc", .is_last = false },
        .{ .id = @splat(1), .number = 1, .data = "", .is_last = true },
    };
    var buffer: [128]u8 = undefined;
    const encoded = encode_tx_data(&frames, &buffer);
    try testing.expectEqual(@as(usize, 1 + 23 + 3 + 23), encoded.len);
    try testing.expectEqual(derivation_version_0, encoded[0]);
    var out: [4]Frame = undefined;
    const parsed = try parse_frames(encoded, &out);
    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqualStrings("abc", parsed[0].data);
    try testing.expect(parsed[1].is_last);
}

/// Anything the consensus parser accepts must re-encode to the identical bytes.
fn check_parse_roundtrip(input: []const u8) !void {
    var frames: [64]Frame = undefined;
    const parsed = parse_frames(input, &frames) catch return;
    var buffer: [4096]u8 = undefined;
    if (tx_data_length(parsed) > buffer.len) return;
    try testing.expectEqualSlices(u8, input, encode_tx_data(parsed, &buffer));
}

test "frame: seeded fuzz encode/parse" {
    var prng = Prng.init(0x6672616d65);
    var input: [512]u8 = undefined;
    for (0..2_000) |_| {
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
        var n = encode_tx_data(frames[0..frame_count], &input).len;
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

test "frame: fuzz parse/encode" {
    try testing.fuzz({}, fuzz_parse, .{});
}
