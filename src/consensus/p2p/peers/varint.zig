//! Unsigned LEB128 varints as used by multiformats (multiaddr, multihash), libp2p
//! framing, and the OP Stack `opstack` ENR value. The multiformats spec caps a varint
//! at 9 bytes (63 bits of payload); we accept any minimal encoding of a `u64` up to
//! 10 bytes but reject non-minimal encodings (trailing zero groups) so every value
//! has exactly one encoding.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The input ended before the final (high-bit clear) byte.
    Truncated,
    /// The value does not fit in a `u64`.
    Overflow,
    /// The encoding has a redundant trailing zero group.
    NonMinimal,
};

/// Longest encoding of a `u64`.
pub const length_max = 10;

pub const Decoded = struct {
    value: u64,
    /// Bytes consumed, `1..length_max`.
    length: u8,
};

/// Number of bytes `value` encodes to.
pub fn encoded_length(value: u64) u8 {
    var remaining = value;
    var length: u8 = 1;
    while (remaining >= 0x80) : (length += 1) remaining >>= 7;
    assert(length >= 1);
    assert(length <= length_max);
    return length;
}

/// Encodes `value` into the front of `output`, returning the written prefix.
pub fn encode(output: []u8, value: u64) []u8 {
    const length = encoded_length(value);
    assert(output.len >= length);
    var remaining = value;
    var index: usize = 0;
    while (index < length) : (index += 1) {
        const group: u8 = @truncate(remaining & 0x7f);
        remaining >>= 7;
        output[index] = if (index + 1 < length) group | 0x80 else group;
    }
    assert(remaining == 0);
    return output[0..length];
}

/// Decodes one varint from the front of `input`.
pub fn decode(input: []const u8) Error!Decoded {
    var value: u64 = 0;
    var index: usize = 0;
    while (index < length_max) : (index += 1) {
        if (index >= input.len) return error.Truncated;
        const byte = input[index];
        const group: u64 = byte & 0x7f;
        if (index == length_max - 1 and group > 1) return error.Overflow;
        value |= group << @intCast(7 * index);
        if (byte & 0x80 == 0) {
            if (index > 0 and byte == 0) return error.NonMinimal;
            const length: u8 = @intCast(index + 1);
            assert(encoded_length(value) == length);
            return .{ .value = value, .length = length };
        }
    }
    return error.Overflow;
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "varint: known encodings" {
    var buffer: [length_max]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{0x00}, encode(&buffer, 0));
    try std.testing.expectEqualSlices(u8, &.{0x7f}, encode(&buffer, 127));
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, encode(&buffer, 128));
    try std.testing.expectEqualSlices(u8, &.{ 0x91, 0x02 }, encode(&buffer, 273));
    try std.testing.expectEqualSlices(u8, &.{ 0xa5, 0x03 }, encode(&buffer, 421));
    try std.testing.expectEqualSlices(u8, &.{ 0x85, 0x42 }, encode(&buffer, 8453));
    try std.testing.expectEqual(@as(u8, 10), encode(&buffer, std.math.maxInt(u64)).len);
}

test "varint: rejects malformed" {
    try std.testing.expectError(error.Truncated, decode(&.{}));
    try std.testing.expectError(error.Truncated, decode(&.{0x80}));
    try std.testing.expectError(error.NonMinimal, decode(&.{ 0x80, 0x00 }));
    var too_big: [10]u8 = @splat(0xff);
    too_big[9] = 0x02;
    try std.testing.expectError(error.Overflow, decode(&too_big));
    const too_long: [11]u8 = @splat(0xff);
    try std.testing.expectError(error.Overflow, decode(&too_long));
}

test "varint: seeded round trip" {
    var prng = Prng.init(0x7661_7269);
    var buffer: [length_max]u8 = undefined;
    for (0..2048) |_| {
        const shift: u6 = @intCast(prng.below(64));
        const value = prng.int(u64) >> shift;
        const encoded = encode(&buffer, value);
        const decoded = try decode(encoded);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(encoded.len, decoded.length);
    }
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    const decoded = decode(input) catch return;
    var buffer: [length_max]u8 = undefined;
    try std.testing.expectEqualSlices(u8, input[0..decoded.length], encode(&buffer, decoded.value));
}

test "varint: fuzz decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 16 });
}
