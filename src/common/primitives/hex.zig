//! Hex encoding and decoding into caller-provided buffers. No allocation.
//!
//! Decoding accepts an optional `0x`/`0X` prefix and both letter cases. Encoding
//! always produces lowercase. Decoding is table driven: one lookup per nibble and a
//! single branch-free validity accumulator per input, so invalid input costs the same
//! as valid input and the hot loop has no data-dependent branches.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The input had an odd number of hex digits.
    OddLength,
    /// The input contained a character outside `[0-9a-fA-F]`.
    InvalidCharacter,
    /// The output buffer length does not match the decoded length.
    InvalidLength,
};

const alphabet = "0123456789abcdef";

/// Maps an ASCII byte to its nibble value, or 0xff when invalid.
const nibble_table: [256]u8 = table: {
    var table: [256]u8 = @splat(0xff);
    for (0..10) |i| table['0' + i] = i;
    for (0..6) |i| {
        table['a' + i] = 10 + i;
        table['A' + i] = 10 + i;
    }
    break :table table;
};

/// Maps a byte to its two lowercase hex digits, as one little-endian u16.
const pair_table: [256][2]u8 = table: {
    var table: [256][2]u8 = undefined;
    for (0..256) |i| table[i] = .{ alphabet[i >> 4], alphabet[i & 0xf] };
    break :table table;
};

/// Returns `input` without a leading `0x` or `0X`.
pub fn strip_prefix(input: []const u8) []const u8 {
    if (input.len >= 2 and input[0] == '0' and (input[1] == 'x' or input[1] == 'X')) {
        return input[2..];
    }
    return input;
}

/// Number of bytes `input` decodes to (after stripping an optional prefix).
pub fn decoded_length(input: []const u8) Error!usize {
    const digits = strip_prefix(input);
    if (digits.len % 2 != 0) return error.OddLength;
    return digits.len / 2;
}

/// Decodes `input` (optional `0x` prefix) into exactly `output`.
pub fn decode(output: []u8, input: []const u8) Error!void {
    const digits = strip_prefix(input);
    if (digits.len % 2 != 0) return error.OddLength;
    if (digits.len / 2 != output.len) return error.InvalidLength;
    var invalid: u8 = 0;
    for (output, 0..) |*byte, i| {
        const high = nibble_table[digits[2 * i]];
        const low = nibble_table[digits[2 * i + 1]];
        // 0xff marks invalid; any invalid nibble sets bit 7 in the accumulator.
        invalid |= high | low;
        byte.* = (high << 4) | (low & 0x0f);
    }
    if (invalid & 0x80 != 0) return error.InvalidCharacter;
    return;
}

/// Decodes `input` into a fixed-size array; length must match exactly.
pub fn decode_array(comptime size: usize, input: []const u8) Error![size]u8 {
    var output: [size]u8 = undefined;
    try decode(&output, input);
    return output;
}

/// Decodes `input` into the prefix of `buffer` and returns the decoded slice.
pub fn decode_into(buffer: []u8, input: []const u8) Error![]u8 {
    const size = try decoded_length(input);
    if (size > buffer.len) return error.InvalidLength;
    try decode(buffer[0..size], input);
    return buffer[0..size];
}

/// Encodes `input` as lowercase hex (no prefix) into exactly `output`.
pub fn encode(output: []u8, input: []const u8) void {
    assert(output.len == input.len * 2);
    for (input, 0..) |byte, i| {
        output[2 * i ..][0..2].* = pair_table[byte];
    }
    assert(output.len == 0 or output[0] != 0);
}

/// Encodes `input` as `0x`-prefixed lowercase hex into exactly `output`.
pub fn encode_prefixed(output: []u8, input: []const u8) void {
    assert(output.len == input.len * 2 + 2);
    output[0] = '0';
    output[1] = 'x';
    encode(output[2..], input);
}

/// Encodes a fixed-size array as `0x`-prefixed hex, returned by value.
pub fn encode_array(comptime size: usize, input: [size]u8) [size * 2 + 2]u8 {
    var output: [size * 2 + 2]u8 = undefined;
    encode_prefixed(&output, &input);
    return output;
}

/// Encodes a quantity (JSON-RPC style): `0x` prefix, no leading zeros, `0x0` for zero.
/// Returns the written prefix of `buffer`, which must hold at least 66 bytes.
pub fn encode_quantity(buffer: []u8, value: u256) []u8 {
    assert(buffer.len >= 66);
    buffer[0] = '0';
    buffer[1] = 'x';
    if (value == 0) {
        buffer[2] = '0';
        return buffer[0..3];
    }
    const nibbles: usize = (256 - @as(usize, @clz(value)) + 3) / 4;
    assert(nibbles >= 1 and nibbles <= 64);
    var remaining = value;
    var i: usize = nibbles;
    while (i > 0) : (i -= 1) {
        buffer[1 + i] = alphabet[@as(u4, @truncate(remaining))];
        remaining >>= 4;
    }
    assert(remaining == 0);
    return buffer[0 .. 2 + nibbles];
}

pub const QuantityError = error{
    /// Missing `0x` prefix, empty digits, or a leading zero digit.
    InvalidQuantity,
    InvalidCharacter,
    Overflow,
};

/// Decodes a JSON-RPC quantity into an unsigned integer of type `T`.
/// Strict: requires `0x`, at least one digit, and no leading zeros (except `0x0`).
pub fn decode_quantity(comptime T: type, input: []const u8) QuantityError!T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    if (input.len < 3 or input[0] != '0' or (input[1] != 'x' and input[1] != 'X')) {
        return error.InvalidQuantity;
    }
    const digits = input[2..];
    if (digits.len > 1 and digits[0] == '0') return error.InvalidQuantity;
    if (digits.len > (@bitSizeOf(T) + 3) / 4) return error.Overflow;
    var value: u256 = 0;
    for (digits) |c| {
        const nibble = nibble_table[c];
        if (nibble == 0xff) return error.InvalidCharacter;
        value = (value << 4) | nibble;
    }
    if (value > std.math.maxInt(T)) return error.Overflow;
    return @intCast(value);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "hex: encode and decode known values" {
    var out: [8]u8 = undefined;
    encode(&out, &.{ 0xde, 0xad, 0xbe, 0xef });
    try testing.expectEqualStrings("deadbeef", &out);
    const decoded = try decode_array(4, "0xDeAdBeEf");
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &decoded);
    try testing.expectEqualSlices(u8, &.{}, &(try decode_array(0, "0x")));
    try testing.expectEqualStrings("0x0001ff", &encode_array(3, .{ 0, 1, 0xff }));
}

test "hex: decode errors" {
    var out: [2]u8 = undefined;
    try testing.expectError(error.OddLength, decode(&out, "0x123"));
    try testing.expectError(error.InvalidLength, decode(&out, "0x12"));
    try testing.expectError(error.InvalidCharacter, decode(&out, "0x12g4"));
    try testing.expectError(error.InvalidCharacter, decode(&out, "zz00"));
    var buffer: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, try decode_into(&buffer, "0102"));
    try testing.expectError(error.InvalidLength, decode_into(&buffer, "0102030405"));
}

test "hex: quantities" {
    var buffer: [66]u8 = undefined;
    try testing.expectEqualStrings("0x0", encode_quantity(&buffer, 0));
    try testing.expectEqualStrings("0x1", encode_quantity(&buffer, 1));
    try testing.expectEqualStrings("0x400", encode_quantity(&buffer, 1024));
    const max = encode_quantity(&buffer, std.math.maxInt(u256));
    try testing.expectEqual(@as(usize, 66), max.len);
    try testing.expectEqual(@as(u64, 1024), try decode_quantity(u64, "0x400"));
    try testing.expectEqual(@as(u64, 0), try decode_quantity(u64, "0x0"));
    try testing.expectError(error.InvalidQuantity, decode_quantity(u64, "0x"));
    try testing.expectError(error.InvalidQuantity, decode_quantity(u64, "0x01"));
    try testing.expectError(error.InvalidQuantity, decode_quantity(u64, "400"));
    try testing.expectError(error.Overflow, decode_quantity(u8, "0x100"));
    try testing.expectError(error.Overflow, decode_quantity(u8, "0x10000000000000000"));
    try testing.expectError(error.InvalidCharacter, decode_quantity(u64, "0xg"));
}

fn check_round_trip(data: []const u8) !void {
    var encoded: [2 * 256 + 2]u8 = undefined;
    const text = encoded[0 .. data.len * 2 + 2];
    encode_prefixed(text, data);
    var decoded: [256]u8 = undefined;
    const back = try decode_into(&decoded, text);
    try testing.expectEqualSlices(u8, data, back);
}

test "hex: seeded fuzz round trip" {
    var prng = Prng.init(0x4e58);
    var data: [256]u8 = undefined;
    for (0..2000) |_| {
        const len = prng.below(data.len + 1);
        prng.fill(data[0..len]);
        try check_round_trip(data[0..len]);
        var buffer: [66]u8 = undefined;
        const value = prng.int(u256) >> @intCast(prng.below(256));
        try testing.expectEqual(value, try decode_quantity(u256, encode_quantity(&buffer, value)));
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    var buffer: [256]u8 = undefined;
    const decoded = decode_into(&buffer, input[0..len]) catch return;
    try check_round_trip(decoded);
    _ = decode_quantity(u256, input[0..len]) catch return;
}

test "hex: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}
