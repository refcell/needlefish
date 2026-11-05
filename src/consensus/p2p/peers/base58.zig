//! Base58btc (Bitcoin alphabet) encoding into caller buffers, used for the text form of
//! libp2p peer ids. Inputs are tiny (a secp256k1 peer id is 39 bytes), so the quadratic
//! schoolbook conversion is fine; the input length is bounded by `input_length_max` so
//! every loop has a fixed upper bound.

const std = @import("std");
const assert = std.debug.assert;

pub const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Largest decoded payload supported. Multihash peer ids are at most ~70 bytes.
pub const input_length_max = 128;
/// Base58 expands by log(256)/log(58) ~= 1.366; this bounds the text length.
pub const encoded_length_max = input_length_max * 138 / 100 + 1;

pub const Error = error{
    InvalidCharacter,
    /// Input or output exceeds the bounds above or the caller buffer.
    TooLong,
};

const digit_table: [256]u8 = table: {
    var table: [256]u8 = @splat(0xff);
    for (alphabet, 0..) |character, index| table[character] = index;
    break :table table;
};

comptime {
    assert(alphabet.len == 58);
}

/// Encodes `input` into `output`, returning the written prefix.
pub fn encode(output: []u8, input: []const u8) Error![]u8 {
    if (input.len > input_length_max) return error.TooLong;
    var digits: [encoded_length_max]u8 = undefined;
    var digits_length: usize = 0;
    for (input) |byte| {
        var carry: u32 = byte;
        for (digits[0..digits_length]) |*digit| {
            carry += @as(u32, digit.*) << 8;
            digit.* = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) : (carry /= 58) {
            assert(digits_length < digits.len);
            digits[digits_length] = @intCast(carry % 58);
            digits_length += 1;
        }
    }
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == 0) zeros += 1;
    const length = zeros + digits_length;
    if (length > output.len) return error.TooLong;
    @memset(output[0..zeros], '1');
    for (0..digits_length) |index| {
        output[zeros + index] = alphabet[digits[digits_length - 1 - index]];
    }
    return output[0..length];
}

/// Decodes `input` into `output`, returning the written prefix.
pub fn decode(output: []u8, input: []const u8) Error![]u8 {
    if (input.len > encoded_length_max) return error.TooLong;
    var bytes: [encoded_length_max]u8 = undefined;
    var bytes_length: usize = 0;
    for (input) |character| {
        const digit = digit_table[character];
        if (digit == 0xff) return error.InvalidCharacter;
        var carry: u32 = digit;
        for (bytes[0..bytes_length]) |*byte| {
            carry += @as(u32, byte.*) * 58;
            byte.* = @truncate(carry);
            carry >>= 8;
        }
        while (carry > 0) : (carry >>= 8) {
            assert(bytes_length < bytes.len);
            bytes[bytes_length] = @truncate(carry);
            bytes_length += 1;
        }
    }
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == '1') zeros += 1;
    const length = zeros + bytes_length;
    if (length > output.len or length > input_length_max) return error.TooLong;
    @memset(output[0..zeros], 0);
    for (0..bytes_length) |index| output[zeros + index] = bytes[bytes_length - 1 - index];
    return output[0..length];
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "base58: known vectors" {
    // From the IETF base58 draft.
    var buffer: [encoded_length_max]u8 = undefined;
    try std.testing.expectEqualStrings("2NEpo7TZRRrLZSi2U", try encode(&buffer, "Hello World!"));
    const leading_zeros = [_]u8{ 0, 0, 0x28, 0x7f, 0xb4, 0xcd };
    try std.testing.expectEqualStrings("11233QC4", try encode(&buffer, &leading_zeros));
    try std.testing.expectEqualStrings("", try encode(&buffer, ""));
    var decoded: [input_length_max]u8 = undefined;
    try std.testing.expectEqualStrings("Hello World!", try decode(&decoded, "2NEpo7TZRRrLZSi2U"));
    try std.testing.expectError(error.InvalidCharacter, decode(&decoded, "0OIl"));
}

test "base58: seeded round trip" {
    var prng = Prng.init(0x6235_38);
    var input: [input_length_max]u8 = undefined;
    var text: [encoded_length_max]u8 = undefined;
    var output: [input_length_max]u8 = undefined;
    for (0..512) |_| {
        const length: usize = @intCast(prng.below(input_length_max + 1));
        prng.fill(input[0..length]);
        const zeros: usize = @intCast(prng.below(@min(length, 4) + 1));
        @memset(input[0..zeros], 0);
        const encoded = try encode(&text, input[0..length]);
        try std.testing.expectEqualSlices(u8, input[0..length], try decode(&output, encoded));
    }
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var output: [input_length_max]u8 = undefined;
    const decoded = decode(&output, input) catch return;
    var text: [encoded_length_max]u8 = undefined;
    const encoded = try encode(&text, decoded);
    try std.testing.expectEqualStrings(input, encoded);
}

test "base58: fuzz decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 200 });
}
