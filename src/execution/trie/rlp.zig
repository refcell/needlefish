//! Minimal RLP encoding and decoding for trie nodes.
//!
//! The trie needs only byte strings and lists, so this file carries a small, strict subset of
//! RLP (Ethereum Yellow Paper, appendix B). The decoder rejects every non-canonical form, so a
//! node that decodes has exactly one encoding. It never allocates and never recurses.

const std = @import("std");
const assert = std.debug.assert;

/// Longest header: one prefix byte plus an 8-byte big-endian length.
pub const header_length_max = 9;

pub const Kind = enum { string, list };

pub const Item = struct {
    kind: Kind,
    payload: []const u8,
    /// Total encoded length of the item: header plus payload.
    encoded_length: u64,
    /// The whole encoding of the item: header and payload.
    raw: []const u8,
};

pub const DecodeError = error{
    InputTooShort,
    NonCanonicalSize,
    LeadingZeroLength,
    LengthOverflow,
};

fn length_of_length(length: u64) u32 {
    assert(length > 55);
    const bits: u32 = 64 - @as(u32, @clz(length));
    const bytes = (bits + 7) / 8;
    assert(bytes >= 1 and bytes <= 8);
    return bytes;
}

/// Length of the header for a list or string of `payload_length` bytes. A one-byte string below
/// 0x80 has no header; callers handle that case through `string_encoded_length`.
pub fn header_length(payload_length: u64) u32 {
    if (payload_length <= 55) return 1;
    return 1 + length_of_length(payload_length);
}

fn write_header(out: []u8, offset: u8, payload_length: u64) u32 {
    assert(offset == 0x80 or offset == 0xc0);
    if (payload_length <= 55) {
        assert(out.len >= 1);
        out[0] = offset + @as(u8, @intCast(payload_length));
        return 1;
    }
    const bytes = length_of_length(payload_length);
    assert(out.len >= 1 + bytes);
    out[0] = offset + 55 + @as(u8, @intCast(bytes));
    var index: u32 = 0;
    while (index < bytes) : (index += 1) {
        const shift: u6 = @intCast((bytes - 1 - index) * 8);
        out[1 + index] = @truncate(payload_length >> shift);
    }
    return 1 + bytes;
}

pub fn write_list_header(out: []u8, payload_length: u64) u32 {
    return write_header(out, 0xc0, payload_length);
}

/// Writes the header for `bytes` as an RLP string. Returns 0 when the string encodes as itself.
pub fn write_string_header(out: []u8, bytes: []const u8) u32 {
    if (bytes.len == 1 and bytes[0] < 0x80) return 0;
    return write_header(out, 0x80, bytes.len);
}

pub fn string_encoded_length(bytes: []const u8) u64 {
    if (bytes.len == 1 and bytes[0] < 0x80) return 1;
    return header_length(bytes.len) + bytes.len;
}

/// Writes `bytes` as an RLP string into `out`. Returns the number of bytes written.
pub fn write_string(out: []u8, bytes: []const u8) u32 {
    const head = write_string_header(out, bytes);
    assert(out.len >= head + bytes.len);
    @memcpy(out[head..][0..bytes.len], bytes);
    const written: u32 = head + @as(u32, @intCast(bytes.len));
    assert(written == string_encoded_length(bytes));
    return written;
}

fn read_length(input: []const u8, bytes: u32) DecodeError!u64 {
    assert(bytes >= 1 and bytes <= 8);
    if (input.len < 1 + bytes) return error.InputTooShort;
    if (input[1] == 0) return error.LeadingZeroLength;
    var length: u64 = 0;
    for (input[1..][0..bytes]) |byte| length = (length << 8) | byte;
    if (length <= 55) return error.NonCanonicalSize;
    return length;
}

/// Decodes the first item of `input`. Trailing bytes are allowed; see `encoded_length`.
pub fn decode_item(input: []const u8) DecodeError!Item {
    if (input.len == 0) return error.InputTooShort;
    const prefix = input[0];
    var kind: Kind = .string;
    var head: u64 = 1;
    var length: u64 = 0;
    if (prefix < 0x80) {
        const byte = input[0..1];
        return .{ .kind = .string, .payload = byte, .encoded_length = 1, .raw = byte };
    } else if (prefix <= 0xb7) {
        length = prefix - 0x80;
        if (length == 1 and input.len >= 2 and input[1] < 0x80) return error.NonCanonicalSize;
    } else if (prefix <= 0xbf) {
        const bytes: u32 = prefix - 0xb7;
        length = try read_length(input, bytes);
        head += bytes;
    } else if (prefix <= 0xf7) {
        kind = .list;
        length = prefix - 0xc0;
    } else {
        kind = .list;
        const bytes: u32 = prefix - 0xf7;
        length = try read_length(input, bytes);
        head += bytes;
    }
    if (length > input.len) return error.InputTooShort;
    if (head + length > input.len) return error.InputTooShort;
    const start: usize = @intCast(head);
    const end: usize = @intCast(head + length);
    assert(end <= input.len);
    return .{
        .kind = kind,
        .payload = input[start..end],
        .encoded_length = head + length,
        .raw = input[0..end],
    };
}

/// Splits a list payload into at most `out.len` items. Returns the item count, or an error if
/// the payload holds more items than fit or is malformed.
pub fn decode_list(payload: []const u8, out: []Item) (DecodeError || error{TooManyItems})!u32 {
    var offset: usize = 0;
    var count: u32 = 0;
    while (offset < payload.len) {
        if (count == out.len) return error.TooManyItems;
        const item = try decode_item(payload[offset..]);
        assert(item.encoded_length > 0);
        out[count] = item;
        count += 1;
        offset += @intCast(item.encoded_length);
    }
    assert(offset == payload.len);
    return count;
}

const testing = std.testing;

test "rlp: string encodings" {
    var buffer: [80]u8 = undefined;
    try testing.expectEqual(@as(u32, 1), write_string(&buffer, &.{0x7f}));
    try testing.expectEqual(@as(u8, 0x7f), buffer[0]);
    try testing.expectEqual(@as(u32, 2), write_string(&buffer, &.{0x80}));
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x80 }, buffer[0..2]);
    try testing.expectEqual(@as(u32, 1), write_string(&buffer, &.{}));
    try testing.expectEqual(@as(u8, 0x80), buffer[0]);
    const long: [56]u8 = @splat(0xaa);
    try testing.expectEqual(@as(u32, 58), write_string(&buffer, &long));
    try testing.expectEqualSlices(u8, &.{ 0xb8, 56 }, buffer[0..2]);
}

test "rlp: decode rejects non-canonical forms" {
    try testing.expectError(error.NonCanonicalSize, decode_item(&.{ 0x81, 0x05 }));
    try testing.expectError(error.NonCanonicalSize, decode_item(&.{ 0xb8, 0x05, 0, 0, 0, 0, 0 }));
    try testing.expectError(error.LeadingZeroLength, decode_item(&.{ 0xb9, 0x00, 0x40 }));
    try testing.expectError(error.InputTooShort, decode_item(&.{ 0x83, 0x01 }));
    try testing.expectError(error.InputTooShort, decode_item(&.{}));
    const item = try decode_item(&.{ 0xc2, 0x80, 0x01 });
    try testing.expectEqual(Kind.list, item.kind);
    var items: [4]Item = undefined;
    try testing.expectEqual(@as(u32, 2), try decode_list(item.payload, &items));
}

fn check_roundtrip(payload: []const u8) !void {
    var buffer: [512]u8 = undefined;
    const written = write_string(&buffer, payload);
    const item = try decode_item(buffer[0..written]);
    try testing.expectEqual(Kind.string, item.kind);
    try testing.expectEqualSlices(u8, payload, item.payload);
    try testing.expectEqual(@as(u64, written), item.encoded_length);
}

fn check_decode_any(input: []const u8) !void {
    const item = decode_item(input) catch return;
    try testing.expect(item.encoded_length <= input.len);
    try testing.expect(item.payload.len <= item.encoded_length);
    if (item.kind == .string) {
        var buffer: [600]u8 = undefined;
        if (item.payload.len > 500) return;
        const written = write_string(&buffer, item.payload);
        try testing.expectEqualSlices(u8, input[0..written], buffer[0..written]);
    }
}

test "rlp: seeded fuzz roundtrip and canonical decode" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7219);
    var payload: [300]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < 2000) : (iteration += 1) {
        const length = prng.below(payload.len + 1);
        prng.fill(payload[0..length]);
        try check_roundtrip(payload[0..length]);
        try check_decode_any(payload[0..@min(length, 64)]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [256]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode_any(input[0..length]);
}

test "rlp: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}
