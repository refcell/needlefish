//! Strict, zero-copy RLP decoder over a byte slice.
//!
//! Every decoded byte string is a slice of the input. The decoder enforces canonical
//! encoding: single bytes below 0x80 must not carry a header, short payloads must use
//! the short form, long-form lengths have no leading zeros, and integers have no
//! leading zero bytes. Lists are entered by creating a child decoder over the list
//! payload, so nesting needs no recursion and no stack.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The input ended inside an item.
    UnexpectedEnd,
    /// A non-minimal header (wrong form or leading zeros in the length).
    NonCanonicalSize,
    /// An integer with leading zero bytes, or a single byte that should be bare.
    NonCanonicalInteger,
    /// Expected a list, found a string.
    ExpectedList,
    /// Expected a string, found a list.
    ExpectedString,
    /// The value does not fit the requested type or size.
    Overflow,
    /// Bytes remain after the last expected item.
    TrailingBytes,
};

pub const Header = struct {
    list: bool,
    /// Bytes taken by the header itself (0 for a bare single byte).
    header_length: usize,
    payload_length: usize,

    pub fn total_length(header: Header) usize {
        return header.header_length + header.payload_length;
    }
};

/// Decodes the header of the item at the start of `input` and checks it fits.
pub fn decode_header(input: []const u8) Error!Header {
    if (input.len == 0) return error.UnexpectedEnd;
    const prefix = input[0];
    const header: Header = switch (prefix) {
        0x00...0x7f => .{ .list = false, .header_length = 0, .payload_length = 1 },
        0x80...0xb7 => .{ .list = false, .header_length = 1, .payload_length = prefix - 0x80 },
        0xb8...0xbf => try decode_long(input, false, prefix - 0xb7),
        0xc0...0xf7 => .{ .list = true, .header_length = 1, .payload_length = prefix - 0xc0 },
        0xf8...0xff => try decode_long(input, true, prefix - 0xf7),
    };
    if (header.payload_length > input.len - header.header_length) return error.UnexpectedEnd;
    // A one-byte string below 0x80 must be encoded as the bare byte.
    if (!header.list and header.header_length == 1 and header.payload_length == 1) {
        if (input[1] < 0x80) return error.NonCanonicalInteger;
    }
    return header;
}

fn decode_long(input: []const u8, list: bool, size: u8) Error!Header {
    assert(size >= 1 and size <= 8);
    if (input.len < 1 + @as(usize, size)) return error.UnexpectedEnd;
    const length_bytes = input[1 .. 1 + size];
    if (length_bytes[0] == 0) return error.NonCanonicalSize;
    var length: u64 = 0;
    for (length_bytes) |b| length = (length << 8) | b;
    if (length <= 55) return error.NonCanonicalSize;
    if (length > input.len) return error.UnexpectedEnd;
    return .{ .list = list, .header_length = 1 + size, .payload_length = @intCast(length) };
}

pub const Decoder = struct {
    input: []const u8,
    position: usize,

    pub fn init(input: []const u8) Decoder {
        return .{ .input = input, .position = 0 };
    }

    pub fn is_empty(decoder: *const Decoder) bool {
        assert(decoder.position <= decoder.input.len);
        return decoder.position == decoder.input.len;
    }

    pub fn rest(decoder: *const Decoder) []const u8 {
        return decoder.input[decoder.position..];
    }

    /// Errors unless every byte was consumed.
    pub fn finish(decoder: *const Decoder) Error!void {
        if (!decoder.is_empty()) return error.TrailingBytes;
    }

    pub fn peek_header(decoder: *const Decoder) Error!Header {
        return decode_header(decoder.rest());
    }

    /// Returns the next item, including its header, and advances past it.
    pub fn raw(decoder: *Decoder) Error![]const u8 {
        const header = try decoder.peek_header();
        const item = decoder.rest()[0..header.total_length()];
        decoder.position += item.len;
        assert(decoder.position <= decoder.input.len);
        return item;
    }

    /// Returns the payload of the next string item.
    pub fn bytes(decoder: *Decoder) Error![]const u8 {
        const header = try decoder.peek_header();
        if (header.list) return error.ExpectedString;
        const payload = decoder.rest()[header.header_length..header.total_length()];
        decoder.position += header.total_length();
        assert(payload.len == header.payload_length);
        return payload;
    }

    /// Returns a string item that must be exactly `size` bytes.
    pub fn fixed(decoder: *Decoder, comptime size: usize) Error![size]u8 {
        const payload = try decoder.bytes();
        if (payload.len != size) return error.Overflow;
        return payload[0..size].*;
    }

    /// Returns a decoder over the payload of the next list item.
    pub fn list(decoder: *Decoder) Error!Decoder {
        const header = try decoder.peek_header();
        if (!header.list) return error.ExpectedList;
        const payload = decoder.rest()[header.header_length..header.total_length()];
        decoder.position += header.total_length();
        return Decoder.init(payload);
    }

    /// Decodes a canonical unsigned integer of type `T`.
    pub fn int(decoder: *Decoder, comptime T: type) Error!T {
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        comptime assert(@bitSizeOf(T) <= 256);
        const payload = try decoder.bytes();
        if (payload.len > 0 and payload[0] == 0) return error.NonCanonicalInteger;
        if (payload.len > (@bitSizeOf(T) + 7) / 8) return error.Overflow;
        var value: u256 = 0;
        for (payload) |b| value = (value << 8) | b;
        if (value > std.math.maxInt(T)) return error.Overflow;
        return @intCast(value);
    }

    pub fn boolean(decoder: *Decoder) Error!bool {
        return switch (try decoder.int(u8)) {
            0 => false,
            1 => true,
            else => error.Overflow,
        };
    }
};

/// Walks every item of `input` (a sequence of items), entering lists with an
/// explicit bounded stack. Validates structure only. Returns the item count.
pub fn validate(input: []const u8, depth_max: comptime_int) (Error || error{TooDeep})!usize {
    var stack: [depth_max]Decoder = undefined;
    stack[0] = Decoder.init(input);
    var depth: usize = 1;
    var count: usize = 0;
    // Each iteration consumes at least one byte or pops a level: bounded by 2 * len + 1.
    var iterations: usize = 0;
    while (depth > 0) : (iterations += 1) {
        assert(iterations <= 2 * input.len + 1);
        const top = &stack[depth - 1];
        if (top.is_empty()) {
            depth -= 1;
            continue;
        }
        const header = try top.peek_header();
        count += 1;
        if (header.list) {
            const child = try top.list();
            if (depth == depth_max) return error.TooDeep;
            stack[depth] = child;
            depth += 1;
        } else {
            _ = try top.bytes();
        }
    }
    return count;
}

const testing = std.testing;

test "decode: headers and canonical checks" {
    try testing.expectEqual(@as(usize, 1), (try decode_header(&.{0x05})).payload_length);
    try testing.expectError(error.NonCanonicalInteger, decode_header(&.{ 0x81, 0x05 }));
    try testing.expectError(error.NonCanonicalSize, decode_header("\xb8\x05abcde"));
    try testing.expectError(error.NonCanonicalSize, decode_header(&.{ 0xb9, 0x00, 0x40 }));
    try testing.expectError(error.UnexpectedEnd, decode_header(&.{ 0x83, 'a' }));
    try testing.expectError(error.UnexpectedEnd, decode_header(&.{}));
    try testing.expectError(error.UnexpectedEnd, decode_header(&.{0xb8}));
}

test "decode: items" {
    var decoder = Decoder.init("\xc8\x83cat\x83dog\x82\x04\x00");
    var items = try decoder.list();
    try testing.expectEqualStrings("cat", try items.bytes());
    try testing.expectEqualStrings("dog", try items.bytes());
    try items.finish();
    try testing.expectEqual(@as(u16, 1024), try decoder.int(u16));
    try decoder.finish();

    var bad = Decoder.init(&.{ 0x82, 0x00, 0x01 });
    try testing.expectError(error.NonCanonicalInteger, bad.int(u64));
    bad = Decoder.init(&.{ 0x82, 0x01, 0x00 });
    try testing.expectError(error.Overflow, bad.int(u8));
    bad = Decoder.init(&.{0xc0});
    try testing.expectError(error.ExpectedString, bad.bytes());
    bad = Decoder.init(&.{0x80});
    try testing.expectError(error.ExpectedList, bad.list());
}
