//! RLP encoder writing into a caller-provided buffer. No allocation.
//!
//! Callers compute the exact encoded size up front with the `*_length` functions,
//! size the buffer once, then write. Writing past the end is a programming error and
//! trips an assertion: a mis-sized buffer means a length function disagrees with the
//! encoder, which is a bug, never a runtime condition.

const std = @import("std");
const assert = std.debug.assert;

/// Payloads up to this length use the short (single byte) header form.
pub const short_payload_max = 55;

/// Number of big-endian bytes needed to represent `value` (0 for zero).
pub fn byte_length(value: anytype) usize {
    const T = @TypeOf(value);
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    if (value == 0) return 0;
    return (@bitSizeOf(T) - @as(usize, @clz(value)) + 7) / 8;
}

/// Length of the header that precedes a string or list payload of `payload_length`.
pub fn header_length(payload_length: usize) usize {
    if (payload_length <= short_payload_max) return 1;
    return 1 + byte_length(@as(u64, payload_length));
}

/// Encoded length of a byte string.
pub fn bytes_length(bytes: []const u8) usize {
    if (bytes.len == 1 and bytes[0] < 0x80) return 1;
    return header_length(bytes.len) + bytes.len;
}

/// Encoded length of an unsigned integer (minimal big-endian byte string).
pub fn int_length(value: anytype) usize {
    const size = byte_length(value);
    if (size == 0) return 1;
    if (size == 1 and value < 0x80) return 1;
    assert(size <= 32);
    return 1 + size;
}

/// Encoded length of a list whose items encode to `payload_length` bytes.
pub fn list_length(payload_length: usize) usize {
    return header_length(payload_length) + payload_length;
}

pub const Encoder = struct {
    buffer: []u8,
    position: usize,

    pub fn init(buffer: []u8) Encoder {
        return .{ .buffer = buffer, .position = 0 };
    }

    /// The bytes written so far.
    pub fn written(encoder: *const Encoder) []u8 {
        assert(encoder.position <= encoder.buffer.len);
        return encoder.buffer[0..encoder.position];
    }

    pub fn remaining(encoder: *const Encoder) usize {
        assert(encoder.position <= encoder.buffer.len);
        return encoder.buffer.len - encoder.position;
    }

    /// Appends already-encoded bytes verbatim.
    pub fn raw(encoder: *Encoder, data: []const u8) void {
        assert(data.len <= encoder.remaining());
        @memcpy(encoder.buffer[encoder.position..][0..data.len], data);
        encoder.position += data.len;
    }

    fn byte(encoder: *Encoder, value: u8) void {
        assert(encoder.remaining() >= 1);
        encoder.buffer[encoder.position] = value;
        encoder.position += 1;
    }

    /// Writes `value` big-endian in exactly `size` bytes.
    fn big_endian(encoder: *Encoder, value: u64, size: usize) void {
        assert(size <= 8);
        assert(size == byte_length(value));
        var i: usize = size;
        while (i > 0) : (i -= 1) {
            encoder.byte(@truncate(value >> @intCast(8 * (i - 1))));
        }
    }

    fn header(encoder: *Encoder, offset: u8, payload_length: usize) void {
        assert(offset == 0x80 or offset == 0xc0);
        if (payload_length <= short_payload_max) {
            encoder.byte(offset + @as(u8, @intCast(payload_length)));
        } else {
            const size = byte_length(@as(u64, payload_length));
            encoder.byte(offset + short_payload_max + @as(u8, @intCast(size)));
            encoder.big_endian(payload_length, size);
        }
    }

    /// Writes a string header for a payload the caller writes next with `raw`.
    pub fn string_header(encoder: *Encoder, payload_length: usize) void {
        encoder.header(0x80, payload_length);
    }

    /// Writes a list header; the caller then writes items totalling `payload_length`.
    pub fn list_header(encoder: *Encoder, payload_length: usize) void {
        encoder.header(0xc0, payload_length);
    }

    pub fn bytes(encoder: *Encoder, value: []const u8) void {
        const start = encoder.position;
        if (value.len == 1 and value[0] < 0x80) {
            encoder.byte(value[0]);
        } else {
            encoder.header(0x80, value.len);
            encoder.raw(value);
        }
        assert(encoder.position - start == bytes_length(value));
    }

    pub fn int(encoder: *Encoder, value: anytype) void {
        const T = @TypeOf(value);
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        comptime assert(@bitSizeOf(T) <= 256);
        const wide: u256 = value;
        const size = byte_length(wide);
        if (size == 0) return encoder.byte(0x80);
        if (size == 1 and wide < 0x80) return encoder.byte(@intCast(wide));
        var scratch: [32]u8 = undefined;
        std.mem.writeInt(u256, &scratch, wide, .big);
        encoder.byte(0x80 + @as(u8, @intCast(size)));
        encoder.raw(scratch[32 - size ..]);
    }

    pub fn boolean(encoder: *Encoder, value: bool) void {
        encoder.int(@intFromBool(value));
    }
};

const testing = std.testing;

test "encode: lengths" {
    try testing.expectEqual(@as(usize, 0), byte_length(@as(u64, 0)));
    try testing.expectEqual(@as(usize, 1), byte_length(@as(u64, 255)));
    try testing.expectEqual(@as(usize, 2), byte_length(@as(u64, 256)));
    try testing.expectEqual(@as(usize, 32), byte_length(@as(u256, std.math.maxInt(u256))));
    try testing.expectEqual(@as(usize, 1), header_length(55));
    try testing.expectEqual(@as(usize, 2), header_length(56));
    try testing.expectEqual(@as(usize, 3), header_length(256));
    try testing.expectEqual(@as(usize, 1), int_length(@as(u64, 0)));
    try testing.expectEqual(@as(usize, 1), int_length(@as(u64, 127)));
    try testing.expectEqual(@as(usize, 2), int_length(@as(u64, 128)));
    try testing.expectEqual(@as(usize, 1), bytes_length(&.{0x7f}));
    try testing.expectEqual(@as(usize, 2), bytes_length(&.{0x80}));
}

test "encode: known encodings" {
    var buffer: [64]u8 = undefined;
    var encoder = Encoder.init(&buffer);
    encoder.list_header(bytes_length("cat") + bytes_length("dog"));
    encoder.bytes("cat");
    encoder.bytes("dog");
    try testing.expectEqualSlices(u8, "\xc8\x83cat\x83dog", encoder.written());

    encoder = Encoder.init(&buffer);
    encoder.int(@as(u64, 0));
    encoder.int(@as(u64, 15));
    encoder.int(@as(u64, 1024));
    encoder.boolean(true);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x0f, 0x82, 0x04, 0x00, 0x01 }, encoder.written());
}
