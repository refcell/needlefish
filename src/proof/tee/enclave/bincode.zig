//! The subset of bincode 2 (`config::standard()`, through serde) the Enclave link uses.
//!
//! Integers above u8 are varints, little-endian: below 251 one byte, then 251 + u16,
//! 252 + u32, 253 + u64 (254 is u128, 255 reserved). A u8 is one raw byte. Enum variants
//! are a u32 varint of the declaration index; `Option` a 0/1 tag byte; sequences, strings
//! and serde byte strings (`serialize_bytes`, which alloy uses for `B256`, `Address`
//! and `Bytes`) a u64 varint length then the items. Like bincode, decoding accepts
//! non-minimal varints and leaves trailing bytes to the caller.

const std = @import("std");
const assert = std.debug.assert;

pub const DecodeError = error{
    UnexpectedEnd,
    InvalidVarint,
    InvalidTag,
    InvalidLength,
    InvalidUtf8,
    TooMany,
};

const single_byte_max = 250;
const u16_byte = 251;
const u32_byte = 252;
const u64_byte = 253;

/// Most bytes one varint takes.
pub const varint_bytes_max = 9;

pub const Encoder = struct {
    writer: *std.Io.Writer,

    pub fn byte(encoder: Encoder, value: u8) std.Io.Writer.Error!void {
        try encoder.writer.writeByte(value);
    }

    pub fn varint(encoder: Encoder, value: u64) std.Io.Writer.Error!void {
        var buffer: [varint_bytes_max]u8 = undefined;
        const encoded = encode_varint(&buffer, value);
        assert(encoded.len >= 1 and encoded.len <= varint_bytes_max);
        try encoder.writer.writeAll(encoded);
    }

    pub fn variant(encoder: Encoder, index: u32) std.Io.Writer.Error!void {
        assert(index < 256);
        try encoder.varint(index);
    }

    /// A length-prefixed byte string (serde bytes, `Vec<u8>`, `String`).
    pub fn bytes(encoder: Encoder, value: []const u8) std.Io.Writer.Error!void {
        assert(value.len <= std.math.maxInt(u64));
        try encoder.varint(value.len);
        try encoder.writer.writeAll(value);
    }

    /// Raw bytes with no prefix (serde tuples such as `[u8; 31]`).
    pub fn raw(encoder: Encoder, value: []const u8) std.Io.Writer.Error!void {
        try encoder.writer.writeAll(value);
    }

    pub fn option_bytes(encoder: Encoder, value: ?[]const u8) std.Io.Writer.Error!void {
        const present = value orelse return encoder.byte(0);
        assert(value != null);
        try encoder.byte(1);
        try encoder.bytes(present);
    }
};

pub fn encode_varint(buffer: *[varint_bytes_max]u8, value: u64) []const u8 {
    if (value <= single_byte_max) {
        buffer[0] = @intCast(value);
        return buffer[0..1];
    }
    if (value <= std.math.maxInt(u16)) {
        buffer[0] = u16_byte;
        std.mem.writeInt(u16, buffer[1..3], @intCast(value), .little);
        return buffer[0..3];
    }
    if (value <= std.math.maxInt(u32)) {
        buffer[0] = u32_byte;
        std.mem.writeInt(u32, buffer[1..5], @intCast(value), .little);
        return buffer[0..5];
    }
    buffer[0] = u64_byte;
    std.mem.writeInt(u64, buffer[1..9], value, .little);
    assert(value > std.math.maxInt(u32));
    return buffer[0..9];
}

/// A zero-copy decoder: slices point into `bytes`.
pub const Decoder = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn remaining(decoder: *const Decoder) usize {
        assert(decoder.offset <= decoder.bytes.len);
        return decoder.bytes.len - decoder.offset;
    }

    pub fn take(decoder: *Decoder, count: usize) DecodeError![]const u8 {
        if (count > decoder.remaining()) return error.UnexpectedEnd;
        const slice = decoder.bytes[decoder.offset..][0..count];
        decoder.offset += count;
        assert(decoder.offset <= decoder.bytes.len);
        return slice;
    }

    pub fn byte(decoder: *Decoder) DecodeError!u8 {
        const slice = try decoder.take(1);
        return slice[0];
    }

    pub fn varint(decoder: *Decoder) DecodeError!u64 {
        const tag = try decoder.byte();
        const value: u64 = switch (tag) {
            0...single_byte_max => tag,
            u16_byte => std.mem.readInt(u16, (try decoder.take(2))[0..2], .little),
            u32_byte => std.mem.readInt(u32, (try decoder.take(4))[0..4], .little),
            u64_byte => std.mem.readInt(u64, (try decoder.take(8))[0..8], .little),
            else => return error.InvalidVarint,
        };
        assert(tag <= u64_byte);
        return value;
    }

    /// An enum variant index (a u32 varint: a u64 marker is invalid).
    pub fn variant(decoder: *Decoder) DecodeError!u32 {
        const tag = decoder.bytes[decoder.offset..];
        if (tag.len > 0 and tag[0] == u64_byte) return error.InvalidVarint;
        const value = try decoder.varint();
        assert(value <= std.math.maxInt(u32));
        return @intCast(value);
    }

    /// A length-prefixed byte string of at most `length_max` bytes.
    pub fn bytes_max(decoder: *Decoder, length_max: usize) DecodeError![]const u8 {
        const length = try decoder.varint();
        if (length > length_max) return error.InvalidLength;
        if (length > decoder.remaining()) return error.UnexpectedEnd;
        return decoder.take(@intCast(length));
    }

    /// A serde byte string of exactly `N` bytes (alloy `FixedBytes<N>`).
    pub fn fixed(decoder: *Decoder, comptime N: usize) DecodeError![N]u8 {
        const length = try decoder.varint();
        if (length != N) return error.InvalidLength;
        const slice = try decoder.take(N);
        return slice[0..N].*;
    }

    pub fn string_max(decoder: *Decoder, length_max: usize) DecodeError![]const u8 {
        const text = try decoder.bytes_max(length_max);
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
        return text;
    }

    pub fn option_bytes(decoder: *Decoder, length_max: usize) DecodeError!?[]const u8 {
        return switch (try decoder.byte()) {
            0 => null,
            1 => try decoder.bytes_max(length_max),
            else => error.InvalidTag,
        };
    }

    /// A sequence length, refused above `count_max` or when even `item_bytes_min` bytes per
    /// item cannot fit in what is left (so callers may allocate `count` items).
    pub fn sequence(decoder: *Decoder, count_max: u64, item_bytes_min: u64) DecodeError!u64 {
        assert(item_bytes_min > 0);
        const count = try decoder.varint();
        if (count > count_max) return error.TooMany;
        if (count > decoder.remaining() / item_bytes_min) return error.UnexpectedEnd;
        return count;
    }
};

const testing = std.testing;
const fuzz = @import("../../../testing/fuzz.zig");

test "bincode: varint boundaries" {
    const cases = [_]struct { u64, []const u8 }{
        .{ 0, &.{0} },
        .{ 250, &.{250} },
        .{ 251, &.{ 251, 251, 0 } },
        .{ 65535, &.{ 251, 0xff, 0xff } },
        .{ 65536, &.{ 252, 0, 0, 1, 0 } },
        .{ 1 << 32, &.{ 253, 0, 0, 0, 0, 1, 0, 0, 0 } },
    };
    for (cases) |case| {
        var buffer: [varint_bytes_max]u8 = undefined;
        try testing.expectEqualSlices(u8, case[1], encode_varint(&buffer, case[0]));
        var decoder: Decoder = .{ .bytes = case[1] };
        try testing.expectEqual(case[0], try decoder.varint());
        try testing.expectEqual(@as(usize, 0), decoder.remaining());
    }
    var reserved: Decoder = .{ .bytes = &.{255} };
    try testing.expectError(error.InvalidVarint, reserved.varint());
    var wide_variant: Decoder = .{ .bytes = &.{ 253, 0, 0, 0, 0, 0, 0, 0, 0 } };
    try testing.expectError(error.InvalidVarint, wide_variant.variant());
    var truncated: Decoder = .{ .bytes = &.{ 252, 1 } };
    try testing.expectError(error.UnexpectedEnd, truncated.varint());
}

fn fuzz_varint(_: void, smith: *std.testing.Smith) anyerror!void {
    const value = smith.value(u64);
    var buffer: [varint_bytes_max]u8 = undefined;
    const encoded = encode_varint(&buffer, value);
    var decoder: Decoder = .{ .bytes = encoded };
    try testing.expectEqual(value, try decoder.varint());
    var junk: [32]u8 = undefined;
    const len = smith.slice(&junk);
    var junk_decoder: Decoder = .{ .bytes = junk[0..len] };
    _ = junk_decoder.bytes_max(16) catch {};
    try testing.expect(junk_decoder.offset <= len);
}

test "bincode: seeded fuzz varints" {
    try fuzz.run({}, fuzz_varint, .{ .iterations = 512 });
}
