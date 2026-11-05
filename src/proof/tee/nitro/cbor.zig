//! Minimal bounded CBOR (RFC 8949) decoder and encoder for AWS Nitro attestations.
//!
//! Nitro attestation documents use a small, definite-length subset of CBOR: maps,
//! arrays, byte and text strings, unsigned and negative integers, tags, and the
//! simple values `false`, `true`, and `null`. This module decodes exactly that
//! subset and rejects everything else: indefinite lengths, floats, reserved
//! additional-info values, and other simple values.
//!
//! The decoder is a pull reader over a borrowed byte slice. `Reader.next` returns
//! one data item head (strings include their payload slice). `Reader.skip` walks one
//! complete data item with an explicit bounded stack, never recursion, and enforces
//! `Limits` on nesting depth and item count. `validate` checks that a whole buffer is
//! exactly one well-formed item.
//!
//! The encoder writes heads into caller-owned fixed buffers; it never allocates.

const std = @import("std");
const assert = std.debug.assert;

/// Hard capacity of the skip stack. `Limits.depth_max` must not exceed it.
pub const depth_limit: u32 = 32;

pub const Major = enum(u3) {
    unsigned = 0,
    negative = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

pub const Error = error{
    Truncated,
    IndefiniteLength,
    ReservedAdditionalInfo,
    UnsupportedSimple,
    InvalidUtf8,
    DepthExceeded,
    TooManyItems,
    TrailingBytes,
    InputTooLarge,
};

pub const Limits = struct {
    /// Maximum container nesting (arrays, maps, and tags each add one level).
    depth_max: u32 = 16,
    /// Maximum number of data items (including container heads) in one walk.
    items_max: u32 = 8192,
    /// Maximum input size accepted by `validate`.
    input_size_max: u32 = 1 << 20,
};

/// One decoded data item head. Container items carry their element count; the
/// elements follow in the stream. Strings borrow from the input.
pub const Item = union(enum) {
    unsigned: u64,
    /// Encoded argument `n`; the integer value is `-1 - n`.
    negative: u64,
    bytes: []const u8,
    text: []const u8,
    array: u64,
    /// Number of key/value pairs.
    map: u64,
    tag: u64,
    boolean: bool,
    null,
};

pub const Reader = struct {
    bytes: []const u8,
    position: u32,

    pub fn init(bytes: []const u8) Reader {
        assert(bytes.len <= std.math.maxInt(u32));
        const reader: Reader = .{ .bytes = bytes, .position = 0 };
        assert(reader.position <= reader.bytes.len);
        return reader;
    }

    pub fn at_end(reader: *const Reader) bool {
        assert(reader.position <= reader.bytes.len);
        return reader.position == reader.bytes.len;
    }

    fn remaining(reader: *const Reader) u64 {
        assert(reader.position <= reader.bytes.len);
        return reader.bytes.len - reader.position;
    }

    fn read_byte(reader: *Reader) Error!u8 {
        if (reader.at_end()) return error.Truncated;
        const byte = reader.bytes[reader.position];
        reader.position += 1;
        assert(reader.position <= reader.bytes.len);
        return byte;
    }

    fn read_argument(reader: *Reader, additional: u5) Error!u64 {
        assert(additional <= 31);
        if (additional < 24) return additional;
        const width: u32 = switch (additional) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28, 29, 30 => return error.ReservedAdditionalInfo,
            31 => return error.IndefiniteLength,
            else => unreachable,
        };
        if (reader.remaining() < width) return error.Truncated;
        var argument: u64 = 0;
        for (reader.bytes[reader.position..][0..width]) |byte| {
            argument = (argument << 8) | byte;
        }
        reader.position += width;
        assert(reader.position <= reader.bytes.len);
        return argument;
    }

    fn read_payload(reader: *Reader, length: u64) Error![]const u8 {
        if (length > reader.remaining()) return error.Truncated;
        const start = reader.position;
        reader.position += @intCast(length);
        assert(reader.position <= reader.bytes.len);
        return reader.bytes[start..reader.position];
    }

    /// Decode the next data item head. Strings are returned with their payload.
    pub fn next(reader: *Reader) Error!Item {
        const initial = try reader.read_byte();
        const major: Major = @fromBackingInt(@intCast(@as(u3, @intCast(initial >> 5))));
        const additional: u5 = @intCast(initial & 0x1f);
        if (major == .simple) return simple_item(additional);
        const argument = try reader.read_argument(additional);
        return switch (major) {
            .unsigned => .{ .unsigned = argument },
            .negative => .{ .negative = argument },
            .bytes => .{ .bytes = try reader.read_payload(argument) },
            .text => text: {
                const text = try reader.read_payload(argument);
                if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
                break :text .{ .text = text };
            },
            .array => .{ .array = argument },
            .map => .{ .map = argument },
            .tag => .{ .tag = argument },
            .simple => unreachable,
        };
    }

    /// Skip one complete data item (including all nested elements).
    pub fn skip(reader: *Reader, limits: Limits) Error!void {
        assert(limits.depth_max <= depth_limit);
        assert(limits.items_max > 0);
        var stack: [depth_limit]u64 = undefined;
        var depth: u32 = 0;
        var items: u32 = 0;
        while (items < limits.items_max) {
            const item = try reader.next();
            items += 1;
            const children = try child_count(item, reader.remaining());
            if (children > 0) {
                if (depth == limits.depth_max) return error.DepthExceeded;
                stack[depth] = children;
                depth += 1;
                continue;
            }
            // A leaf completes; pop every container it finishes.
            while (depth > 0) {
                stack[depth - 1] -= 1;
                if (stack[depth - 1] > 0) break;
                depth -= 1;
            }
            if (depth == 0) return;
        }
        return error.TooManyItems;
    }
};

fn simple_item(additional: u5) Error!Item {
    assert(additional <= 31);
    return switch (additional) {
        20 => .{ .boolean = false },
        21 => .{ .boolean = true },
        22 => .null,
        31 => error.IndefiniteLength,
        28, 29, 30 => error.ReservedAdditionalInfo,
        else => error.UnsupportedSimple,
    };
}

/// Number of nested data items that follow `item`. Each item takes at least one
/// byte, so a count larger than the remaining input is rejected up front.
fn child_count(item: Item, remaining: u64) Error!u64 {
    const children: u64 = switch (item) {
        .array => |count| count,
        .map => |pairs| if (pairs > std.math.maxInt(u64) / 2) return error.Truncated else pairs * 2,
        .tag => 1,
        else => 0,
    };
    if (children > remaining) return error.Truncated;
    assert(children <= remaining);
    return children;
}

/// Check that `bytes` holds exactly one well-formed data item within `limits`.
pub fn validate(bytes: []const u8, limits: Limits) Error!void {
    assert(limits.depth_max <= depth_limit);
    if (bytes.len > limits.input_size_max) return error.InputTooLarge;
    var reader = Reader.init(bytes);
    try reader.skip(limits);
    if (!reader.at_end()) return error.TrailingBytes;
    assert(reader.position == bytes.len);
}

/// Encoded size of a head with `argument`.
pub fn head_size(argument: u64) u32 {
    const size: u32 = if (argument < 24)
        1
    else if (argument <= 0xff)
        2
    else if (argument <= 0xffff)
        3
    else if (argument <= 0xffff_ffff)
        5
    else
        9;
    assert(size >= 1 and size <= 9);
    return size;
}

/// Encode a canonical (shortest-form) head into `out`; returns the used prefix.
pub fn head_encode(out: *[9]u8, major: Major, argument: u64) []const u8 {
    const size = head_size(argument);
    const major_bits: u8 = @as(u8, @backingInt(major)) << 5;
    const additional: u8 = switch (size) {
        1 => @intCast(argument),
        2 => 24,
        3 => 25,
        5 => 26,
        9 => 27,
        else => unreachable,
    };
    out[0] = major_bits | additional;
    var index: u32 = 1;
    while (index < size) : (index += 1) {
        const shift: u6 = @intCast((size - 1 - index) * 8);
        out[index] = @truncate(argument >> shift);
    }
    assert(index == size);
    return out[0..size];
}

/// Fixed-buffer CBOR writer. Writes canonical heads only.
pub const Writer = struct {
    buffer: []u8,
    position: u32 = 0,

    pub const WriteError = error{NoSpaceLeft};

    pub fn written(writer: *const Writer) []const u8 {
        assert(writer.position <= writer.buffer.len);
        return writer.buffer[0..writer.position];
    }

    pub fn raw(writer: *Writer, bytes: []const u8) WriteError!void {
        assert(writer.position <= writer.buffer.len);
        if (writer.buffer.len - writer.position < bytes.len) return error.NoSpaceLeft;
        @memcpy(writer.buffer[writer.position..][0..bytes.len], bytes);
        writer.position += @intCast(bytes.len);
        assert(writer.position <= writer.buffer.len);
    }

    pub fn head(writer: *Writer, major: Major, argument: u64) WriteError!void {
        var encoded: [9]u8 = undefined;
        const bytes = head_encode(&encoded, major, argument);
        assert(bytes.len == head_size(argument));
        try writer.raw(bytes);
    }

    pub fn byte_string(writer: *Writer, bytes: []const u8) WriteError!void {
        try writer.head(.bytes, bytes.len);
        try writer.raw(bytes);
    }

    pub fn text_string(writer: *Writer, text: []const u8) WriteError!void {
        assert(std.unicode.utf8ValidateSlice(text));
        try writer.head(.text, text.len);
        try writer.raw(text);
    }

    /// Encode a signed integer as major type 0 or 1.
    pub fn integer(writer: *Writer, value: i64) WriteError!void {
        if (value >= 0) return writer.head(.unsigned, @intCast(value));
        const argument: u64 = @intCast(-1 - value);
        assert(argument < std.math.maxInt(u64));
        try writer.head(.negative, argument);
    }

    pub fn simple_null(writer: *Writer) WriteError!void {
        try writer.raw(&.{0xf6});
    }
};

const fuzz = @import("../../../testing/fuzz.zig");
const testing = std.testing;

test "cbor: decodes integers, strings, and simple values" {
    const input = [_]u8{
        0x18, 0x2a, // 42
        0x38, 0x22, // -35
        0x43, 1, 2, 3, // h'010203'
        0x62, 'h', 'i', // "hi"
        0xf4, 0xf5, 0xf6, // false true null
        0x1b, 0, 0, 0, 1, 0, 0, 0, 0, // 2^32
    };
    var reader = Reader.init(&input);
    try testing.expectEqual(@as(u64, 42), (try reader.next()).unsigned);
    try testing.expectEqual(@as(u64, 34), (try reader.next()).negative);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try reader.next()).bytes);
    try testing.expectEqualStrings("hi", (try reader.next()).text);
    try testing.expectEqual(false, (try reader.next()).boolean);
    try testing.expectEqual(true, (try reader.next()).boolean);
    try testing.expect((try reader.next()) == .null);
    try testing.expectEqual(@as(u64, 1 << 32), (try reader.next()).unsigned);
    try testing.expect(reader.at_end());
    try testing.expectError(error.Truncated, reader.next());
}

test "cbor: validate accepts nested containers and tags" {
    // 18([h'a10138 22', {}, h'01', h'02'])
    const cose = [_]u8{ 0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x41, 1, 0x41, 2 };
    try validate(&cose, .{});
    // {"a": [1, [2, {}]], "b": null}
    const nested = [_]u8{ 0xa2, 0x61, 'a', 0x82, 1, 0x82, 2, 0xa0, 0x61, 'b', 0xf6 };
    try validate(&nested, .{});
    try validate(&.{0x80}, .{});
    try validate(&.{0xa0}, .{});
}

test "cbor: validate rejects malformed and out-of-subset input" {
    try testing.expectError(error.Truncated, validate(&.{}, .{}));
    try testing.expectError(error.TrailingBytes, validate(&.{ 0x01, 0x02 }, .{}));
    try testing.expectError(error.IndefiniteLength, validate(&.{ 0x9f, 0xff }, .{}));
    try testing.expectError(error.IndefiniteLength, validate(&.{ 0x5f, 0xff }, .{}));
    try testing.expectError(error.IndefiniteLength, validate(&.{0xff}, .{}));
    try testing.expectError(error.ReservedAdditionalInfo, validate(&.{0x1c}, .{}));
    try testing.expectError(error.UnsupportedSimple, validate(&.{0xf7}, .{}));
    // Half-precision float.
    try testing.expectError(error.UnsupportedSimple, validate(&.{ 0xf9, 0, 0 }, .{}));
    try testing.expectError(error.Truncated, validate(&.{ 0x43, 1, 2 }, .{}));
    try testing.expectError(error.Truncated, validate(&.{ 0x82, 0x01 }, .{}));
    const huge_array = [_]u8{ 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.Truncated, validate(&huge_array, .{}));
    try testing.expectError(error.InvalidUtf8, validate(&.{ 0x61, 0xff }, .{}));
    try testing.expectError(error.InputTooLarge, validate(&.{ 1, 2 }, .{ .input_size_max = 1 }));
}

test "cbor: validate enforces depth and item limits" {
    const deep = [_]u8{ 0x81, 0x81, 0x81, 0x81, 0x01 };
    try validate(&deep, .{ .depth_max = 4 });
    try testing.expectError(error.DepthExceeded, validate(&deep, .{ .depth_max = 3 }));
    const wide = [_]u8{ 0x84, 1, 2, 3, 4 };
    try validate(&wide, .{ .items_max = 5 });
    try testing.expectError(error.TooManyItems, validate(&wide, .{ .items_max = 4 }));
    const tags = [_]u8{ 0xc1, 0xc1, 0x01 };
    try testing.expectError(error.DepthExceeded, validate(&tags, .{ .depth_max = 1 }));
}

test "cbor: writer emits canonical heads that read back" {
    var buffer: [64]u8 = undefined;
    var writer: Writer = .{ .buffer = &buffer };
    try writer.head(.array, 4);
    try writer.text_string("Signature1");
    try writer.integer(-35);
    try writer.integer(70000);
    try writer.simple_null();
    try testing.expectEqualSlices(u8, &.{ 0x84, 0x6a }, writer.written()[0..2]);
    var reader = Reader.init(writer.written());
    try testing.expectEqual(@as(u64, 4), (try reader.next()).array);
    try testing.expectEqualStrings("Signature1", (try reader.next()).text);
    try testing.expectEqual(@as(u64, 34), (try reader.next()).negative);
    try testing.expectEqual(@as(u64, 70000), (try reader.next()).unsigned);
    try testing.expect((try reader.next()) == .null);
    try testing.expect(reader.at_end());
    var tiny: [1]u8 = undefined;
    var full: Writer = .{ .buffer = &tiny };
    try testing.expectError(error.NoSpaceLeft, full.text_string("ab"));
}

test "cbor: head sizes cover every width" {
    const cases = [_]struct { argument: u64, size: u32 }{
        .{ .argument = 0, .size = 1 },       .{ .argument = 23, .size = 1 },
        .{ .argument = 24, .size = 2 },      .{ .argument = 255, .size = 2 },
        .{ .argument = 256, .size = 3 },     .{ .argument = 65536, .size = 5 },
        .{ .argument = 1 << 32, .size = 9 },
    };
    for (cases) |case| {
        var out: [9]u8 = undefined;
        const encoded = head_encode(&out, .unsigned, case.argument);
        try testing.expectEqual(case.size, @as(u32, @intCast(encoded.len)));
        var reader = Reader.init(encoded);
        try testing.expectEqual(case.argument, (try reader.next()).unsigned);
    }
}

/// Property: validate never panics, and a validated buffer is consumed exactly by
/// a flat sequence of `next` calls.
fn fuzz_validate(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    validate(input, .{ .items_max = 512 }) catch return;
    var reader = Reader.init(input);
    var items: u32 = 0;
    while (!reader.at_end()) : (items += 1) {
        try testing.expect(items < 512);
        _ = try reader.next();
    }
    try testing.expect(items > 0);
}

test "cbor: fuzz validate" {
    try fuzz.run({}, fuzz_validate, .{ .iterations = 1024 });
}

/// Property: every document the writer builds from fuzz choices validates.
fn fuzz_generate(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [2048]u8 = undefined;
    var writer: Writer = .{ .buffer = &buffer };
    var pending: u32 = 1;
    var steps: u32 = 0;
    while (pending > 0 and steps < 64) : (steps += 1) {
        pending -= 1;
        const room: u32 = 64 - steps;
        switch (smith.valueRangeAtMost(u8, 0, 5)) {
            0 => try writer.integer(smith.value(i64)),
            1 => try writer.byte_string(&@as([3]u8, @splat(smith.value(u8)))),
            2 => try writer.text_string("nitro"),
            3 => if (pending + 2 < room) {
                try writer.head(.array, 2);
                pending += 2;
            } else try writer.simple_null(),
            4 => if (pending + 2 < room) {
                try writer.head(.map, 1);
                pending += 2;
            } else try writer.simple_null(),
            else => try writer.simple_null(),
        }
    }
    while (pending > 0) : (pending -= 1) try writer.simple_null();
    try validate(writer.written(), .{ .depth_max = depth_limit });
}

test "cbor: fuzz generated documents validate" {
    try fuzz.run({}, fuzz_generate, .{ .iterations = 512 });
}
