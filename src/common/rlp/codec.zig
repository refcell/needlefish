//! Comptime-generic RLP codec driven by Zig types.
//!
//! Mapping:
//!   unsigned ints, bool          -> canonical integer string
//!   `[N]u8`, `[]const u8`        -> byte string (decoding borrows the input)
//!   `struct { bytes: [N]u8 }`    -> byte string (Address, B256, Bloom, ...)
//!   other structs                -> list of fields, in declaration order
//!   `[]const T`                  -> list of items (encode only; decode lists by hand)
//!   types with `rlp_length`/`rlp_encode`/`rlp_decode` decls use those instead.
//!
//! Nesting follows the type structure, which is comptime-known and finite, so the
//! call depth is bounded by the type depth (no data-driven recursion).

const std = @import("std");
const assert = std.debug.assert;
const encode_module = @import("encode.zig");
const decode_module = @import("decode.zig");

const Encoder = encode_module.Encoder;
const Decoder = decode_module.Decoder;
const Error = decode_module.Error;

fn is_byte_wrapper(comptime T: type) bool {
    const info = @typeInfo(T);
    if (info != .@"struct") return false;
    const names = info.@"struct".field_names;
    if (names.len != 1 or !std.mem.eql(u8, names[0], "bytes")) return false;
    const field_info = @typeInfo(info.@"struct".field_types[0]);
    return field_info == .array and field_info.array.child == u8;
}

fn has_custom(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum" => @hasDecl(T, "rlp_length"),
        else => false,
    };
}

/// Payload length of a struct encoded as a list (sum of its encoded fields).
pub fn fields_length(value: anytype) usize {
    var total: usize = 0;
    inline for (@typeInfo(@TypeOf(value)).@"struct".field_names) |name| {
        total += length(@field(value, name));
    }
    return total;
}

fn items_length(items: anytype) usize {
    var total: usize = 0;
    for (items) |item| total += length(item);
    return total;
}

/// Exact number of bytes `encode(value)` writes.
pub fn length(value: anytype) usize {
    const T = @TypeOf(value);
    if (comptime has_custom(T)) return value.rlp_length();
    if (comptime is_byte_wrapper(T)) return encode_module.bytes_length(&value.bytes);
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int, .comptime_int => encode_module.int_length(value),
        .array => |array| blk: {
            comptime assert(array.child == u8);
            break :blk encode_module.bytes_length(&value);
        },
        .pointer => |pointer| blk: {
            comptime assert(pointer.size == .slice);
            if (pointer.child == u8) break :blk encode_module.bytes_length(value);
            break :blk encode_module.list_length(items_length(value));
        },
        .@"struct" => encode_module.list_length(fields_length(value)),
        else => @compileError("rlp: unsupported type " ++ @typeName(T)),
    };
}

/// Encodes `value`; the encoder must have at least `length(value)` bytes left.
pub fn encode(encoder: *Encoder, value: anytype) void {
    const T = @TypeOf(value);
    const start = encoder.position;
    if (comptime has_custom(T)) {
        value.rlp_encode(encoder);
    } else if (comptime is_byte_wrapper(T)) {
        encoder.bytes(&value.bytes);
    } else switch (@typeInfo(T)) {
        .bool => encoder.boolean(value),
        .int => encoder.int(value),
        .array => encoder.bytes(&value),
        .pointer => |pointer| if (pointer.child == u8) {
            encoder.bytes(value);
        } else {
            encoder.list_header(items_length(value));
            for (value) |item| encode(encoder, item);
        },
        .@"struct" => |info| {
            encoder.list_header(fields_length(value));
            inline for (info.field_names) |name| encode(encoder, @field(value, name));
        },
        else => @compileError("rlp: unsupported type " ++ @typeName(T)),
    }
    assert(encoder.position - start == length(value));
}

/// Encodes each field of struct `value` in order, without a list header.
pub fn encode_fields(encoder: *Encoder, value: anytype) void {
    const start = encoder.position;
    inline for (@typeInfo(@TypeOf(value)).@"struct".field_names) |name| {
        encode(encoder, @field(value, name));
    }
    assert(encoder.position - start == fields_length(value));
}

/// Decodes the fields of struct `T` in order from a list decoder (no finish check).
pub fn decode_fields(comptime T: type, items: *Decoder) Error!T {
    const info = @typeInfo(T).@"struct";
    var value: T = undefined;
    inline for (info.field_names, info.field_types) |name, Field| {
        @field(value, name) = try decode(Field, items);
    }
    return value;
}

/// Encodes `value` into `buffer` and returns the written prefix.
pub fn encode_to(buffer: []u8, value: anytype) []u8 {
    assert(buffer.len >= length(value));
    var encoder = Encoder.init(buffer);
    encode(&encoder, value);
    return encoder.written();
}

/// Decodes the next item of `decoder` as `T`.
pub fn decode(comptime T: type, decoder: *Decoder) Error!T {
    if (comptime has_custom(T)) return T.rlp_decode(decoder);
    if (comptime is_byte_wrapper(T)) {
        const size = @typeInfo(@FieldType(T, "bytes")).array.len;
        return .{ .bytes = try decoder.fixed(size) };
    }
    switch (@typeInfo(T)) {
        .bool => return decoder.boolean(),
        .int => return decoder.int(T),
        .array => |array| return decoder.fixed(array.len),
        .pointer => |pointer| {
            comptime assert(pointer.child == u8);
            return decoder.bytes();
        },
        .@"struct" => {
            var items = try decoder.list();
            const value = try decode_fields(T, &items);
            try items.finish();
            return value;
        },
        else => @compileError("rlp: unsupported type " ++ @typeName(T)),
    }
}

/// Decodes `input` as exactly one `T` with no trailing bytes.
pub fn decode_exact(comptime T: type, input: []const u8) Error!T {
    var decoder = Decoder.init(input);
    const value = try decode(T, &decoder);
    try decoder.finish();
    return value;
}

const testing = std.testing;

test "codec: struct round trip" {
    const Inner = struct { flag: bool, tag: [4]u8 };
    const Outer = struct {
        nonce: u64,
        value: u256,
        data: []const u8,
        inner: Inner,
        word: struct { bytes: [32]u8 },
    };
    const outer: Outer = .{
        .nonce = 9,
        .value = 1 << 200,
        .data = "hello",
        .inner = .{ .flag = true, .tag = "abcd".* },
        .word = .{ .bytes = @splat(7) },
    };
    var buffer: [256]u8 = undefined;
    const encoded = encode_to(&buffer, outer);
    try testing.expectEqual(length(outer), encoded.len);
    const back = try decode_exact(Outer, encoded);
    try testing.expectEqual(outer.nonce, back.nonce);
    try testing.expectEqual(outer.value, back.value);
    try testing.expectEqualStrings(outer.data, back.data);
    try testing.expectEqual(outer.inner.flag, back.inner.flag);
    try testing.expectEqualSlices(u8, &outer.word.bytes, &back.word.bytes);
}

test "codec: slices encode as lists" {
    const items = [_]u64{ 1, 2, 300 };
    var buffer: [16]u8 = undefined;
    const slice: []const u64 = &items;
    try testing.expectEqualSlices(
        u8,
        &.{ 0xc5, 0x01, 0x02, 0x82, 0x01, 0x2c },
        encode_to(&buffer, slice),
    );
}
