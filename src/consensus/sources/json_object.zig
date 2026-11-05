//! Strict field access for JSON-RPC results: object and array iterators over a raw JSON
//! value, and Ethereum hex decoders that reject anything outside the execution-apis
//! encodings (QUANTITY without leading zeros, DATA with an even number of digits, fixed
//! sizes for hashes and addresses, no escapes).
//!
//! Inputs are raw values handed out by the RPC client, so they are already well formed;
//! the scanner still reports structural errors rather than trusting that.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;

pub const Error = error{
    /// The JSON is malformed or a value has the wrong JSON type.
    InvalidJson,
    /// A value has the right JSON type but is not a valid encoding.
    InvalidField,
    /// A required field is absent.
    MissingField,
    /// A list or byte string exceeds its configured bound.
    TooLarge,
    OutOfMemory,
};

pub const Field = struct {
    key: []const u8,
    value: json.Token,
    /// The full raw JSON of the value.
    raw: []const u8,
};

/// Start offset of the value whose first token is `value`, given the scanner right after
/// that token.
fn raw_start(scanner: *const json.Scanner, value: json.Token) usize {
    const base = @intFromPtr(scanner.input.ptr);
    return switch (value.tag) {
        .object_begin, .array_begin => scanner.offset() - 1,
        .string => @intFromPtr(value.bytes.ptr) - base - 1,
        .number => @intFromPtr(value.bytes.ptr) - base,
        .true, .null => scanner.offset() - 4,
        .false => scanner.offset() - 5,
        .object_end, .array_end, .end => unreachable,
    };
}

/// Reads the next value from `scanner` and returns it with its raw bytes.
fn next_value(scanner: *json.Scanner) Error!struct { json.Token, []const u8 } {
    const value = scanner.next() catch return error.InvalidJson;
    switch (value.tag) {
        .object_end, .array_end, .end => return error.InvalidJson,
        else => {},
    }
    const start = raw_start(scanner, value);
    scanner.skip(value) catch return error.InvalidJson;
    const end = scanner.offset();
    assert(start < end);
    return .{ value, scanner.input[start..end] };
}

pub const ObjectIterator = struct {
    scanner: json.Scanner,
    done: bool = false,

    pub fn init(raw: []const u8) Error!ObjectIterator {
        var scanner = json.Scanner.init(raw);
        const first = scanner.next() catch return error.InvalidJson;
        if (first.tag != .object_begin) return error.InvalidJson;
        assert(scanner.depth == 1);
        return .{ .scanner = scanner };
    }

    pub fn next(iterator: *ObjectIterator) Error!?Field {
        if (iterator.done) return null;
        const key = iterator.scanner.next() catch return error.InvalidJson;
        if (key.tag == .object_end) {
            iterator.done = true;
            return null;
        }
        if (key.tag != .string or !key.key) return error.InvalidJson;
        const value, const raw = try next_value(&iterator.scanner);
        assert(raw.len > 0);
        return .{ .key = key.bytes, .value = value, .raw = raw };
    }
};

pub const Element = struct { value: json.Token, raw: []const u8 };

pub const ArrayIterator = struct {
    scanner: json.Scanner,
    done: bool = false,

    pub fn init(raw: []const u8) Error!ArrayIterator {
        var scanner = json.Scanner.init(raw);
        const first = scanner.next() catch return error.InvalidJson;
        if (first.tag != .array_begin) return error.InvalidJson;
        assert(scanner.depth == 1);
        return .{ .scanner = scanner };
    }

    pub fn next(iterator: *ArrayIterator) Error!?Element {
        if (iterator.done) return null;
        const save = iterator.scanner;
        const peeked = iterator.scanner.next() catch return error.InvalidJson;
        if (peeked.tag == .array_end) {
            iterator.done = true;
            return null;
        }
        iterator.scanner = save;
        const value, const raw = try next_value(&iterator.scanner);
        assert(raw.len > 0);
        return .{ .value = value, .raw = raw };
    }
};

/// Number of elements of a JSON array, rejecting more than `count_max`.
pub fn array_count(raw: []const u8, count_max: u32) Error!u32 {
    var iterator = try ArrayIterator.init(raw);
    var count: u32 = 0;
    while (try iterator.next()) |_| {
        if (count == count_max) return error.TooLarge;
        count += 1;
    }
    assert(count <= count_max);
    return count;
}

/// The raw text of a hex string value; escapes are never valid in hex.
fn hex_text(token: json.Token) Error![]const u8 {
    if (token.tag != .string) return error.InvalidJson;
    if (token.escaped) return error.InvalidField;
    assert(token.tag == .string);
    return token.bytes;
}

pub fn quantity(comptime T: type, token: json.Token) Error!T {
    const text = try hex_text(token);
    return json.parse_quantity(T, text) catch error.InvalidField;
}

pub fn fixed(comptime N: usize, token: json.Token) Error![N]u8 {
    const text = try hex_text(token);
    return json.parse_fixed(N, text) catch error.InvalidField;
}

pub fn hash(token: json.Token) Error!B256 {
    return .init(try fixed(32, token));
}

pub fn address(token: json.Token) Error!Address {
    return .init(try fixed(20, token));
}

/// An address or JSON null.
pub fn address_or_null(token: json.Token) Error!?Address {
    if (token.tag == .null) return null;
    return try address(token);
}

pub fn boolean(token: json.Token) Error!bool {
    return switch (token.tag) {
        .true => true,
        .false => false,
        else => error.InvalidJson,
    };
}

/// Byte length of a DATA string without decoding it.
pub fn data_size(token: json.Token) Error!usize {
    const text = try hex_text(token);
    if (text.len < 2 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) {
        return error.InvalidField;
    }
    if (text.len % 2 != 0) return error.InvalidField;
    return (text.len - 2) / 2;
}

/// Decodes DATA into `out`, which must be exactly the decoded size.
pub fn data_into(token: json.Token, out: []u8) Error!void {
    const size = try data_size(token);
    if (size != out.len) return error.InvalidField;
    const decoded = json.parse_data(token.bytes, out) catch return error.InvalidField;
    assert(decoded.len == out.len);
}

/// Decodes DATA of at most `size_max` bytes into memory from `allocator`.
pub fn data_alloc(
    allocator: std.mem.Allocator,
    token: json.Token,
    size_max: usize,
) Error![]u8 {
    const size = try data_size(token);
    if (size > size_max) return error.TooLarge;
    const out = try allocator.alloc(u8, size);
    try data_into(token, out);
    assert(out.len <= size_max);
    return out;
}

/// A non-negative integer encoded as a decimal string (beacon API) or a QUANTITY.
pub fn decimal_or_quantity(token: json.Token) Error!u64 {
    const text = try hex_text(token);
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        return quantity(u64, token);
    }
    if (text.len == 0 or text.len > 20) return error.InvalidField;
    if (text.len > 1 and text[0] == '0') return error.InvalidField;
    for (text) |character| {
        if (character < '0' or character > '9') return error.InvalidField;
    }
    return std.fmt.parseInt(u64, text, 10) catch error.InvalidField;
}

/// Tracks required fields by bit: `see(index)` once per field, `require(mask)` at the end.
pub fn Seen(comptime count: u32) type {
    comptime assert(count > 0 and count <= 64);
    return struct {
        const Self = @This();
        bits: u64 = 0,

        pub fn see(seen: *Self, index: u32) Error!void {
            assert(index < count);
            const bit = @as(u64, 1) << @intCast(index);
            if (seen.bits & bit != 0) return error.InvalidJson; // Duplicate key.
            seen.bits |= bit;
        }

        pub fn has(seen: Self, index: u32) bool {
            assert(index < count);
            return seen.bits & (@as(u64, 1) << @intCast(index)) != 0;
        }

        pub fn require(seen: Self, mask: u64) Error!void {
            assert(mask != 0);
            if (seen.bits & mask != mask) return error.MissingField;
        }
    };
}

const testing = std.testing;

test "json object: iterates fields with raw values" {
    var iterator = try ObjectIterator.init(
        \\{"a":"0x1","b":{"c":[1,2]},"d":null,"e":true,"f":false,"g":12}
    );
    const expected = [_][2][]const u8{
        .{ "a", "\"0x1\"" }, .{ "b", "{\"c\":[1,2]}" }, .{ "d", "null" },
        .{ "e", "true" },    .{ "f", "false" },         .{ "g", "12" },
    };
    for (expected) |pair| {
        const field = (try iterator.next()).?;
        try testing.expectEqualStrings(pair[0], field.key);
        try testing.expectEqualStrings(pair[1], field.raw);
    }
    try testing.expect(try iterator.next() == null);
    try testing.expect(try iterator.next() == null);
}

test "json object: arrays and counts" {
    try testing.expectEqual(@as(u32, 3), try array_count("[1,{\"a\":[]},\"x\"]", 8));
    try testing.expectEqual(@as(u32, 0), try array_count("[]", 8));
    try testing.expectError(error.TooLarge, array_count("[1,2,3]", 2));
    try testing.expectError(error.InvalidJson, array_count("{}", 2));
}

test "json object: strict hex" {
    const token = struct {
        fn of(text: []const u8) json.Token {
            return .{ .tag = .string, .bytes = text };
        }
    }.of;
    try testing.expectEqual(@as(u64, 0x10), try quantity(u64, token("0x10")));
    try testing.expectError(error.InvalidField, quantity(u64, token("0x010")));
    try testing.expectError(error.InvalidField, quantity(u64, token("0x")));
    try testing.expectError(error.InvalidField, quantity(u8, token("0x100")));
    try testing.expectError(error.InvalidJson, quantity(u64, .{ .tag = .number, .bytes = "1" }));
    try testing.expectError(error.InvalidField, address(token("0x00")));
    try testing.expectEqual(@as(usize, 2), try data_size(token("0xabcd")));
    try testing.expectError(error.InvalidField, data_size(token("0xabc")));
    try testing.expectEqual(@as(u64, 12), try decimal_or_quantity(token("12")));
    try testing.expectEqual(@as(u64, 18), try decimal_or_quantity(token("0x12")));
    try testing.expectError(error.InvalidField, decimal_or_quantity(token("012")));
    try testing.expectError(error.InvalidField, decimal_or_quantity(token("1a")));
    var escaped = token("0x10");
    escaped.escaped = true;
    try testing.expectError(error.InvalidField, quantity(u64, escaped));
}
