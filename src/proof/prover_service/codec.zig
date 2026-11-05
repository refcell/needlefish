//! Strict JSON for the prover service protocol, driven by the protocol types at comptime,
//! with the serde conventions base/base uses:
//!
//! - structs are objects with fields in declaration order; `null` optionals are omitted
//!   (`skip_serializing_if = "Option::is_none"`); absent fields take their default, and a
//!   field without a default is required;
//! - unions are adjacently tagged: `{"proof_type": "<tag>", "payload": <value>}`;
//! - integers are plain JSON numbers, enums snake_case strings, `[N]u8` and `[]const u8`
//!   0x-hex strings, `Text` JSON strings, `Timestamp` RFC 3339 strings.
//!
//! Decoding is strict: duplicate fields, wrong JSON types, non-canonical numbers, bad hex,
//! oversized strings or lists, and trailing data are errors. Unknown fields are skipped, as
//! serde does without `deny_unknown_fields`. Byte strings and lists are allocated from the
//! caller's arena (a fixed buffer), every list has a declared `<field>_max` bound, and a
//! type with a `validate` method is checked after decoding.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const protocol = @import("protocol.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    /// Malformed JSON or a value of the wrong JSON type.
    InvalidJson,
    /// A value of the right JSON type that is not a valid encoding.
    InvalidField,
    MissingField,
    DuplicateField,
    /// A string, byte string or list above its bound.
    TooLarge,
    OutOfMemory,
};

pub const WriteError = json.Writer.WriteError;

/// Decodes one JSON document into `T`. Slices in the result point into `arena` memory.
pub fn decode(comptime T: type, arena: Allocator, raw: []const u8) Error!T {
    json.validate(raw) catch return error.InvalidJson;
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return error.InvalidJson;
    const value = try decode_value(T, null, arena, &scanner, first);
    const end = scanner.next() catch return error.InvalidJson;
    if (end.tag != .end) return error.InvalidJson;
    assert(scanner.depth == 0);
    return value;
}

/// Writes `value` as one JSON value.
pub fn encode(comptime T: type, writer: *json.Writer, value: *const T) WriteError!void {
    const depth = writer.depth;
    try encode_value(T, writer, value.*);
    assert(writer.depth == depth);
}

/// `bound` is the item bound of a slice field (its parent's `<field>_max` declaration).
fn decode_value(
    comptime T: type,
    comptime bound: ?u64,
    arena: Allocator,
    scanner: *json.Scanner,
    token: json.Token,
) Error!T {
    switch (@typeInfo(T)) {
        .bool => return switch (token.tag) {
            .true => true,
            .false => false,
            else => error.InvalidJson,
        },
        .int => return decode_integer(T, token),
        .@"enum" => return decode_enum(T, token),
        .optional => |info| {
            if (token.tag == .null) return null;
            return try decode_value(info.child, bound, arena, scanner, token);
        },
        .array => |info| {
            comptime assert(info.child == u8);
            return decode_fixed(info.len, token);
        },
        .pointer => |info| {
            comptime assert(info.size == .slice);
            if (info.child == u8) return decode_bytes(arena, token, bound.?);
            return decode_list(info.child, bound.?, arena, scanner, token);
        },
        .@"struct" => {
            if (@hasDecl(T, "is_text")) return decode_text(T, token);
            if (@hasDecl(T, "is_timestamp")) return decode_timestamp(token);
            return decode_struct(T, arena, scanner, token);
        },
        .@"union" => return decode_union(T, arena, scanner, token),
        else => @compileError("unsupported protocol type " ++ @typeName(T)),
    }
}

/// The `<name>_max` declaration of `Parent` for slice fields, null for other fields.
fn bound_of(comptime Parent: type, comptime name: []const u8, comptime Field: type) ?u64 {
    const Inner = switch (@typeInfo(Field)) {
        .optional => |info| info.child,
        else => Field,
    };
    if (@typeInfo(Inner) != .pointer) return null;
    return @field(Parent, name ++ "_max");
}

fn decode_struct(
    comptime T: type,
    arena: Allocator,
    scanner: *json.Scanner,
    token: json.Token,
) Error!T {
    if (token.tag != .object_begin) return error.InvalidJson;
    const info = @typeInfo(T).@"struct";
    comptime assert(info.field_names.len <= 32);
    var result: T = undefined;
    var seen: u32 = 0;
    var members: u32 = 0;
    while (true) : (members += 1) {
        assert(members <= scanner.input.len);
        const key = scanner.next() catch return error.InvalidJson;
        if (key.tag == .object_end) break;
        assert(key.tag == .string and key.key);
        const value = scanner.next() catch return error.InvalidJson;
        const matched = inline for (info.field_names, info.field_types, 0..) |name, Field, index| {
            if (!key.escaped and std.mem.eql(u8, key.bytes, name)) {
                const bit = @as(u32, 1) << index;
                if (seen & bit != 0) return error.DuplicateField;
                seen |= bit;
                const bound = comptime bound_of(T, name, Field);
                @field(result, name) = try decode_value(Field, bound, arena, scanner, value);
                break true;
            }
        } else false;
        if (!matched) scanner.skip(value) catch return error.InvalidJson;
    }
    const names = info.field_names;
    inline for (names, info.field_types, info.field_attrs, 0..) |name, Field, attrs, index| {
        if (seen & (@as(u32, 1) << index) == 0) {
            @field(result, name) = attrs.defaultValue(Field) orelse return error.MissingField;
        }
    }
    if (@hasDecl(T, "validate")) try result.validate();
    return result;
}

fn decode_union(
    comptime T: type,
    arena: Allocator,
    scanner: *json.Scanner,
    token: json.Token,
) Error!T {
    if (token.tag != .object_begin) return error.InvalidJson;
    const Tag = std.meta.Tag(T);
    var tag: ?Tag = null;
    // The scanner right after the payload's first token, replayed once the tag is known.
    var payload: ?json.Scanner = null;
    var payload_token: json.Token = undefined;
    var members: u32 = 0;
    while (true) : (members += 1) {
        assert(members <= scanner.input.len);
        const key = scanner.next() catch return error.InvalidJson;
        if (key.tag == .object_end) break;
        const value = scanner.next() catch return error.InvalidJson;
        if (!key.escaped and std.mem.eql(u8, key.bytes, "proof_type")) {
            if (tag != null) return error.DuplicateField;
            tag = try decode_enum(Tag, value);
        } else if (!key.escaped and std.mem.eql(u8, key.bytes, "payload")) {
            if (payload != null) return error.DuplicateField;
            payload = scanner.*;
            payload_token = value;
            scanner.skip(value) catch return error.InvalidJson;
        } else {
            scanner.skip(value) catch return error.InvalidJson;
        }
    }
    const active = tag orelse return error.MissingField;
    var replay = payload orelse return error.MissingField;
    const info = @typeInfo(T).@"union";
    inline for (info.field_names, info.field_types) |name, Field| {
        if (active == @field(Tag, name)) {
            const inner = try decode_value(Field, null, arena, &replay, payload_token);
            return @unionInit(T, name, inner);
        }
    }
    unreachable; // Every tag names a field.
}

fn decode_list(
    comptime Item: type,
    comptime bound: u64,
    arena: Allocator,
    scanner: *json.Scanner,
    token: json.Token,
) Error![]const Item {
    if (token.tag != .array_begin) return error.InvalidJson;
    var items: std.ArrayList(Item) = .empty;
    while (true) {
        const element = scanner.next() catch return error.InvalidJson;
        if (element.tag == .array_end) break;
        if (items.items.len == bound) return error.TooLarge;
        const item = try decode_value(Item, null, arena, scanner, element);
        try items.append(arena, item);
    }
    assert(items.items.len <= bound);
    return items.items;
}

/// A plain non-negative JSON integer without a sign, fraction, exponent or leading zero.
fn decode_integer(comptime T: type, token: json.Token) Error!T {
    if (token.tag != .number) return error.InvalidJson;
    const text = token.bytes;
    assert(text.len > 0);
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidField;
    if (text.len > 1 and text[0] == '0') return error.InvalidField;
    return std.fmt.parseInt(T, text, 10) catch error.InvalidField;
}

fn decode_enum(comptime T: type, token: json.Token) Error!T {
    if (token.tag != .string) return error.InvalidJson;
    if (token.escaped) return error.InvalidField;
    return std.meta.stringToEnum(T, token.bytes) orelse error.InvalidField;
}

fn hex_text(token: json.Token) Error![]const u8 {
    if (token.tag != .string) return error.InvalidJson;
    if (token.escaped) return error.InvalidField;
    const text = token.bytes;
    if (text.len < 2 or text[0] != '0' or text[1] != 'x') return error.InvalidField;
    return text;
}

fn decode_fixed(comptime size: usize, token: json.Token) Error![size]u8 {
    const text = try hex_text(token);
    return json.parse_fixed(size, text) catch error.InvalidField;
}

fn decode_bytes(arena: Allocator, token: json.Token, bound: u64) Error![]const u8 {
    const text = try hex_text(token);
    if (text.len % 2 != 0) return error.InvalidField;
    const size = (text.len - 2) / 2;
    if (size > bound) return error.TooLarge;
    const out = try arena.alloc(u8, size);
    const decoded = json.parse_data(text, out) catch return error.InvalidField;
    assert(decoded.len == size);
    return decoded;
}

fn decode_text(comptime T: type, token: json.Token) Error!T {
    if (token.tag != .string) return error.InvalidJson;
    var text: T = .{};
    const decoded = json.unescape(token, &text.buffer) catch |err| return switch (err) {
        error.NoSpaceLeft => error.TooLarge,
        error.InvalidString => error.InvalidField,
    };
    if (decoded.len > T.bytes_max) return error.TooLarge;
    if (decoded.ptr != &text.buffer) @memcpy(text.buffer[0..decoded.len], decoded);
    text.len = @intCast(decoded.len);
    if (!std.unicode.utf8ValidateSlice(text.slice())) return error.InvalidField;
    return text;
}

fn decode_timestamp(token: json.Token) Error!protocol.Timestamp {
    if (token.tag != .string or token.escaped) return error.InvalidJson;
    return parse_rfc3339(token.bytes) orelse error.InvalidField;
}

fn encode_value(comptime T: type, writer: *json.Writer, value: T) WriteError!void {
    switch (@typeInfo(T)) {
        .bool => try writer.boolean(value),
        .int => try writer.integer(value),
        .@"enum" => try writer.string(@tagName(value)),
        .optional => |info| {
            if (value) |inner| return encode_value(info.child, writer, inner);
            try writer.null_value();
        },
        .array => try writer.data(&value),
        .pointer => |info| {
            if (info.child == u8) return writer.data(value);
            try writer.begin_array();
            for (value) |item| try encode_value(info.child, writer, item);
            try writer.end_array();
        },
        .@"struct" => {
            if (@hasDecl(T, "is_text")) return writer.string(value.slice());
            if (@hasDecl(T, "is_timestamp")) {
                var buffer: [20]u8 = undefined;
                return writer.string(format_rfc3339(value, &buffer));
            }
            try encode_struct(T, writer, value);
        },
        .@"union" => {
            try writer.begin_object();
            try writer.key("proof_type");
            try writer.string(@tagName(value));
            try writer.key("payload");
            switch (value) {
                inline else => |payload| try encode_value(@TypeOf(payload), writer, payload),
            }
            try writer.end_object();
        },
        else => @compileError("unsupported protocol type " ++ @typeName(T)),
    }
}

fn encode_struct(comptime T: type, writer: *json.Writer, value: T) WriteError!void {
    const info = @typeInfo(T).@"struct";
    try writer.begin_object();
    inline for (info.field_names, info.field_types) |name, Field| {
        const field = @field(value, name);
        const omitted = switch (@typeInfo(Field)) {
            .optional => field == null,
            else => false,
        };
        if (!omitted) {
            try writer.key(name);
            try encode_value(Field, writer, field);
        }
    }
    try writer.end_object();
}

/// Seconds of 9999-12-31T23:59:59Z, the last instant with a four-digit year.
pub const timestamp_seconds_max: u64 = 253_402_300_799;

const Civil = struct { year: u64, month: u64, day: u64 };

/// Days since 1970-01-01 to a proleptic Gregorian date (Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) Civil {
    const shifted = days + 719_468;
    const era = shifted / 146_097;
    const day_of_era = shifted - era * 146_097;
    const year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 -
        day_of_era / 146_096) / 365;
    const day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    const month_index = (5 * day_of_year + 2) / 153;
    const day = day_of_year - (153 * month_index + 2) / 5 + 1;
    const month = if (month_index < 10) month_index + 3 else month_index - 9;
    const year = year_of_era + era * 400 + @intFromBool(month <= 2);
    assert(month >= 1 and month <= 12);
    assert(day >= 1 and day <= 31);
    return .{ .year = year, .month = month, .day = day };
}

/// The inverse of `civil_from_days`; null before 1970.
fn days_from_civil(civil: Civil) ?u64 {
    assert(civil.month >= 1 and civil.month <= 12);
    const year = civil.year - @intFromBool(civil.month <= 2);
    const era = year / 400;
    const year_of_era = year - era * 400;
    const month_shifted = if (civil.month > 2) civil.month - 3 else civil.month + 9;
    const day_of_year = (153 * month_shifted + 2) / 5 + civil.day - 1;
    const day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    const days = era * 146_097 + day_of_era;
    if (days < 719_468) return null;
    return days - 719_468;
}

pub fn format_rfc3339(timestamp: protocol.Timestamp, buffer: *[20]u8) []const u8 {
    const seconds = @min(timestamp.seconds, timestamp_seconds_max);
    const civil = civil_from_days(seconds / 86_400);
    const second_of_day = seconds % 86_400;
    const text = std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        civil.year,           civil.month,               civil.day,
        second_of_day / 3600, (second_of_day / 60) % 60, second_of_day % 60,
    }) catch unreachable; // 20 bytes for every year up to 9999.
    assert(text.len == 20);
    return text;
}

fn digits(text: []const u8, start: usize, count: usize) ?u64 {
    if (text.len < start + count) return null;
    var value: u64 = 0;
    for (text[start..][0..count]) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        value = value * 10 + (byte - '0');
    }
    return value;
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+00:00)`; the fraction is truncated (chrono writes
/// nanoseconds), other offsets are rejected.
pub fn parse_rfc3339(text: []const u8) ?protocol.Timestamp {
    if (text.len < 20) return null;
    for ([_]usize{ 4, 7 }) |index| if (text[index] != '-') return null;
    if (text[10] != 'T' or text[13] != ':' or text[16] != ':') return null;
    const civil: Civil = .{
        .year = digits(text, 0, 4) orelse return null,
        .month = digits(text, 5, 2) orelse return null,
        .day = digits(text, 8, 2) orelse return null,
    };
    const hour = digits(text, 11, 2) orelse return null;
    const minute = digits(text, 14, 2) orelse return null;
    const second = digits(text, 17, 2) orelse return null;
    if (civil.month < 1 or civil.month > 12 or civil.day < 1 or civil.day > 31) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;
    var index: usize = 19;
    if (text[index] == '.') {
        index += 1;
        const fraction_start = index;
        while (index < text.len and std.ascii.isDigit(text[index])) index += 1;
        if (index == fraction_start or index - fraction_start > 9) return null;
    }
    const zone = text[index..];
    if (!std.mem.eql(u8, zone, "Z") and !std.mem.eql(u8, zone, "+00:00")) return null;
    const days = days_from_civil(civil) orelse return null;
    // Reject dates that do not exist (2026-02-30) by converting back.
    if (!std.meta.eql(civil_from_days(days), civil)) return null;
    return .{ .seconds = days * 86_400 + hour * 3600 + minute * 60 + second };
}

/// Writes `value` into `buffer`; the encoded JSON.
pub fn encode_to(comptime T: type, buffer: []u8, value: *const T) error{NoSpaceLeft}![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    encode(T, &writer, value) catch return error.NoSpaceLeft;
    assert(out.end <= buffer.len);
    return out.buffered();
}

test {
    _ = @import("codec_test.zig");
}
