//! JSON-RPC method extraction for the allowlist: reads the `method` and `id` of a single
//! request or of every entry of a batch, without allocating (`utilities/json` Scanner).
//!
//! The proxy must see the same method the upstream will execute, so the extractor is
//! stricter than a plain JSON-RPC parser. Keys are matched after unescaping and ignoring
//! ASCII case (go-ethereum decodes with `encoding/json`, which accepts `"Method"`), and a
//! request with more than one `method` key is invalid instead of first-or-last-wins.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const allowlist_module = @import("allowlist.zig");

pub const batch_max = 100;
pub const name_size_max = allowlist_module.name_size_max;

pub const Error = error{ ParseError, InvalidRequest, BatchTooLarge };

pub const Entry = struct {
    /// The decoded method name, if it fits and is a plain name.
    name_buffer: [name_size_max]u8 = undefined,
    name_size: u8 = 0,
    /// Raw JSON text of `id` (a string with its quotes, a number, or `null`).
    id: []const u8 = "null",
    /// Byte range of the request object in the body (`{` through `}`).
    start: u32 = 0,
    end: u32 = 0,

    pub fn name(entry: *const Entry) ?[]const u8 {
        if (entry.name_size == 0) return null;
        assert(entry.name_size <= name_size_max);
        return entry.name_buffer[0..entry.name_size];
    }
};

pub const Summary = struct {
    batch: bool,
    count: u32,
};

/// Extracts every request of `body` into `entries`.
pub fn extract(body: []const u8, entries: *[batch_max]Entry) Error!Summary {
    var scanner = json.Scanner.init(body);
    const first = scanner.next() catch return error.ParseError;
    var summary: Summary = .{ .batch = false, .count = 0 };
    switch (first.tag) {
        .object_begin => {
            entries[0] = try extract_object(&scanner, body);
            summary.count = 1;
        },
        .array_begin => {
            summary.batch = true;
            summary.count = try extract_batch(&scanner, body, entries);
        },
        else => return error.InvalidRequest,
    }
    const last = scanner.next() catch return error.ParseError;
    assert(last.tag == .end);
    assert(summary.count >= 1 and summary.count <= batch_max);
    return summary;
}

fn extract_batch(scanner: *json.Scanner, body: []const u8, entries: *[batch_max]Entry) Error!u32 {
    var count: u32 = 0;
    // Each element consumes at least one byte, so input length bounds the loop.
    while (true) {
        assert(count <= body.len);
        const token = scanner.next() catch return error.ParseError;
        if (token.tag == .array_end) break;
        if (token.tag != .object_begin) return error.InvalidRequest;
        if (count == batch_max) return error.BatchTooLarge;
        entries[count] = try extract_object(scanner, body);
        count += 1;
    }
    if (count == 0) return error.InvalidRequest;
    assert(count <= batch_max);
    return count;
}

const Key = enum { method, id, other };

/// Reads one request object whose `{` was just consumed.
fn extract_object(scanner: *json.Scanner, body: []const u8) Error!Entry {
    assert(scanner.offset() > 0 and body[scanner.offset() - 1] == '{');
    var entry: Entry = .{ .start = scanner.offset() - 1 };
    var method_seen = false;
    var id_seen = false;
    var members: u32 = 0;
    while (true) : (members += 1) {
        assert(members <= body.len);
        const key_token = scanner.next() catch return error.ParseError;
        if (key_token.tag == .object_end) break;
        assert(key_token.tag == .string and key_token.key);
        const value = scanner.next() catch return error.ParseError;
        switch (classify(key_token)) {
            .method => {
                if (method_seen) return error.InvalidRequest;
                method_seen = true;
                if (value.tag != .string) return error.InvalidRequest;
                set_name(&entry, value);
            },
            .id => {
                if (id_seen) return error.InvalidRequest;
                id_seen = true;
                entry.id = try id_text(body, value);
            },
            .other => scanner.skip(value) catch return error.ParseError,
        }
    }
    if (!method_seen) return error.InvalidRequest;
    entry.end = scanner.offset();
    assert(entry.end > entry.start and body[entry.end - 1] == '}');
    return entry;
}

fn classify(key_token: json.Token) Key {
    var buffer: [8]u8 = undefined;
    const key = json.unescape(key_token, &buffer) catch return .other;
    if (std.ascii.eqlIgnoreCase(key, "method")) return .method;
    if (std.ascii.eqlIgnoreCase(key, "id")) return .id;
    return .other;
}

/// Leaves the name empty (never allowed) when it does not decode to a plain method name.
fn set_name(entry: *Entry, value: json.Token) void {
    assert(value.tag == .string);
    const decoded = json.unescape(value, &entry.name_buffer) catch return;
    if (!allowlist_module.valid_name(decoded)) return;
    assert(decoded.len <= name_size_max);
    if (decoded.ptr != &entry.name_buffer) @memcpy(entry.name_buffer[0..decoded.len], decoded);
    entry.name_size = @intCast(decoded.len);
}

fn id_text(body: []const u8, value: json.Token) Error![]const u8 {
    switch (value.tag) {
        .number => return value.bytes,
        .null => return "null",
        .string => {
            // Re-include the quotes: the token bytes are a slice of `body`.
            const start = @intFromPtr(value.bytes.ptr) - @intFromPtr(body.ptr) - 1;
            const end = start + value.bytes.len + 2;
            assert(body[start] == '"' and body[end - 1] == '"');
            return body[start..end];
        },
        else => return error.InvalidRequest,
    }
}

/// Writes a JSON-RPC error response object.
pub fn write_error(
    out: *std.Io.Writer,
    id: []const u8,
    code: i32,
    message: []const u8,
) std.Io.Writer.Error!void {
    assert(id.len > 0);
    assert(code < 0);
    try out.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},\"error\":{{\"code\":{d},\"message\":", .{
        id,
        code,
    });
    try json.write_string_escaped(out, message);
    try out.writeAll("}}");
}

const testing = std.testing;

fn extract_test(body: []const u8, entries: *[batch_max]Entry) Error!Summary {
    return extract(body, entries);
}

test "methods: single request" {
    var entries: [batch_max]Entry = undefined;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":\"a\\\"b\",\"method\":\"eth_call\",\"params\":[{}]}";
    const summary = try extract_test(body, &entries);
    try testing.expect(!summary.batch);
    try testing.expectEqual(@as(u32, 1), summary.count);
    try testing.expectEqualStrings("eth_call", entries[0].name().?);
    try testing.expectEqualStrings("\"a\\\"b\"", entries[0].id);
    _ = try extract_test("{\"method\":\"x\"}", &entries);
    try testing.expectEqualStrings("null", entries[0].id);
}

test "methods: batch, escapes, and case-insensitive keys" {
    var entries: [batch_max]Entry = undefined;
    const body = "[{\"id\":1,\"method\":\"eth_chainId\"}," ++
        "{\"ID\":2,\"Me\\u0074hod\":\"eth_\\u0063all\"}]";
    const summary = try extract_test(body, &entries);
    try testing.expect(summary.batch);
    try testing.expectEqual(@as(u32, 2), summary.count);
    try testing.expectEqualStrings("eth_chainId", entries[0].name().?);
    try testing.expectEqualStrings("eth_call", entries[1].name().?);
    try testing.expectEqualStrings("2", entries[1].id);
    try testing.expectEqualStrings(body[1..32], body[entries[0].start..entries[0].end]);
    try testing.expectEqual(@as(u32, body.len - 1), entries[1].end);
    // A method that is not a plain name extracts but never matches.
    _ = try extract_test("{\"method\":\"eth call\"}", &entries);
    try testing.expectEqual(@as(?[]const u8, null), entries[0].name());
}

test "methods: invalid shapes" {
    var entries: [batch_max]Entry = undefined;
    const invalid = [_][]const u8{
        "[]",                           "[1]",
        "{\"id\":1}",                   "\"eth_call\"",
        "{\"method\":1}",               "{\"method\":\"a\",\"METHOD\":\"b\"}",
        "{\"method\":\"a\",\"id\":{}}", "{\"method\":\"a\",\"id\":1,\"id\":2}",
    };
    for (invalid) |body| {
        try testing.expectError(error.InvalidRequest, extract_test(body, &entries));
    }
    try testing.expectError(error.ParseError, extract_test("{\"method\":", &entries));
    try testing.expectError(error.ParseError, extract_test("{\"method\":\"a\"} x", &entries));
    var big: [2 + (batch_max + 1) * 15]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&big);
    try writer.writeAll("[");
    for (0..batch_max + 1) |index| {
        if (index > 0) try writer.writeAll(",");
        try writer.writeAll("{\"method\":\"a\"}");
    }
    try writer.writeAll("]");
    try testing.expectError(error.BatchTooLarge, extract_test(writer.buffered(), &entries));
}

test "methods: write_error" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write_error(&writer, "7", -32601, "method not allowed");
    const expected = "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32601," ++
        "\"message\":\"method not allowed\"}}";
    try testing.expectEqualStrings(expected, writer.buffered());
}

/// Never crashes; an accepted body is valid JSON and every extracted name is a plain name
/// that appears in the body (literally or escaped) and every id is valid JSON.
fn check_arbitrary(body: []const u8) !void {
    var entries: [batch_max]Entry = undefined;
    const summary = extract(body, &entries) catch return;
    try json.validate(body);
    try testing.expect(summary.count >= 1 and summary.count <= batch_max);
    for (entries[0..summary.count]) |*entry| {
        try json.validate(entry.id);
        if (entry.name()) |name| try testing.expect(allowlist_module.valid_name(name));
        try json.validate(body[entry.start..entry.end]);
    }
}

test "methods: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x3e7);
    const pieces = [_][]const u8{
        "{",            "}", "[",          "]",
        ",",            ":", "\"method\"", "\"id\"",
        "\"eth_call\"", "1", "null",       "\"a\\u0062\"",
        "\"Method\"",   " ", "\"",
    };
    var input: [256]u8 = undefined;
    for (0..4000) |_| {
        var writer: std.Io.Writer = .fixed(&input);
        const parts = prng.below(24);
        for (0..parts) |_| writer.writeAll(pieces[prng.below(pieces.len)]) catch break;
        try check_arbitrary(writer.buffered());
    }
}

fn fuzz_extract(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try check_arbitrary(input[0..size]);
}

test "methods: fuzz extract" {
    try testing.fuzz({}, fuzz_extract, .{});
}
