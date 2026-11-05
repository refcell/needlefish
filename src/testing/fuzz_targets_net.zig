//! Network-facing fuzz targets owned by the dst-fuzz lane.
//!
//! Each target checks properties, not just "does not crash":
//!   - HTTP parser: structured requests and responses parse back to exactly the generated
//!     fields when fed in random chunks; every partial buffer reports the outcome the
//!     declared limits predict; two chunkings agree. Arbitrary bytes never break the
//!     limits, a complete message is a stable prefix (shorter is incomplete, longer is the
//!     same message), and errors stay errors when more bytes arrive.
//!   - WebSocket frames: encode then decode returns every header field and the payload for
//!     all three length encodings; every truncation is incomplete (or the limit error);
//!     arbitrary, mutated, and non-minimal frames match an RFC 6455 reference model, and
//!     accepted headers re-encode byte for byte.
//!   - Flashblocks: generated payloads survive JSON, stored brotli, and compressed brotli
//!     framing; truncated messages are rejected; any accepted input (arbitrary or mutated)
//!     reaches a write/decode fixed point; ids match a reference decimal parser.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const http = @import("../utilities/http/parser.zig");
const ws = @import("../utilities/ws/frame.zig");
const flashblocks = @import("../common/flashblocks/root.zig");
const comp = @import("../batcher/comp/root.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectError = std.testing.expectError;

// ------------------------------------------------------------------ drawing

/// A selector in `[0, count)`. Out-of-range Smith values read as zero, so small selectors
/// still spread over the seeded driver's skewed-small words.
fn draw(smith: *Smith, count: u32) u8 {
    assert(count > 0);
    assert(count <= 256);
    const value: u8 = @intCast(smith.value(u8) % count);
    assert(value < count);
    return value;
}

fn draw_u16(smith: *Smith, count: u32) u16 {
    assert(count > 0);
    assert(count <= 1 << 16);
    const value: u16 = @intCast(smith.value(u16) % count);
    assert(value < count);
    return value;
}

// ------------------------------------------------------------------ http: generation

const http_wire_max = 4096;
const http_extra_headers_max = 36; // A few past `http.headers_max` to reach TooManyHeaders.
const http_header_slots = http_extra_headers_max + 3;
const http_body_max = 300;
const http_junk_max = 16;
const http_chunks_max = 16;

const token_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ++
    "0123456789!#$%&'*+-.^_`|~";
const method_names = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH" };

comptime {
    assert(http_extra_headers_max > http.headers_max);
    for (method_names, 0..) |name, index| {
        assert(std.mem.eql(u8, @tagName(@as(http.Method, @fromBackingInt(@intCast(index)))), name));
    }
}

const Framing = enum { none, length, chunked };
const Connection = enum { absent, close, keep_alive, other };
const Casing = enum { exact, mixed };
const Eof = enum { streaming, at_eof };

const Wire = struct {
    bytes: [http_wire_max]u8 = undefined,
    length: u32 = 0,

    fn append(wire: *Wire, text: []const u8) void {
        assert(wire.length + text.len <= wire.bytes.len);
        @memcpy(wire.bytes[wire.length..][0..text.len], text);
        wire.length += @intCast(text.len);
    }

    fn append_byte(wire: *Wire, byte: u8) void {
        assert(wire.length < wire.bytes.len);
        wire.bytes[wire.length] = byte;
        wire.length += 1;
    }

    fn append_token(wire: *Wire, smith: *Smith, length_min: u8, length_max: u8) void {
        assert(length_min > 0 and length_min <= length_max);
        const length = length_min + draw(smith, length_max - length_min + 1);
        for (0..length) |_| wire.append_byte(token_alphabet[draw(smith, token_alphabet.len)]);
    }

    /// Optional whitespace (`OWS`) that the parser trims around header values.
    fn append_whitespace(wire: *Wire, smith: *Smith) void {
        const count = draw(smith, 3);
        for (0..count) |_| wire.append_byte(if (draw(smith, 2) == 0) ' ' else '\t');
    }
};

/// One generated message plus everything the parser must report for it.
const HttpCase = struct {
    wire: Wire = .{},
    response: bool = false,
    version: http.Version = .http_1_1,
    method: http.Method = .GET,
    method_text: []const u8 = "",
    target: []const u8 = "",
    status: u16 = 200,
    reason: []const u8 = "",
    request_method: http.Method = .GET,
    headers: [http_header_slots]http.Header = undefined,
    header_count: u32 = 0,
    connection: Connection = .absent,
    framing: Framing = .none,
    body: [http_body_max]u8 = undefined,
    /// Declared (content-length) and, unless the response has no body, sent body size.
    body_length: u32 = 0,
    head_size: u32 = 0,
    /// The message without trailing pipelined junk.
    message_size: u32 = 0,
    limits: http.Limits = .{},

    fn no_body(case: *const HttpCase) bool {
        if (!case.response) return false;
        const status = case.status;
        return case.request_method == .HEAD or status < 200 or status == 204 or status == 304;
    }

    fn close_delimited(case: *const HttpCase) bool {
        return case.response and !case.no_body() and case.framing == .none;
    }

    fn expected_body(case: *const HttpCase) []const u8 {
        if (case.no_body()) return "";
        if (!case.response and case.framing == .none) return "";
        return case.body[0..case.body_length];
    }

    fn keep_alive(case: *const HttpCase) bool {
        if (case.close_delimited()) return false;
        return switch (case.connection) {
            .close => false,
            .keep_alive => true,
            .absent, .other => case.version == .http_1_1,
        };
    }
};

fn randomize_case(bytes: []u8, smith: *Smith) void {
    for (bytes) |*byte| {
        if (draw(smith, 2) == 0) byte.* = std.ascii.toUpper(byte.*);
    }
}

fn emit_header(
    case: *HttpCase,
    smith: *Smith,
    name: []const u8,
    value: []const u8,
    casing: Casing,
) void {
    assert(case.header_count < http_header_slots);
    assert(name.len > 0);
    const wire = &case.wire;
    const name_start = wire.length;
    wire.append(name);
    const name_end = wire.length;
    wire.append(":");
    wire.append_whitespace(smith);
    const value_start = wire.length;
    wire.append(value);
    const value_end = wire.length;
    wire.append_whitespace(smith);
    wire.append("\r\n");
    if (casing == .mixed) {
        randomize_case(wire.bytes[name_start..name_end], smith);
        randomize_case(wire.bytes[value_start..value_end], smith);
    }
    case.headers[case.header_count] = .{
        .name = wire.bytes[name_start..name_end],
        .value = wire.bytes[value_start..value_end],
    };
    case.header_count += 1;
}

fn emit_extra_header(case: *HttpCase, smith: *Smith) void {
    var name: [14]u8 = undefined;
    name[0..2].* = "x-".*;
    const name_length = 3 + draw(smith, 12);
    for (name[2..name_length]) |*byte| byte.* = token_alphabet[draw(smith, token_alphabet.len)];
    var value: [20]u8 = undefined;
    const value_length = draw(smith, value.len + 1);
    for (value[0..value_length], 0..) |*byte, index| {
        // Visible ASCII, inner spaces and tabs, and obs-text; never CR, LF, or DEL.
        byte.* = 0x20 + draw(smith, 0xdf);
        if (byte.* == 0x7f) byte.* = '\t';
        const edge = index == 0 or index + 1 == value_length;
        if (edge and (byte.* == ' ' or byte.* == '\t')) byte.* = 'v';
    }
    emit_header(case, smith, name[0..name_length], value[0..value_length], .exact);
}

fn emit_special_headers(case: *HttpCase, smith: *Smith) void {
    switch (case.connection) {
        .absent => {},
        .close => emit_header(case, smith, "connection", "close", .mixed),
        .keep_alive => emit_header(case, smith, "connection", "keep-alive", .mixed),
        .other => emit_header(case, smith, "connection", "upgrade", .mixed),
    }
    switch (case.framing) {
        .none => {},
        .chunked => emit_header(case, smith, "transfer-encoding", "chunked", .mixed),
        .length => {
            const copies: u8 = if (draw(smith, 4) == 0) 2 else 1;
            for (0..copies) |_| {
                var text: [24]u8 = @splat('0');
                const zeros = draw(smith, 3);
                const digits = std.fmt.bufPrint(text[zeros..], "{d}", .{case.body_length}) catch
                    unreachable; // A u32 needs at most 10 digits.
                emit_header(case, smith, "content-length", text[0 .. zeros + digits.len], .mixed);
            }
        },
    }
}

fn emit_headers(case: *HttpCase, smith: *Smith) void {
    const extra = draw(smith, http_extra_headers_max + 1);
    const split = draw(smith, @as(u32, extra) + 1);
    var index: u8 = 0;
    while (index <= extra) : (index += 1) {
        if (index == split) emit_special_headers(case, smith);
        if (index < extra) emit_extra_header(case, smith);
    }
    assert(case.header_count >= extra);
}

fn version_text(version: http.Version) []const u8 {
    return switch (version) {
        .http_1_0 => "HTTP/1.0",
        .http_1_1 => "HTTP/1.1",
    };
}

fn method_of(text: []const u8) http.Method {
    for (method_names, 0..) |name, index| {
        if (std.mem.eql(u8, name, text)) return @fromBackingInt(@intCast(index));
    }
    return .other;
}

fn emit_request_line(case: *HttpCase, smith: *Smith) void {
    const wire = &case.wire;
    const choice = draw(smith, method_names.len + 1);
    const method_start = wire.length;
    if (choice < method_names.len) wire.append(method_names[choice]) else {
        wire.append_token(smith, 1, 8);
    }
    case.method_text = wire.bytes[method_start..wire.length];
    case.method = method_of(case.method_text);
    wire.append(" ");
    const target_start = wire.length;
    wire.append("/");
    const target_extra = draw(smith, 41);
    for (0..target_extra) |_| wire.append_byte(0x21 + draw(smith, 0x7e - 0x21 + 1));
    case.target = wire.bytes[target_start..wire.length];
    wire.append(" ");
    wire.append(version_text(case.version));
    wire.append("\r\n");
}

fn emit_status_line(case: *HttpCase, smith: *Smith) void {
    const wire = &case.wire;
    case.status = switch (draw(smith, 8)) {
        0 => 204,
        1 => 304,
        2 => 100 + draw_u16(smith, 100),
        else => 200 + draw_u16(smith, 400),
    };
    case.request_method = if (draw(smith, 4) == 0) .HEAD else .GET;
    wire.append(version_text(case.version));
    var digits: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&digits, "{d}", .{case.status}) catch unreachable; // 100..599.
    wire.append(" ");
    wire.append(&digits);
    case.reason = "";
    switch (draw(smith, 3)) {
        0 => {},
        1 => wire.append(" "),
        else => {
            wire.append(" ");
            const start = wire.length;
            const length = 1 + draw(smith, 20);
            for (0..length) |_| wire.append_byte(0x20 + draw(smith, 0x7e - 0x20 + 1));
            case.reason = wire.bytes[start..wire.length];
        },
    }
    wire.append("\r\n");
}

fn emit_chunk_size(wire: *Wire, smith: *Smith, size: u32) void {
    var text: [8]u8 = @splat('0');
    var digits: [8]u8 = undefined;
    const hex = if (draw(smith, 2) == 0)
        std.fmt.bufPrint(&digits, "{x}", .{size}) catch unreachable // Fits: size < 2^16.
    else
        std.fmt.bufPrint(&digits, "{X}", .{size}) catch unreachable;
    const zeros = @min(draw(smith, 3), text.len - hex.len);
    @memcpy(text[zeros..][0..hex.len], hex);
    wire.append(text[0 .. zeros + hex.len]);
    if (draw(smith, 4) == 0) {
        wire.append(";");
        wire.append_token(smith, 1, 6);
    }
    wire.append("\r\n");
}

fn emit_chunked_body(case: *HttpCase, smith: *Smith) void {
    const wire = &case.wire;
    var offset: u32 = 0;
    var chunk: u32 = 0;
    while (offset < case.body_length) : (chunk += 1) {
        assert(chunk < http_chunks_max);
        const remaining = case.body_length - offset;
        var size: u32 = 1 + draw_u16(smith, 128);
        if (chunk + 1 == http_chunks_max) size = remaining;
        size = @min(size, remaining);
        emit_chunk_size(wire, smith, size);
        wire.append(case.body[offset..][0..size]);
        wire.append("\r\n");
        offset += size;
    }
    emit_chunk_size(wire, smith, 0);
    wire.append("\r\n");
}

fn emit_body(case: *HttpCase, smith: *Smith) void {
    if (case.no_body()) return;
    switch (case.framing) {
        .none => if (case.response) case.wire.append(case.body[0..case.body_length]),
        .length => case.wire.append(case.body[0..case.body_length]),
        .chunked => emit_chunked_body(case, smith),
    }
}

fn generate_http_case(case: *HttpCase, smith: *Smith, prng: *Prng) void {
    // Shape first: Smith reads selectors from the front of the input, so draws made after
    // long byte runs would see an exhausted input. Bulk bytes come from `prng`.
    case.response = draw(smith, 2) == 1;
    case.version = if (draw(smith, 2) == 0) .http_1_0 else .http_1_1;
    case.framing = @fromBackingInt(@intCast(draw(smith, 3)));
    case.connection = @fromBackingInt(@intCast(draw(smith, 4)));
    if (case.framing != .none or case.response) {
        case.body_length = draw_u16(smith, http_body_max + 1);
        prng.fill(case.body[0..case.body_length]);
    }
    const junk = draw(smith, http_junk_max + 1);
    const limits_mode = draw(smith, 6);
    if (case.response) emit_status_line(case, smith) else emit_request_line(case, smith);
    emit_headers(case, smith);
    case.wire.append("\r\n");
    case.head_size = case.wire.length;
    emit_body(case, smith);
    case.message_size = case.wire.length;
    if (!case.close_delimited()) {
        prng.fill(case.wire.bytes[case.wire.length..][0..junk]);
        case.wire.length += junk;
    }
    switch (limits_mode) {
        0 => case.limits.head_size_max = case.head_size,
        1 => case.limits.head_size_max = case.head_size - 1,
        2 => case.limits.body_size_max = case.body_length,
        3 => case.limits.body_size_max = case.body_length -| 1,
        else => {},
    }
    assert(case.head_size > 0 and case.head_size <= case.message_size);
}

// ------------------------------------------------------------------ http: checking

const Outcome = union(enum) { incomplete, failure: http.Error, complete };

const Summary = union(enum) {
    incomplete,
    failure: http.Error,
    complete: struct { consumed: u32, body_hash: u64, header_count: u32 },
};

fn summarize(consumed: u32, body: []const u8, header_count: u32) Summary {
    assert(body.len <= consumed);
    return .{ .complete = .{
        .consumed = consumed,
        .body_hash = std.hash.Wyhash.hash(0, body),
        .header_count = header_count,
    } };
}

/// What the parser must report after `received` bytes of `case`, from the declared limits.
fn http_expected(case: *const HttpCase, received: u32, eof: Eof) Outcome {
    assert(received <= case.wire.length);
    const limits = case.limits;
    if (case.head_size > limits.head_size_max) {
        if (received >= limits.head_size_max) return .{ .failure = error.HeadTooLarge };
        return .incomplete;
    }
    if (received < case.head_size) return .incomplete;
    if (case.header_count > http.headers_max) return .{ .failure = error.TooManyHeaders };
    const framed = !case.no_body();
    const too_large = case.body_length > limits.body_size_max;
    if (framed and case.framing == .length and too_large) {
        return .{ .failure = error.BodyTooLarge };
    }
    if (case.close_delimited()) {
        if (received - case.head_size > limits.body_size_max) {
            return .{ .failure = error.BodyTooLarge };
        }
        return if (eof == .at_eof) .complete else .incomplete;
    }
    if (received < case.message_size) return .incomplete;
    if (framed and case.framing == .chunked and too_large) {
        return .{ .failure = error.BodyTooLarge };
    }
    return .complete;
}

fn expect_failure(expected: Outcome, err: http.Error) !Summary {
    if (expected != .failure) {
        std.debug.print("http: unexpected {s}, expected {s}\n", .{
            @errorName(err), @tagName(expected),
        });
        return error.TestUnexpectedResult;
    }
    try expectEqual(expected.failure, err);
    return .{ .failure = err };
}

fn expect_outcome(expected: Outcome, actual: std.meta.Tag(Outcome)) !void {
    if (expected != actual) {
        std.debug.print("http: got {s}, expected {s}\n", .{
            @tagName(actual), @tagName(expected),
        });
        return error.TestUnexpectedResult;
    }
}

fn expect_common(
    case: *const HttpCase,
    version: http.Version,
    headers: *const http.Headers,
    body: []const u8,
    keep_alive: bool,
) !void {
    try expectEqual(case.version, version);
    try expectEqual(case.header_count, headers.count);
    for (case.headers[0..case.header_count], headers.slice()) |want, got| {
        try expectEqualStrings(want.name, got.name);
        try expectEqualStrings(want.value, got.value);
    }
    try expectEqualSlices(u8, case.expected_body(), body);
    try expectEqual(case.keep_alive(), keep_alive);
}

fn check_request(case: *const HttpCase, buffer: []u8) !Summary {
    assert(!case.response);
    const expected = http_expected(case, @intCast(buffer.len), .streaming);
    const parsed = http.parse_request(buffer, case.limits) catch |err|
        return expect_failure(expected, err);
    switch (parsed) {
        .incomplete => {
            try expect_outcome(expected, .incomplete);
            return .incomplete;
        },
        .complete => |complete| {
            try expect_outcome(expected, .complete);
            const message = complete.message;
            try expectEqual(case.method, message.method);
            try expectEqualStrings(case.method_text, message.method_text);
            try expectEqualStrings(case.target, message.target);
            const keep_alive = message.keep_alive;
            try expect_common(case, message.version, &message.headers, message.body, keep_alive);
            try expectEqual(case.message_size, complete.consumed);
            return summarize(complete.consumed, message.body, message.headers.count);
        },
    }
}

fn check_response(case: *const HttpCase, buffer: []u8, eof: Eof) !Summary {
    assert(case.response);
    const expected = http_expected(case, @intCast(buffer.len), eof);
    const parsed = switch (eof) {
        .streaming => http.parse_response(buffer, case.limits, case.request_method),
        .at_eof => http.parse_response_at_eof(buffer, case.limits, case.request_method),
    } catch |err| return expect_failure(expected, err);
    switch (parsed) {
        .incomplete => {
            try expect_outcome(expected, .incomplete);
            return .incomplete;
        },
        .complete => |complete| {
            try expect_outcome(expected, .complete);
            const message = complete.message;
            try expectEqual(case.status, message.status);
            try expectEqualStrings(case.reason, message.reason);
            const keep_alive = message.keep_alive;
            try expect_common(case, message.version, &message.headers, message.body, keep_alive);
            const consumed = if (case.close_delimited()) buffer.len else case.message_size;
            try expectEqual(consumed, complete.consumed);
            return summarize(complete.consumed, message.body, message.headers.count);
        },
    }
}

/// Feeds `case` into one buffer in random chunks, re-parsing after each, as a connection
/// does. Parsing must leave an incomplete buffer intact (chunked bodies decode in place).
fn http_feed(case: *const HttpCase, work: []u8, prng: *Prng) !Summary {
    assert(work.len >= case.wire.length);
    var received: u32 = 0;
    var steps: u32 = 0;
    while (received < case.wire.length) : (steps += 1) {
        assert(steps < http_wire_max);
        const remaining = case.wire.length - received;
        const step_max: u64 = if (prng.chance(1, 4)) 4 else 96;
        const step: u32 = @intCast(@min(remaining, prng.range(1, step_max)));
        @memcpy(work[received..][0..step], case.wire.bytes[received..][0..step]);
        received += step;
        const summary = if (case.response)
            try check_response(case, work[0..received], .streaming)
        else
            try check_request(case, work[0..received]);
        if (summary != .incomplete) return summary;
    }
    // Only close-delimited responses wait for the end of the stream.
    try expect(case.close_delimited());
    @memcpy(work[0..received], case.wire.bytes[0..received]);
    return check_response(case, work[0..received], .at_eof);
}

fn fuzz_http_structured(_: void, smith: *Smith) anyerror!void {
    var case: HttpCase = .{};
    var prng = Prng.init(smith.value(u64));
    generate_http_case(&case, smith, &prng);
    var work_first: [http_wire_max]u8 = undefined;
    var work_second: [http_wire_max]u8 = undefined;
    const first = try http_feed(&case, &work_first, &prng);
    const second = try http_feed(&case, &work_second, &prng);
    try expect(first != .incomplete);
    try expect(std.meta.eql(first, second));
}

test "fuzz_targets_net: http structured messages parse back in any chunking" {
    try fuzz.run({}, fuzz_http_structured, .{ .iterations = 1024, .input_size_max = 2048 });
}

// ------------------------------------------------------------------ http: arbitrary bytes

const http_bytes_max = http_wire_max;

const http_fragments = [_][]const u8{
    "GET ",              "POST ",                      " / ",
    "HTTP/1.1",          "HTTP/1.0",                   "HTTP/1.1 200 OK",
    "HTTP/1.1 204",      " 101 ",                      "\r\n",
    "\r\n\r\n",          ": ",                         "Content-Length: ",
    "content-length:",   "Transfer-Encoding: chunked", "transfer-encoding: gzip",
    "Connection: close", "0",                          "5",
    "a",                 "FFFFFFFF",                   ";x=1",
    "-1",                " ",                          "\t",
    "\r",                "\n",                         "x",
    "\x00",              "\x7f",                       "0\r\n\r\n",
    "HTTP/1.1 600 X",    "HTTP/1.0 999",               "HTTP/1.1 099 Y",
};

/// Start lines, including out-of-range statuses, so fragment soup often has a valid head.
const http_start_lines = [_][]const u8{
    "GET / HTTP/1.1\r\n", "POST /x HTTP/1.0\r\n", "HTTP/1.1 200 OK\r\n",
    "HTTP/1.1 204\r\n",   "HTTP/1.1 600 X\r\n",   "HTTP/1.0 099\r\n",
};

const HttpKind = enum { request, response, response_at_eof };

/// A structured message with a few bytes overwritten, so mutations reach complete parses.
fn generate_http_mutated(smith: *Smith, prng: *Prng, buffer: []u8) u32 {
    var case: HttpCase = .{};
    generate_http_case(&case, smith, prng);
    const length = @min(case.wire.length, buffer.len);
    @memcpy(buffer[0..length], case.wire.bytes[0..length]);
    if (length == 0) return 0;
    const edits = draw(smith, 4);
    for (0..edits) |_| {
        const at = prng.below(length);
        buffer[at] = if (prng.chance(1, 2)) prng.int(u8) else "\r\n: 0;"[prng.below(6)];
    }
    return length;
}

fn generate_http_bytes(smith: *Smith, prng: *Prng, buffer: []u8) u32 {
    const mode = draw(smith, 3);
    if (mode == 2) return generate_http_mutated(smith, prng, buffer);
    if (mode == 0) {
        const length = draw_u16(smith, @intCast(buffer.len + 1));
        smith.bytes(buffer[0..length]);
        return length;
    }
    var length: u32 = 0;
    const start = draw(smith, http_start_lines.len + 1);
    if (start < http_start_lines.len) {
        const line = http_start_lines[start];
        assert(line.len + 2 <= buffer.len);
        @memcpy(buffer[0..line.len], line);
        length = @intCast(line.len);
        // Half the heads end right away; the rest collect fragments first.
        if (draw(smith, 2) == 0) {
            buffer[length..][0..2].* = "\r\n".*;
            length += 2;
        }
    }
    const count = draw(smith, 96);
    for (0..count) |_| {
        const pick = draw(smith, http_fragments.len + 1);
        if (pick == http_fragments.len) {
            if (length == buffer.len) break;
            buffer[length] = smith.value(u8);
            length += 1;
            continue;
        }
        const fragment = http_fragments[pick];
        if (length + fragment.len > buffer.len) break;
        @memcpy(buffer[length..][0..fragment.len], fragment);
        length += @intCast(fragment.len);
    }
    assert(length <= buffer.len);
    return length;
}

fn is_token_byte(byte: u8) bool {
    return std.mem.indexOfScalar(u8, token_alphabet, byte) != null;
}

fn inside(outer: []const u8, inner: []const u8) bool {
    const outer_start = @intFromPtr(outer.ptr);
    const inner_start = @intFromPtr(inner.ptr);
    return inner_start >= outer_start and inner_start + inner.len <= outer_start + outer.len;
}

fn check_header_invariants(head: []const u8, header: http.Header) !void {
    try expect(inside(head, header.name));
    try expect(inside(head, header.value));
    try expect(header.name.len > 0);
    for (header.name) |byte| try expect(is_token_byte(byte));
    for (header.value) |byte| try expect((byte >= 0x20 or byte == '\t') and byte != 0x7f);
    if (header.value.len > 0) {
        const first = header.value[0];
        const last = header.value[header.value.len - 1];
        try expect(first != ' ' and first != '\t' and last != ' ' and last != '\t');
    }
}

/// Bounds every complete message must respect, whatever bytes produced it.
fn check_message_invariants(
    buffer: []const u8,
    headers: *const http.Headers,
    body: []const u8,
    consumed: u32,
    limits: http.Limits,
) !Summary {
    try expect(consumed <= buffer.len);
    try expect(headers.count <= http.headers_max);
    try expect(body.len <= limits.body_size_max);
    try expect(inside(buffer[0..consumed], body));
    const body_start = @intFromPtr(body.ptr) - @intFromPtr(buffer.ptr);
    try expect(body_start >= 4);
    try expect(body_start <= limits.head_size_max);
    try expectEqualStrings("\r\n\r\n", buffer[body_start - 4 .. body_start]);
    for (headers.slice()) |header| try check_header_invariants(buffer[0..body_start], header);
    return summarize(consumed, body, headers.count);
}

fn parse_any(kind: HttpKind, buffer: []u8, limits: http.Limits, method: http.Method) !Summary {
    if (kind == .request) {
        const parsed = http.parse_request(buffer, limits) catch |err| return .{ .failure = err };
        const complete = switch (parsed) {
            .incomplete => return .incomplete,
            .complete => |complete| complete,
        };
        const message = complete.message;
        try expect(message.method_text.len > 0 and message.target.len > 0);
        for (message.method_text) |byte| try expect(is_token_byte(byte));
        for (message.target) |byte| try expect(byte > 0x20 and byte != 0x7f);
        try expectEqual(method_of(message.method_text), message.method);
        const consumed = complete.consumed;
        return check_message_invariants(buffer, &message.headers, message.body, consumed, limits);
    }
    const parsed = (if (kind == .response)
        http.parse_response(buffer, limits, method)
    else
        http.parse_response_at_eof(buffer, limits, method)) catch |err| return .{ .failure = err };
    const complete = switch (parsed) {
        .incomplete => return .incomplete,
        .complete => |complete| complete,
    };
    const message = complete.message;
    try expect(message.status >= 100 and message.status <= 599);
    if (method == .HEAD) try expectEqual(@as(usize, 0), message.body.len);
    const consumed = complete.consumed;
    return check_message_invariants(buffer, &message.headers, message.body, consumed, limits);
}

fn reparse(kind: HttpKind, input: []const u8, limits: http.Limits, method: http.Method) !Summary {
    var work: [http_bytes_max + http_junk_max]u8 = undefined;
    @memcpy(work[0..input.len], input);
    return parse_any(kind, work[0..input.len], limits, method);
}

fn check_http_bytes(
    kind: HttpKind,
    input: []const u8,
    extended: []const u8,
    limits: http.Limits,
    method: http.Method,
    prng: *Prng,
) !void {
    assert(extended.len >= input.len);
    const summary = try reparse(kind, input, limits, method);
    // At end of stream a close-delimited body is "whatever arrived": no prefix property.
    if (kind == .response_at_eof) return;
    switch (summary) {
        .incomplete => {
            // Incomplete means more bytes could still finish the head within its limit.
            if (input.len >= limits.head_size_max) {
                const search = input[0..limits.head_size_max];
                try expect(std.mem.find(u8, search, "\r\n\r\n") != null);
            }
        },
        // More bytes cannot repair an error.
        .failure => try expect(std.meta.eql(summary, try reparse(kind, extended, limits, method))),
        .complete => |complete| {
            const consumed = complete.consumed;
            try expect(std.meta.eql(summary, try reparse(kind, extended, limits, method)));
            const exact = try reparse(kind, input[0..consumed], limits, method);
            try expect(std.meta.eql(summary, exact));
            try expect(consumed > 0);
            try expect(try reparse(kind, input[0 .. consumed - 1], limits, method) == .incomplete);
            for (0..4) |_| {
                const prefix = prng.below(consumed);
                try expect(try reparse(kind, input[0..prefix], limits, method) == .incomplete);
            }
        },
    }
}

fn fuzz_http_bytes(_: void, smith: *Smith) anyerror!void {
    var pristine: [http_bytes_max + http_junk_max]u8 = undefined;
    var prng = Prng.init(smith.value(u64));
    const length = generate_http_bytes(smith, &prng, pristine[0..http_bytes_max]);
    const junk = draw(smith, http_junk_max + 1);
    prng.fill(pristine[length..][0..junk]);
    const limits: http.Limits = if (draw(smith, 2) == 0) .{} else .{
        .head_size_max = 1 + draw_u16(smith, 1024),
        .body_size_max = draw_u16(smith, 1024),
    };
    const method: http.Method = if (draw(smith, 4) == 0) .HEAD else .GET;
    const input = pristine[0..length];
    const extended = pristine[0 .. length + junk];
    inline for (.{ HttpKind.request, HttpKind.response, HttpKind.response_at_eof }) |kind| {
        try check_http_bytes(kind, input, extended, limits, method, &prng);
    }
}

test "fuzz_targets_net: http arbitrary bytes respect limits and prefix stability" {
    try fuzz.run({}, fuzz_http_bytes, .{ .iterations = 2048, .input_size_max = 2048 });
}

// ------------------------------------------------------------------ ws: round trip

const ws_valid_opcodes = [_]ws.Opcode{ .continuation, .text, .binary, .close, .ping, .pong };
const ws_size_boundaries = [_]u64{ 0, 1, 125, 126, 127, 0xffff, 0x10000 };
const ws_payload_max = 0x10000 + 512;
const ws_bytes_max = 1024;
const ws_wire_max = ws.header_size_max + ws_payload_max + 16;

const WsFixture = struct {
    payload: []u8,
    wire: []u8,
    pristine: []u8,

    fn init(allocator: std.mem.Allocator) !WsFixture {
        const payload = try allocator.alloc(u8, ws_payload_max);
        errdefer allocator.free(payload);
        const wire = try allocator.alloc(u8, ws_wire_max);
        errdefer allocator.free(wire);
        const pristine = try allocator.alloc(u8, ws_wire_max);
        return .{ .payload = payload, .wire = wire, .pristine = pristine };
    }

    fn deinit(fixture: *WsFixture, allocator: std.mem.Allocator) void {
        allocator.free(fixture.payload);
        allocator.free(fixture.wire);
        allocator.free(fixture.pristine);
        fixture.* = undefined;
    }
};

/// Minimal header size (RFC 6455 5.2): 7-bit, 16-bit, or 64-bit length, plus the mask.
fn ws_header_size(payload_size: u64, masked: bool) usize {
    const extended: usize = if (payload_size < 126) 0 else if (payload_size <= 0xffff) 2 else 8;
    const size = 2 + extended + @as(usize, if (masked) 4 else 0);
    assert(size <= ws.header_size_max);
    return size;
}

fn ws_draw_size(smith: *Smith, control: bool) u64 {
    if (control) return draw(smith, 126);
    return switch (draw(smith, 8)) {
        0 => ws_size_boundaries[draw(smith, ws_size_boundaries.len)],
        1 => 0x10000 + @as(u64, draw_u16(smith, 512)),
        2, 3 => 126 + @as(u64, draw_u16(smith, 2048)),
        else => draw(smith, 126),
    };
}

fn ws_draw_limits(smith: *Smith, payload_size: u64) ws.Limits {
    return switch (draw(smith, 4)) {
        0 => .{ .payload_size_max = payload_size },
        1 => .{ .payload_size_max = payload_size -| 1 },
        else => .{},
    };
}

/// Every strict prefix of a frame is incomplete, except that once the length is readable an
/// oversized payload is rejected before it is buffered.
fn ws_check_truncated(frame: []u8, role: ws.Role, limits: ws.Limits, size: u64, prng: *Prng) !void {
    assert(frame.len >= 2);
    const length_end = ws_header_size(size, false);
    const too_large = size > limits.payload_size_max;
    var prefix: usize = 0;
    var steps: usize = 0;
    while (prefix < frame.len) : (steps += 1) {
        assert(steps <= frame.len);
        const result = ws.decode_frame(frame[0..prefix], role, limits);
        if (too_large and prefix >= length_end) {
            try expectError(error.PayloadTooLarge, result);
        } else {
            try expect(try result == .incomplete);
        }
        const header_zone = prefix < ws.header_size_max + 2;
        const stride = if (header_zone) 1 else 1 + prng.below(frame.len / 8 + 1);
        prefix += @intCast(stride);
    }
    const last = ws.decode_frame(frame[0 .. frame.len - 1], role, limits);
    if (too_large) {
        try expectError(error.PayloadTooLarge, last);
    } else {
        try expect(try last == .incomplete);
    }
}

fn fuzz_ws_round_trip(fixture: *WsFixture, smith: *Smith) anyerror!void {
    const opcode = ws_valid_opcodes[draw(smith, ws_valid_opcodes.len)];
    const control = opcode.is_control();
    const fin = control or draw(smith, 4) != 0;
    const size = ws_draw_size(smith, control);
    const role: ws.Role = if (draw(smith, 2) == 0) .server else .client;
    const masked = role == .server;
    const limits = ws_draw_limits(smith, size);
    const junk = draw(smith, 9);
    var mask: [4]u8 = undefined;
    smith.bytes(&mask);
    var prng = Prng.init(smith.value(u64));
    const payload = fixture.payload[0..@intCast(size)];
    prng.fill(payload);
    var header: [ws.header_size_max]u8 = undefined;
    const header_size = ws.encode_header(&header, fin, opcode, size, if (masked) mask else null);
    try expectEqual(ws_header_size(size, masked), header_size);
    const total = header_size + payload.len;
    const wire = fixture.wire[0 .. total + junk];
    @memcpy(wire[0..header_size], header[0..header_size]);
    @memcpy(wire[header_size..total], payload);
    if (masked) ws.apply_mask(mask, wire[header_size..total], 0);
    prng.fill(wire[total..]);
    try ws_check_truncated(wire[0..total], role, limits, size, &prng);
    const other: ws.Role = if (masked) .client else .server;
    try expectError(error.MaskMismatch, ws.decode_frame(wire, other, limits));
    if (size > limits.payload_size_max) {
        return expectError(error.PayloadTooLarge, ws.decode_frame(wire, role, limits));
    }
    const frame = switch (try ws.decode_frame(wire, role, limits)) {
        .incomplete => return error.TestUnexpectedResult,
        .frame => |frame| frame,
    };
    try expectEqual(fin, frame.header.fin);
    try expectEqual(opcode, frame.header.opcode);
    try expectEqual(masked, frame.header.masked);
    try expectEqual(size, frame.header.payload_size);
    const mask_expected: [4]u8 = if (masked) mask else @splat(0);
    try expectEqualSlices(u8, &mask_expected, &frame.header.mask);
    try expectEqual(total, frame.size);
    try expect(frame.payload.ptr == wire.ptr + header_size);
    try expectEqualSlices(u8, payload, frame.payload);
}

test "fuzz_targets_net: ws frame encode decode round trip and truncation" {
    var fixture = try WsFixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    try fuzz.run(&fixture, fuzz_ws_round_trip, .{ .iterations = 1024 });
}

// ------------------------------------------------------------------ ws: reference model

const WsExpect = union(enum) {
    incomplete,
    failure: ws.DecodeError,
    frame: struct { header_size: usize, payload_size: u64 },
};

/// RFC 6455 5.2 decoding written independently of `ws.decode_frame`, in its check order.
fn ws_model(input: []const u8, role: ws.Role, limits: ws.Limits) WsExpect {
    if (input.len < 2) return .incomplete;
    if (input[0] & 0x70 != 0) return .{ .failure = error.ReservedBitsSet };
    const opcode = input[0] & 0x0f;
    const control = opcode >= 8;
    if (!(opcode <= 2 or (opcode >= 8 and opcode <= 10))) {
        return .{ .failure = error.UnknownOpcode };
    }
    const fin = input[0] & 0x80 != 0;
    const masked = input[1] & 0x80 != 0;
    if (masked != (role == .server)) return .{ .failure = error.MaskMismatch };
    const length_code = input[1] & 0x7f;
    if (control and !fin) return .{ .failure = error.ControlFrameFragmented };
    if (control and length_code > 125) return .{ .failure = error.ControlFrameTooLarge };
    var header_size: usize = 2;
    var payload_size: u64 = length_code;
    if (length_code == 126) {
        if (input.len < 4) return .incomplete;
        payload_size = @as(u64, input[2]) << 8 | input[3];
        if (payload_size < 126) return .{ .failure = error.NonMinimalLength };
        header_size = 4;
    } else if (length_code == 127) {
        if (input.len < 10) return .incomplete;
        payload_size = 0;
        for (input[2..10]) |byte| payload_size = payload_size << 8 | byte;
        if (payload_size < 0x10000 or payload_size >= 1 << 63) {
            return .{ .failure = error.NonMinimalLength };
        }
        header_size = 10;
    }
    if (payload_size > limits.payload_size_max) return .{ .failure = error.PayloadTooLarge };
    if (masked) header_size += 4;
    if (input.len < header_size or input.len - header_size < payload_size) return .incomplete;
    return .{ .frame = .{ .header_size = header_size, .payload_size = payload_size } };
}

const WsShape = enum { any, non_minimal };

/// A valid frame with a few header bytes flipped and an optional truncation.
fn ws_generate_mutated(buffer: []u8, smith: *Smith, prng: *Prng, role: ws.Role) u32 {
    const opcode = ws_valid_opcodes[draw(smith, ws_valid_opcodes.len)];
    const control = opcode.is_control();
    const fin = control or draw(smith, 2) == 0;
    const short = control or draw(smith, 2) == 0;
    const size: u64 = if (short) draw(smith, 126) else 126 + @as(u64, draw_u16(smith, 300));
    const masked = (role == .server) != (draw(smith, 8) == 0);
    var mask: [4]u8 = undefined;
    smith.bytes(&mask);
    var header: [ws.header_size_max]u8 = undefined;
    const header_size = ws.encode_header(&header, fin, opcode, size, if (masked) mask else null);
    const total: u32 = @intCast(header_size + size);
    assert(total <= buffer.len);
    @memcpy(buffer[0..header_size], header[0..header_size]);
    prng.fill(buffer[header_size..total]);
    const flips = draw(smith, 4);
    for (0..flips) |_| {
        const index = draw(smith, @min(total, ws.header_size_max));
        const bit = @as(u8, 1) << @intCast(draw(smith, 8));
        buffer[index] ^= if (draw(smith, 2) == 0) bit else prng.int(u8);
    }
    return if (draw(smith, 2) == 0) total else draw_u16(smith, total + 1);
}

/// A header whose 16-bit or 64-bit length could have used a shorter encoding.
fn ws_generate_non_minimal(buffer: []u8, smith: *Smith, role: ws.Role) u32 {
    const opcode = ws_valid_opcodes[draw(smith, ws_valid_opcodes.len)];
    const fin = draw(smith, 4) != 0;
    const mask_bit: u8 = if (role == .server) 0x80 else 0;
    buffer[0] = (if (fin) @as(u8, 0x80) else 0) | @backingInt(opcode);
    var length: u32 = 0;
    if (draw(smith, 2) == 0) {
        buffer[1] = mask_bit | 126;
        // Bias toward 125, the largest length the 7-bit form can carry.
        const value: u16 = if (draw(smith, 2) == 0) 125 else draw(smith, 126);
        std.mem.writeInt(u16, buffer[2..4], value, .big);
        length = 4;
    } else {
        buffer[1] = mask_bit | 127;
        const high: u64 = if (draw(smith, 2) == 0) 0 else 1 << 63;
        const low: u64 = if (draw(smith, 2) == 0) 0xffff else smith.value(u16);
        std.mem.writeInt(u64, buffer[2..10], high | low, .big);
        length = 10;
    }
    if (mask_bit != 0) {
        smith.bytes(buffer[length..][0..4]);
        length += 4;
    }
    const payload = draw(smith, 126);
    smith.bytes(buffer[length..][0..payload]);
    length += payload;
    return if (draw(smith, 2) == 0) length else draw_u16(smith, length + 1);
}

fn ws_check_frame(
    pristine: []u8,
    work: []u8,
    frame: anytype,
    model: anytype,
    role: ws.Role,
    limits: ws.Limits,
) !void {
    try expectEqual(model.header_size + model.payload_size, frame.size);
    try expectEqual(model.payload_size, frame.header.payload_size);
    try expect(frame.payload.ptr == work.ptr + model.header_size);
    try expectEqual(@as(usize, @intCast(model.payload_size)), frame.payload.len);
    for (frame.payload, 0..) |byte, index| {
        const raw = pristine[model.header_size + index];
        try expectEqual(raw ^ frame.header.mask[index % 4], byte);
    }
    var header: [ws.header_size_max]u8 = undefined;
    const mask: ?[4]u8 = if (frame.header.masked) frame.header.mask else null;
    const fin = frame.header.fin;
    const size = ws.encode_header(&header, fin, frame.header.opcode, model.payload_size, mask);
    // Accepted headers are canonical: re-encoding the fields gives the same bytes.
    try expectEqualSlices(u8, pristine[0..model.header_size], header[0..size]);
    for (0..frame.size) |prefix| {
        try expect(try ws.decode_frame(pristine[0..prefix], role, limits) == .incomplete);
    }
}

fn fuzz_ws_bytes(fixture: *WsFixture, smith: *Smith) anyerror!void {
    const role: ws.Role = if (draw(smith, 2) == 0) .server else .client;
    const limits: ws.Limits = if (draw(smith, 2) == 0) .{} else .{
        .payload_size_max = draw_u16(smith, 512),
    };
    const buffer = fixture.pristine[0..ws_bytes_max];
    const shape: WsShape = if (draw(smith, 3) == 2) .non_minimal else .any;
    var prng = Prng.init(smith.value(u64));
    const length: u32 = switch (shape) {
        .non_minimal => ws_generate_non_minimal(buffer, smith, role),
        .any => if (draw(smith, 2) == 0) ws_generate_mutated(buffer, smith, &prng, role) else blk: {
            const raw = draw_u16(smith, 65);
            smith.bytes(buffer[0..raw]);
            break :blk raw;
        },
    };
    const pristine = buffer[0..length];
    const work = fixture.wire[0..length];
    @memcpy(work, pristine);
    const expected = ws_model(pristine, role, limits);
    const actual = ws.decode_frame(work, role, limits) catch |err| {
        try expectEqual(std.meta.Tag(WsExpect).failure, std.meta.activeTag(expected));
        return expectEqual(expected.failure, err);
    };
    switch (actual) {
        .incomplete => {
            try expectEqual(std.meta.Tag(WsExpect).incomplete, std.meta.activeTag(expected));
        },
        .frame => |frame| {
            try expect(shape != .non_minimal);
            try expectEqual(std.meta.Tag(WsExpect).frame, std.meta.activeTag(expected));
            try ws_check_frame(pristine, work, frame, expected.frame, role, limits);
        },
    }
}

test "fuzz_targets_net: ws frame decode matches the RFC 6455 model" {
    var fixture = try WsFixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    try fuzz.run(&fixture, fuzz_ws_bytes, .{ .iterations = 4096 });
}

// ------------------------------------------------------------------ flashblocks

const fb_transactions_max = 4;
const fb_transaction_size_max = 48;
const fb_withdrawals_max = 3;
const fb_extra_size_max = 32;
const fb_text_max = 16 * 1024;
const fb_message_max = 2 * fb_text_max + 64;
const fb_raw_max = 1024;

const FlashblockStorage = struct {
    transactions: [fb_transactions_max][fb_transaction_size_max]u8 = undefined,
    transaction_slices: [fb_transactions_max][]const u8 = undefined,
    withdrawals: [fb_withdrawals_max]flashblocks.Withdrawal = undefined,
    extra: [fb_extra_size_max]u8 = undefined,
};

const FlashblocksFixture = struct {
    encoder: comp.brotli.Encoder,
    text: [fb_text_max]u8 = undefined,
    again: [fb_text_max]u8 = undefined,
    message: [fb_message_max]u8 = undefined,

    fn create(allocator: std.mem.Allocator) !*FlashblocksFixture {
        const fixture = try allocator.create(FlashblocksFixture);
        errdefer allocator.destroy(fixture);
        fixture.* = .{ .encoder = try comp.brotli.Encoder.init(allocator, fb_text_max) };
        return fixture;
    }

    fn destroy(fixture: *FlashblocksFixture, allocator: std.mem.Allocator) void {
        fixture.encoder.deinit(allocator);
        allocator.destroy(fixture);
    }
};

/// A data value: edge values by selector, otherwise uniform from `prng`.
fn data_u64(smith: *Smith, prng: *Prng) u64 {
    return switch (draw(smith, 8)) {
        0 => 0,
        1 => std.math.maxInt(u64),
        2 => prng.below(256),
        else => prng.int(u64),
    };
}

fn random_u256(smith: *Smith, prng: *Prng) u256 {
    return switch (draw(smith, 3)) {
        0 => draw(smith, 256),
        1 => data_u64(smith, prng),
        else => @as(u256, data_u64(smith, prng)) << 192 | @as(u256, data_u64(smith, prng)) << 64 |
            data_u64(smith, prng),
    };
}

fn random_base(smith: *Smith, prng: *Prng, storage: *FlashblockStorage) flashblocks.PayloadBase {
    var base: flashblocks.PayloadBase = undefined;
    prng.fill(&base.parent_beacon_block_root.bytes);
    prng.fill(&base.parent_hash.bytes);
    prng.fill(&base.fee_recipient.bytes);
    prng.fill(&base.prev_randao.bytes);
    base.block_number = data_u64(smith, prng);
    base.gas_limit = data_u64(smith, prng);
    base.timestamp = data_u64(smith, prng);
    const extra_length = draw(smith, fb_extra_size_max + 1);
    prng.fill(storage.extra[0..extra_length]);
    base.extra_data = storage.extra[0..extra_length];
    base.base_fee_per_gas = random_u256(smith, prng);
    return base;
}

fn random_delta(smith: *Smith, prng: *Prng, storage: *FlashblockStorage) flashblocks.Delta {
    var delta: flashblocks.Delta = undefined;
    prng.fill(&delta.state_root.bytes);
    prng.fill(&delta.receipts_root.bytes);
    prng.fill(&delta.logs_bloom.bytes);
    delta.gas_used = data_u64(smith, prng);
    prng.fill(&delta.block_hash.bytes);
    const transaction_count = draw(smith, fb_transactions_max + 1);
    for (0..transaction_count) |index| {
        const length = draw(smith, fb_transaction_size_max + 1);
        prng.fill(storage.transactions[index][0..length]);
        storage.transaction_slices[index] = storage.transactions[index][0..length];
    }
    delta.transactions = storage.transaction_slices[0..transaction_count];
    const withdrawal_count = draw(smith, fb_withdrawals_max + 1);
    for (storage.withdrawals[0..withdrawal_count]) |*withdrawal| {
        withdrawal.index = data_u64(smith, prng);
        withdrawal.validator_index = data_u64(smith, prng);
        prng.fill(&withdrawal.address.bytes);
        withdrawal.amount_gwei = data_u64(smith, prng);
    }
    delta.withdrawals = storage.withdrawals[0..withdrawal_count];
    prng.fill(&delta.withdrawals_root.bytes);
    delta.blob_gas_used = if (draw(smith, 2) == 0) null else data_u64(smith, prng);
    return delta;
}

fn random_flashblock(
    smith: *Smith,
    prng: *Prng,
    storage: *FlashblockStorage,
) flashblocks.Flashblock {
    var payload_id: [8]u8 = undefined;
    prng.fill(&payload_id);
    const index = data_u64(smith, prng);
    const base = if (draw(smith, 2) == 0) null else random_base(smith, prng, storage);
    const diff = random_delta(smith, prng, storage);
    const metadata: flashblocks.Metadata = .{
        .block_number = data_u64(smith, prng),
        .prev_flashblock_id = .{
            .block_number = data_u64(smith, prng),
            .index = data_u64(smith, prng),
        },
    };
    return .{
        .payload_id = payload_id,
        .index = index,
        .base = base,
        .diff = diff,
        .metadata = metadata,
    };
}

fn expect_base_equal(expected: flashblocks.PayloadBase, actual: flashblocks.PayloadBase) !void {
    const root = expected.parent_beacon_block_root.bytes;
    try expectEqualSlices(u8, &root, &actual.parent_beacon_block_root.bytes);
    try expectEqualSlices(u8, &expected.parent_hash.bytes, &actual.parent_hash.bytes);
    try expectEqualSlices(u8, &expected.fee_recipient.bytes, &actual.fee_recipient.bytes);
    try expectEqualSlices(u8, &expected.prev_randao.bytes, &actual.prev_randao.bytes);
    try expectEqual(expected.block_number, actual.block_number);
    try expectEqual(expected.gas_limit, actual.gas_limit);
    try expectEqual(expected.timestamp, actual.timestamp);
    try expectEqualSlices(u8, expected.extra_data, actual.extra_data);
    try expectEqual(expected.base_fee_per_gas, actual.base_fee_per_gas);
}

fn expect_delta_equal(expected: flashblocks.Delta, actual: flashblocks.Delta) !void {
    try expectEqualSlices(u8, &expected.state_root.bytes, &actual.state_root.bytes);
    try expectEqualSlices(u8, &expected.receipts_root.bytes, &actual.receipts_root.bytes);
    try expectEqualSlices(u8, &expected.logs_bloom.bytes, &actual.logs_bloom.bytes);
    try expectEqual(expected.gas_used, actual.gas_used);
    try expectEqualSlices(u8, &expected.block_hash.bytes, &actual.block_hash.bytes);
    try expectEqual(expected.transactions.len, actual.transactions.len);
    for (expected.transactions, actual.transactions) |want, got| {
        try expectEqualSlices(u8, want, got);
    }
    try expectEqual(expected.withdrawals.len, actual.withdrawals.len);
    for (expected.withdrawals, actual.withdrawals) |want, got| {
        try expectEqual(want.index, got.index);
        try expectEqual(want.validator_index, got.validator_index);
        try expectEqualSlices(u8, &want.address.bytes, &got.address.bytes);
        try expectEqual(want.amount_gwei, got.amount_gwei);
    }
    try expectEqualSlices(u8, &expected.withdrawals_root.bytes, &actual.withdrawals_root.bytes);
    try expectEqual(expected.blob_gas_used, actual.blob_gas_used);
}

fn expect_flashblock_equal(expected: flashblocks.Flashblock, actual: flashblocks.Flashblock) !void {
    try expectEqualSlices(u8, &expected.payload_id, &actual.payload_id);
    try expectEqual(expected.index, actual.index);
    try expectEqual(expected.base == null, actual.base == null);
    if (expected.base) |base| try expect_base_equal(base, actual.base.?);
    try expect_delta_equal(expected.diff, actual.diff);
    try expectEqual(expected.metadata.block_number, actual.metadata.block_number);
    const want_id = expected.metadata.prev_flashblock_id;
    const got_id = actual.metadata.prev_flashblock_id;
    try expectEqual(want_id.block_number, got_id.block_number);
    try expectEqual(want_id.index, got_id.index);
}

fn write_flashblock(buffer: []u8, flashblock: flashblocks.Flashblock) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try flashblocks.write_json(&writer, flashblock);
    const text = writer.buffered();
    assert(text.len > 0 and text[0] == '{');
    return text;
}

/// Wraps JSON text as a WebSocket message: plain, whitespace-led, or brotli (stored or
/// compressed, without the batcher's channel version byte).
fn frame_message(fixture: *FlashblocksFixture, smith: *Smith, text: []const u8) ![]const u8 {
    assert(text.len <= fb_text_max);
    const out = fixture.message[0..];
    switch (draw(smith, 4)) {
        0 => {
            @memcpy(out[0..text.len], text);
            return out[0..text.len];
        },
        1 => {
            const lead = 1 + draw(smith, 4);
            for (out[0..lead]) |*byte| byte.* = " \t\r\n"[draw(smith, 4)];
            @memcpy(out[lead..][0..text.len], text);
            return out[0 .. lead + text.len];
        },
        2 => return (try comp.brotli_compress_stored(text, out))[1..],
        else => return fixture.encoder.compress(text, out),
    }
}

fn expect_rejected(arena: std.mem.Allocator, message: []const u8) !void {
    if (flashblocks.decode_message(arena, message)) |_| {
        std.debug.print("flashblocks: accepted truncated message of {d} bytes\n", .{message.len});
        return error.TestUnexpectedResult;
    } else |_| {}
}

fn fuzz_flashblock_round_trip(fixture: *FlashblocksFixture, smith: *Smith) anyerror!void {
    var storage: FlashblockStorage = .{};
    var prng = Prng.init(smith.value(u64));
    const original = random_flashblock(smith, &prng, &storage);
    const text = try write_flashblock(&fixture.text, original);
    const message = try frame_message(fixture, smith, text);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const decoded = try flashblocks.decode_message(arena, message);
    try expect_flashblock_equal(original, decoded);
    try expectEqualStrings(text, try write_flashblock(&fixture.again, decoded));
    try expect_rejected(arena, message[0 .. message.len - 1]);
    for (0..3) |_| try expect_rejected(arena, message[0..@intCast(prng.below(message.len))]);
}

test "fuzz_targets_net: flashblock write and decode round trip" {
    const fixture = try FlashblocksFixture.create(std.testing.allocator);
    defer fixture.destroy(std.testing.allocator);
    const options: fuzz.Options = .{ .iterations = 512, .input_size_max = 4096 };
    try fuzz.run(fixture, fuzz_flashblock_round_trip, options);
}

const json_alphabet = "0123456789abcdefxX\":,{}[] -";
const hex_alphabet = "0123456789abcdefABCDEF";

fn mutate_text(buffer: []u8, length_start: usize, smith: *Smith, prng: *Prng) usize {
    var length = length_start;
    const edits = draw(smith, 4);
    for (0..edits) |_| {
        if (length == 0) break;
        const at = draw_u16(smith, @intCast(length));
        switch (draw(smith, 4)) {
            0 => buffer[at] = prng.int(u8),
            1 => buffer[at] = json_alphabet[draw(smith, json_alphabet.len)],
            2 => buffer[at] = hex_alphabet[draw(smith, hex_alphabet.len)],
            else => {
                const cut = @min(length - at, draw(smith, 16));
                std.mem.copyForwards(u8, buffer[at .. length - cut], buffer[at + cut .. length]);
                length -= cut;
            },
        }
    }
    assert(length <= length_start);
    return length;
}

/// Arbitrary or mutated messages: any accepted input decodes, re-encodes, and decodes again
/// to the same flashblock and the same bytes.
fn fuzz_flashblock_any(fixture: *FlashblocksFixture, smith: *Smith) anyerror!void {
    var message: []const u8 = undefined;
    var prng = Prng.init(smith.value(u64));
    if (draw(smith, 3) == 0) {
        const length = draw_u16(smith, fb_raw_max + 1);
        smith.bytes(fixture.message[0..length]);
        message = fixture.message[0..length];
    } else {
        var storage: FlashblockStorage = .{};
        const original = random_flashblock(smith, &prng, &storage);
        const text = try write_flashblock(&fixture.text, original);
        const length = mutate_text(&fixture.text, text.len, smith, &prng);
        message = try frame_message(fixture, smith, fixture.text[0..length]);
    }
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const decoded = flashblocks.decode_message(arena, message) catch return;
    const text = try write_flashblock(&fixture.text, decoded);
    const again = try flashblocks.decode_message(arena, text);
    try expect_flashblock_equal(decoded, again);
    try expectEqualStrings(text, try write_flashblock(&fixture.again, again));
}

test "fuzz_targets_net: flashblock decode of arbitrary input reaches a fixed point" {
    const fixture = try FlashblocksFixture.create(std.testing.allocator);
    defer fixture.destroy(std.testing.allocator);
    try fuzz.run(fixture, fuzz_flashblock_any, .{ .iterations = 1024, .input_size_max = 4096 });
}

const id_alphabet = "0123456789-_+ x";

/// `<digits>-<digits>` with up to 21 digits per side (u64 overflows at 20), sometimes with
/// one byte replaced from `id_alphabet`.
fn generate_id_text(buffer: *[48]u8, smith: *Smith, prng: *Prng) usize {
    const left = draw(smith, 22);
    const right = draw(smith, 22);
    const length: usize = left + 1 + right;
    assert(length <= buffer.len);
    for (buffer[0..length]) |*byte| byte.* = '0' + draw(smith, 10);
    buffer[left] = '-';
    if (draw(smith, 2) == 0) {
        buffer[prng.below(length)] = id_alphabet[draw(smith, id_alphabet.len)];
    }
    return length;
}

/// base/base parses each half with Rust's `u64::from_str`: an optional '+', then one or
/// more ASCII digits, no overflow.
fn reference_decimal(text: []const u8) ?u64 {
    const digits = if (text.len > 1 and text[0] == '+') text[1..] else text;
    if (digits.len == 0) return null;
    var value: u64 = 0;
    for (digits) |byte| {
        if (byte < '0' or byte > '9') return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, byte - '0') catch return null;
    }
    return value;
}

fn reference_id(text: []const u8) ?flashblocks.FlashblockId {
    const dash = std.mem.indexOfScalar(u8, text, '-') orelse return null;
    const block_number = reference_decimal(text[0..dash]) orelse return null;
    const index = reference_decimal(text[dash + 1 ..]) orelse return null;
    return .{ .block_number = block_number, .index = index };
}

fn fuzz_flashblock_id(_: void, smith: *Smith) anyerror!void {
    const id: flashblocks.FlashblockId = .{
        .block_number = smith.value(u64),
        .index = smith.value(u64),
    };
    var buffer: [48]u8 = undefined;
    const formatted = id.format(&buffer);
    try expectEqual(id, try flashblocks.FlashblockId.parse(formatted));
    try expectEqual(id, reference_id(formatted).?);
    var input: [48]u8 = undefined;
    var prng = Prng.init(smith.value(u64));
    const length = generate_id_text(&input, smith, &prng);
    const text = input[0..length];
    const actual = flashblocks.FlashblockId.parse(text) catch null;
    try expectEqual(reference_id(text), actual);
}

test "fuzz_targets_net: flashblock id matches the reference parser" {
    try fuzz.run({}, fuzz_flashblock_id, .{ .iterations = 8192 });
}
