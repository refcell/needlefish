//! Incremental HTTP/1.1 message parser over a caller-owned buffer.
//!
//! `parse_request` / `parse_response` look at the bytes received so far and return either
//! `.incomplete` (read more) or a complete message whose slices point into the buffer, plus
//! the number of bytes it consumed so pipelined messages can follow. Chunked bodies are
//! decoded in place (the decoded body overwrites the chunk framing), so the buffer is the
//! only memory used. Header count, header size, and body size are bounded by `Limits`.

const std = @import("std");
const assert = std.debug.assert;

pub const headers_max = 32;

pub const Limits = struct {
    head_size_max: u32 = 8 * 1024,
    body_size_max: u32 = 1024 * 1024,
};

pub const Error = error{
    InvalidRequestLine,
    InvalidStatusLine,
    InvalidHeader,
    InvalidVersion,
    InvalidContentLength,
    InvalidChunk,
    TooManyHeaders,
    HeadTooLarge,
    BodyTooLarge,
    UnsupportedTransferEncoding,
};

pub const Method = enum { GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH, other };

pub const Version = enum { http_1_0, http_1_1 };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Headers = struct {
    items: [headers_max]Header = undefined,
    count: u32 = 0,

    pub fn slice(headers: *const Headers) []const Header {
        return headers.items[0..headers.count];
    }

    /// Case-insensitive lookup of the first header named `name`.
    pub fn get(headers: *const Headers, name: []const u8) ?[]const u8 {
        for (headers.slice()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

pub const Request = struct {
    method: Method,
    method_text: []const u8,
    target: []const u8,
    version: Version,
    headers: Headers,
    body: []const u8,
    keep_alive: bool,
};

pub const Response = struct {
    status: u16,
    reason: []const u8,
    version: Version,
    headers: Headers,
    body: []const u8,
    keep_alive: bool,
};

pub fn Parsed(comptime Message: type) type {
    return union(enum) {
        incomplete,
        complete: struct { message: Message, consumed: u32 },
    };
}

const Head = struct {
    start_line: []const u8,
    headers: Headers,
    /// Offset of the first body byte.
    body_offset: u32,
};

/// Finds the end of the head and splits header lines. Returns null if incomplete.
fn parse_head(buffer: []const u8, limits: Limits) Error!?Head {
    const search = buffer[0..@min(buffer.len, limits.head_size_max)];
    const end = std.mem.find(u8, search, "\r\n\r\n") orelse {
        if (buffer.len >= limits.head_size_max) return error.HeadTooLarge;
        return null;
    };
    var head: Head = .{ .start_line = undefined, .headers = .{}, .body_offset = @intCast(end + 4) };
    var lines = std.mem.splitSequence(u8, buffer[0..end], "\r\n");
    head.start_line = lines.next().?;
    while (lines.next()) |line| {
        if (head.headers.count == headers_max) return error.TooManyHeaders;
        head.headers.items[head.headers.count] = try parse_header_line(line);
        head.headers.count += 1;
    }
    return head;
}

fn parse_header_line(line: []const u8) Error!Header {
    const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidHeader;
    const name = line[0..colon];
    if (name.len == 0) return error.InvalidHeader;
    for (name) |byte| if (!is_token_byte(byte)) return error.InvalidHeader;
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    for (value) |byte| {
        // Bare CR/LF or other control bytes inside a value enable request smuggling.
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidHeader;
    }
    return .{ .name = name, .value = value };
}

fn is_token_byte(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn parse_version(text: []const u8) Error!Version {
    if (std.mem.eql(u8, text, "HTTP/1.1")) return .http_1_1;
    if (std.mem.eql(u8, text, "HTTP/1.0")) return .http_1_0;
    return error.InvalidVersion;
}

fn parse_method(text: []const u8) Method {
    inline for (@typeInfo(Method).@"enum".field_names) |name| {
        if (comptime !std.mem.eql(u8, name, "other")) {
            if (std.mem.eql(u8, text, name)) return @field(Method, name);
        }
    }
    return .other;
}

fn keep_alive_of(version: Version, headers: *const Headers) bool {
    const connection = headers.get("connection") orelse return version == .http_1_1;
    if (std.ascii.eqlIgnoreCase(connection, "close")) return false;
    if (std.ascii.eqlIgnoreCase(connection, "keep-alive")) return true;
    return version == .http_1_1;
}

const BodyKind = union(enum) { none, length: u32, chunked };

fn body_kind(headers: *const Headers, limits: Limits) Error!BodyKind {
    var length: ?u32 = null;
    var chunked = false;
    for (headers.slice()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(header.value, "chunked")) {
                return error.UnsupportedTransferEncoding;
            }
            chunked = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            const value = parse_decimal(header.value) orelse return error.InvalidContentLength;
            // Conflicting duplicate lengths are a smuggling vector (RFC 9112 6.3).
            if (length != null and length.? != value) return error.InvalidContentLength;
            if (value > limits.body_size_max) return error.BodyTooLarge;
            length = @intCast(value);
        }
    }
    // Both framings at once is ambiguous; reject it.
    if (chunked and length != null) return error.InvalidContentLength;
    if (chunked) return .chunked;
    if (length) |l| return .{ .length = l };
    return .none;
}

fn parse_decimal(text: []const u8) ?u64 {
    if (text.len == 0 or text.len > 19) return null;
    var value: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
        value = value * 10 + (byte - '0');
    }
    return value;
}

const Body = struct { body: []const u8, end: u32 };

/// Returns the body and the offset just past the message, or null if incomplete.
fn parse_body(buffer: []u8, offset: u32, kind: BodyKind, limits: Limits) Error!?Body {
    switch (kind) {
        .none => return .{ .body = buffer[offset..offset], .end = offset },
        .length => |length| {
            if (buffer.len - offset < length) return null;
            return .{ .body = buffer[offset..][0..length], .end = offset + length };
        },
        .chunked => return decode_chunked(buffer, offset, limits),
    }
}

/// Decodes chunked framing in place. The decoded body is written starting at `offset`.
fn decode_chunked(buffer: []u8, offset: u32, limits: Limits) Error!?Body {
    var read: usize = offset;
    var written: usize = offset;
    // Each chunk consumes at least 3 bytes ("0\r\n"), so the buffer bounds the loop.
    var chunks: usize = 0;
    while (chunks <= buffer.len) : (chunks += 1) {
        const line_end = std.mem.findPos(u8, buffer, read, "\r\n") orelse {
            if (!chunk_size_pending_valid(buffer[read..])) return error.InvalidChunk;
            return null;
        };
        const size = parse_chunk_size(buffer[read..line_end]) orelse return error.InvalidChunk;
        read = line_end + 2;
        if (size == 0) {
            // Trailers are not supported: require the terminating CRLF right away.
            if (buffer.len - read < 2) return null;
            if (buffer[read] != '\r' or buffer[read + 1] != '\n') return error.InvalidChunk;
            return .{ .body = buffer[offset..written], .end = @intCast(read + 2) };
        }
        if (written - offset + size > limits.body_size_max) return error.BodyTooLarge;
        if (buffer.len - read < @as(usize, size) + 2) return null;
        if (buffer[read + size] != '\r' or buffer[read + size + 1] != '\n') {
            return error.InvalidChunk;
        }
        std.mem.copyForwards(u8, buffer[written..][0..size], buffer[read..][0..size]);
        written += size;
        read += size + 2;
    }
    unreachable;
}

/// Strict hex chunk size: 1-8 hex digits, optional `;extension` ignored. Rejects signs,
/// underscores, and whitespace that lenient parsers accept (a request smuggling vector).
/// Whether an unterminated chunk-size line can still become valid: at most
/// `chunk_line_pending_max` bytes, and its digits so far are 1-8 hex digits (a trailing CR
/// may be the first half of the CRLF). Lets a malformed line fail as soon as it arrives.
fn chunk_size_pending_valid(pending: []const u8) bool {
    if (pending.len > chunk_line_pending_max) return false;
    const line = if (pending.len > 0 and pending[pending.len - 1] == '\r')
        pending[0 .. pending.len - 1]
    else
        pending;
    const end = std.mem.findScalar(u8, line, ';') orelse line.len;
    if (end > 8) return false;
    if (end < line.len and end == 0) return false; // An extension without digits.
    for (line[0..end]) |digit| {
        _ = std.fmt.charToDigit(digit, 16) catch return false;
    }
    return true;
}

const chunk_line_pending_max = 32;

fn parse_chunk_size(line: []const u8) ?u32 {
    const end = std.mem.findScalar(u8, line, ';') orelse line.len;
    const digits = line[0..end];
    if (digits.len == 0 or digits.len > 8) return null;
    var value: u32 = 0;
    for (digits) |digit| {
        const nibble = std.fmt.charToDigit(digit, 16) catch return null;
        value = value << 4 | nibble;
    }
    return value;
}

/// Parses one request from the start of `buffer`. Chunked bodies are decoded in place, so
/// the buffer is modified only once the whole message has arrived.
pub fn parse_request(buffer: []u8, limits: Limits) Error!Parsed(Request) {
    const head = try parse_head(buffer, limits) orelse return .incomplete;
    var parts = std.mem.splitScalar(u8, head.start_line, ' ');
    const method_text = parts.next() orelse return error.InvalidRequestLine;
    const target = parts.next() orelse return error.InvalidRequestLine;
    const version_text = parts.next() orelse return error.InvalidRequestLine;
    if (parts.next() != null) return error.InvalidRequestLine;
    if (method_text.len == 0 or target.len == 0) return error.InvalidRequestLine;
    for (method_text) |byte| if (!is_token_byte(byte)) return error.InvalidRequestLine;
    for (target) |byte| if (byte <= 0x20 or byte == 0x7f) return error.InvalidRequestLine;
    const version = try parse_version(version_text);
    const kind = try body_kind(&head.headers, limits);
    if (kind == .chunked and !chunked_complete(buffer, head.body_offset, limits)) {
        return .incomplete;
    }
    const body = try parse_body(buffer, head.body_offset, kind, limits) orelse return .incomplete;
    return .{ .complete = .{
        .message = .{
            .method = parse_method(method_text),
            .method_text = method_text,
            .target = target,
            .version = version,
            .headers = head.headers,
            .body = body.body,
            .keep_alive = keep_alive_of(version, &head.headers),
        },
        .consumed = body.end,
    } };
}

/// Checks, without modifying the buffer, that a chunked body has fully arrived. Decoding in
/// place before then would corrupt framing needed by the next attempt.
/// Whether the chunked body is complete, or already known to fail: then "complete" lets
/// the decoder report the error (a malformed size line, or declared sizes over the body
/// limit) as soon as it arrives instead of after the whole body.
fn chunked_complete(buffer: []const u8, offset: u32, limits: Limits) bool {
    var read: usize = offset;
    var total: u64 = 0;
    var chunks: usize = 0;
    while (chunks <= buffer.len) : (chunks += 1) {
        const line_end = std.mem.findPos(u8, buffer, read, "\r\n") orelse {
            return !chunk_size_pending_valid(buffer[read..]);
        };
        // Malformed: report complete so the decoder returns the error.
        const size = parse_chunk_size(buffer[read..line_end]) orelse return true;
        read = line_end + 2;
        if (size == 0) return buffer.len - read >= 2;
        total += size;
        if (total > limits.body_size_max) return true;
        if (buffer.len - read < @as(usize, size) + 2) return false;
        read += size + 2;
    }
    return true;
}

/// Parses one response. `request_method` decides whether a body is expected (HEAD has none).
/// A response with a body but no declared length is delimited by connection close (RFC 9112
/// 6.3): it stays `.incomplete` here; finish it with `parse_response_at_eof`.
pub fn parse_response(
    buffer: []u8,
    limits: Limits,
    request_method: Method,
) Error!Parsed(Response) {
    return parse_response_framed(buffer, limits, request_method, false);
}

/// Like `parse_response`, after the peer closed the connection: a close-delimited body ends
/// at the end of `buffer`. Length-framed and chunked responses must already be complete.
pub fn parse_response_at_eof(
    buffer: []u8,
    limits: Limits,
    request_method: Method,
) Error!Parsed(Response) {
    return parse_response_framed(buffer, limits, request_method, true);
}

fn parse_response_framed(
    buffer: []u8,
    limits: Limits,
    request_method: Method,
    at_eof: bool,
) Error!Parsed(Response) {
    const head = try parse_head(buffer, limits) orelse return .incomplete;
    const line = head.start_line;
    if (line.len < 12 or line[8] != ' ') return error.InvalidStatusLine;
    const version = try parse_version(line[0..8]);
    const status = std.fmt.parseInt(u16, line[9..12], 10) catch return error.InvalidStatusLine;
    if (status < 100 or status > 599) return error.InvalidStatusLine;
    if (line.len > 12 and line[12] != ' ') return error.InvalidStatusLine;
    const reason = if (line.len > 13) line[13..] else "";
    const no_body = request_method == .HEAD or status < 200 or status == 204 or status == 304;
    const kind: BodyKind = if (no_body) .none else try body_kind(&head.headers, limits);
    const close_delimited = !no_body and kind == .none and
        head.headers.get("content-length") == null;
    var body: Body = undefined;
    if (close_delimited) {
        if (buffer.len - head.body_offset > limits.body_size_max) return error.BodyTooLarge;
        if (!at_eof) return .incomplete;
        const end: u32 = @intCast(buffer.len);
        body = .{ .body = buffer[head.body_offset..end], .end = end };
    } else {
        if (kind == .chunked and !chunked_complete(buffer, head.body_offset, limits)) {
            return .incomplete;
        }
        body = try parse_body(buffer, head.body_offset, kind, limits) orelse return .incomplete;
    }
    return .{ .complete = .{
        .message = .{
            .status = status,
            .reason = reason,
            .version = version,
            .headers = head.headers,
            .body = body.body,
            .keep_alive = !close_delimited and keep_alive_of(version, &head.headers),
        },
        .consumed = body.end,
    } };
}

test {
    _ = @import("parser_test.zig");
}
