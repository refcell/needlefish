//! HTTP parser tests: requests, responses, pipelining, chunked bodies, limits, smuggling
//! rejections, incremental feeding, and fuzz targets.

const std = @import("std");
const parser = @import("parser.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectError = std.testing.expectError;

fn request_of(text: []const u8, buffer: []u8) !parser.Request {
    @memcpy(buffer[0..text.len], text);
    const parsed = try parser.parse_request(buffer[0..text.len], .{});
    return parsed.complete.message;
}

test "http: parses a JSON-RPC POST" {
    var buffer: [512]u8 = undefined;
    const request = try request_of("POST / HTTP/1.1\r\nHost: localhost:8545\r\n" ++
        "Content-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}", &buffer);
    try expectEqual(parser.Method.POST, request.method);
    try expectEqualStrings("/", request.target);
    try expectEqual(parser.Version.http_1_1, request.version);
    try expectEqualStrings("{\"a\":1}", request.body);
    try expectEqualStrings("application/json", request.headers.get("content-type").?);
    try expect(request.keep_alive);
}

test "http: incomplete until the whole message arrives" {
    const text = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    var buffer: [128]u8 = undefined;
    @memcpy(buffer[0..text.len], text);
    for (0..text.len) |size| {
        const parsed = try parser.parse_request(buffer[0..size], .{});
        try expect(parsed == .incomplete);
    }
    const parsed = try parser.parse_request(buffer[0..text.len], .{});
    try expectEqual(@as(u32, text.len), parsed.complete.consumed);
}

test "http: pipelined requests" {
    const text = "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    var buffer: [128]u8 = undefined;
    @memcpy(buffer[0..text.len], text);
    const first = (try parser.parse_request(buffer[0..text.len], .{})).complete;
    try expectEqualStrings("/a", first.message.target);
    const rest = buffer[first.consumed..text.len];
    const second = (try parser.parse_request(rest, .{})).complete;
    try expectEqualStrings("/b", second.message.target);
    try expect(second.message.keep_alive);
    try expectEqual(@as(usize, text.len), first.consumed + second.consumed);
}

test "http: chunked body decoded in place" {
    var buffer: [256]u8 = undefined;
    const request = try request_of("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n6;ext=1\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n", &buffer);
    try expectEqualStrings("Wikipedia in \r\n\r\nchunks.", request.body);
}

test "http: rejects smuggling and malformed input" {
    const post = "POST / HTTP/1.1\r\n";
    const chunked = post ++ "Transfer-Encoding: chunked\r\n\r\n";
    const both_framings = chunked[0 .. chunked.len - 2] ++ "Content-Length: 3\r\n\r\n";
    const cases = [_]struct { []const u8, parser.Error }{
        .{ post ++ "Content-Length: 1\r\nContent-Length: 2\r\n\r\nab", error.InvalidContentLength },
        .{ both_framings, error.InvalidContentLength },
        .{ post ++ "Transfer-Encoding: gzip\r\n\r\n", error.UnsupportedTransferEncoding },
        .{ post ++ "Content-Length: +1\r\n\r\na", error.InvalidContentLength },
        .{ chunked ++ "+1\r\na\r\n0\r\n\r\n", error.InvalidChunk },
        .{ chunked ++ "1_0\r\na\r\n0\r\n\r\n", error.InvalidChunk },
        .{ "GET / HTTP/2.0\r\n\r\n", error.InvalidVersion },
        .{ "GET /\r\n\r\n", error.InvalidRequestLine },
        .{ "GET  / HTTP/1.1\r\n\r\n", error.InvalidRequestLine },
        .{ "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n", error.InvalidHeader },
        .{ "GET / HTTP/1.1\r\nNoColon\r\n\r\n", error.InvalidHeader },
        .{ "GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", error.InvalidHeader },
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        @memcpy(buffer[0..case[0].len], case[0]);
        try expectError(case[1], parser.parse_request(buffer[0..case[0].len], .{}));
    }
}

test "http: limits" {
    var buffer: [256]u8 = undefined;
    const big = "POST / HTTP/1.1\r\nContent-Length: 1000\r\n\r\n";
    @memcpy(buffer[0..big.len], big);
    try expectError(error.BodyTooLarge, parser.parse_request(buffer[0..big.len], .{
        .body_size_max = 999,
    }));
    @memset(&buffer, 'a');
    try expectError(error.HeadTooLarge, parser.parse_request(&buffer, .{ .head_size_max = 64 }));
    var many: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&many);
    try writer.writeAll("GET / HTTP/1.1\r\n");
    for (0..parser.headers_max + 1) |index| try writer.print("H{d}: v\r\n", .{index});
    try writer.writeAll("\r\n");
    try expectError(error.TooManyHeaders, parser.parse_request(writer.buffered(), .{}));
}

test "http: responses" {
    var buffer: [256]u8 = undefined;
    const text = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 204 No Content\r\n\r\n";
    @memcpy(buffer[0..text.len], text);
    const first = (try parser.parse_response(buffer[0..text.len], .{}, .POST)).complete;
    try expectEqual(@as(u16, 200), first.message.status);
    try expectEqualStrings("OK", first.message.reason);
    try expectEqualStrings("ok", first.message.body);
    const rest = buffer[first.consumed..text.len];
    const second = (try parser.parse_response(rest, .{}, .POST)).complete;
    try expectEqual(@as(u16, 204), second.message.status);
    try expectEqual(@as(usize, 0), second.message.body.len);

    const head = "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n";
    @memcpy(buffer[0..head.len], head);
    const no_body = (try parser.parse_response(buffer[0..head.len], .{}, .HEAD)).complete;
    try expectEqual(@as(usize, 0), no_body.message.body.len);
    const bad = "HTTP/1.1 99 X\r\n\r\n";
    @memcpy(buffer[0..bad.len], bad);
    try expectError(error.InvalidStatusLine, parser.parse_response(buffer[0..bad.len], .{}, .GET));
}

/// Parsing arbitrary bytes never crashes; a complete result never claims more bytes than
/// given, and its slices stay inside the buffer.
fn parse_arbitrary(input: []u8) !void {
    const limits: parser.Limits = .{ .head_size_max = 512, .body_size_max = 512 };
    const range_start = @intFromPtr(input.ptr);
    const range_end = range_start + input.len;
    if (parser.parse_request(input, limits)) |parsed| switch (parsed) {
        .incomplete => {},
        .complete => |c| {
            try expect(c.consumed <= input.len);
            const body = @intFromPtr(c.message.body.ptr);
            try expect(c.message.body.len == 0 or
                (body >= range_start and body + c.message.body.len <= range_end));
        },
    } else |_| {}
    if (parser.parse_response(input, limits, .GET)) |parsed| switch (parsed) {
        .incomplete => {},
        .complete => |c| try expect(c.consumed <= input.len),
    } else |_| {}
}

test "http: seeded fuzz of near-valid messages" {
    var prng = Prng.init(0x4777);
    const seeds = [_][]const u8{
        "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
    };
    var buffer: [256]u8 = undefined;
    for (0..3000) |_| {
        const seed = seeds[prng.below(seeds.len)];
        @memcpy(buffer[0..seed.len], seed);
        var size = seed.len;
        const mutations = prng.range(0, 4);
        for (0..mutations) |_| {
            const position = prng.below(size);
            switch (prng.below(3)) {
                0 => buffer[position] = prng.int(u8),
                1 => size = position + 1,
                2 => buffer[position] = "\r\n:;0 "[prng.below(6)],
                else => unreachable,
            }
        }
        try parse_arbitrary(buffer[0..size]);
    }
}

fn fuzz_parse(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try parse_arbitrary(input[0..size]);
}

test "http: fuzz parser" {
    try std.testing.fuzz({}, fuzz_parse, .{});
}
