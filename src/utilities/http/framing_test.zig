//! Close-delimited responses (no Content-Length, no chunking): parser and client over SimIo.

const std = @import("std");

const io = @import("../io/root.zig");
const io_common = @import("../io/common.zig");
const parser = @import("parser.zig");
const client_module = @import("client.zig");

const Address = io.Address;
const SimIo = io.SimIo;
const expectEqualStrings = std.testing.expectEqualStrings;

test "http: close-delimited response waits for end of stream" {
    const text = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello world";
    var buffer: [text.len]u8 = text.*;
    try std.testing.expect(try parser.parse_response(&buffer, .{}, .GET) == .incomplete);
    const done = (try parser.parse_response_at_eof(&buffer, .{}, .GET)).complete;
    try expectEqualStrings("hello world", done.message.body);
    try std.testing.expect(!done.message.keep_alive);
    try std.testing.expectEqual(@as(u32, text.len), done.consumed);
    // HTTP/1.1 keep-alive without a length is still delimited by close (RFC 9112 6.3).
    const bare = "HTTP/1.1 200 OK\r\n\r\nabc";
    var bare_buffer: [bare.len]u8 = bare.*;
    const bare_done = (try parser.parse_response_at_eof(&bare_buffer, .{}, .POST)).complete;
    try expectEqualStrings("abc", bare_done.message.body);
    try std.testing.expect(!bare_done.message.keep_alive);
    // The body limit applies while waiting.
    try std.testing.expectError(error.BodyTooLarge, parser.parse_response(&buffer, .{
        .body_size_max = 4,
    }, .GET));
    // Framed responses are unaffected: 204 and Content-Length: 0 complete immediately.
    var no_content = "HTTP/1.1 204 No Content\r\n\r\n".*;
    try std.testing.expect(try parser.parse_response(&no_content, .{}, .GET) != .incomplete);
    var empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".*;
    try std.testing.expect(try parser.parse_response(&empty, .{}, .GET) != .incomplete);
    // A truncated length-framed body is still incomplete at end of stream.
    var cut = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc".*;
    try std.testing.expect(try parser.parse_response_at_eof(&cut, .{}, .GET) == .incomplete);
}

/// Accepts one connection, reads the request, writes `reply`, then closes its write side.
const RawServer = struct {
    io: *SimIo,
    listener: SimIo.Fd,
    fd: ?SimIo.Fd = null,
    reply: []const u8,
    sent: usize = 0,
    completion: SimIo.Completion = .{},
    scratch: [1024]u8 = undefined,

    fn on_accept(
        server: *RawServer,
        c: *SimIo.Completion,
        result: io_common.AcceptError!SimIo.Fd,
    ) void {
        server.fd = result catch unreachable; // The test's only connection.
        server.io.recv(*RawServer, server, on_recv, c, server.fd.?, &server.scratch);
    }

    fn on_recv(
        server: *RawServer,
        c: *SimIo.Completion,
        result: io_common.RecvError!usize,
    ) void {
        std.debug.assert((result catch 0) > 0);
        server.io.send(*RawServer, server, on_send, c, server.fd.?, server.reply);
    }

    fn on_send(
        server: *RawServer,
        c: *SimIo.Completion,
        result: io_common.SendError!usize,
    ) void {
        server.sent += result catch unreachable; // The client keeps reading until close.
        if (server.sent < server.reply.len) {
            const rest = server.reply[server.sent..];
            return server.io.send(*RawServer, server, on_send, c, server.fd.?, rest);
        }
        server.io.shutdown_now(server.fd.?);
    }
};

const Body = struct {
    text: [64]u8 = undefined,
    size: usize = 0,
    err: ?client_module.Error = null,
    calls: u32 = 0,

    fn on_response(
        body: *Body,
        client: *client_module.Client(SimIo),
        response: client_module.Error!*const parser.Response,
    ) void {
        _ = client;
        body.calls += 1;
        const r = response catch |err| {
            body.err = err;
            return;
        };
        @memcpy(body.text[0..r.body.len], r.body);
        body.size = r.body.len;
    }
};

fn run_exchange(seed: u64, reply: []const u8, body: *Body) !void {
    const world_options: io.sim.Options = .{ .seed = seed, .segment_size_max = 5 };
    var world = try io.SimWorld.init(std.testing.allocator, world_options);
    defer world.deinit();
    var server_io: SimIo = undefined;
    try SimIo.init(&server_io, std.testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
    });
    defer server_io.deinit();
    var client_io: SimIo = undefined;
    try SimIo.init(&client_io, std.testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
    });
    defer client_io.deinit();
    const listener = try server_io.open_socket_tcp(.ip4);
    defer server_io.close_now(listener);
    const bound = try server_io.listen(listener, Address.ip4(.{ 10, 0, 0, 1 }, 80), 4);
    var raw: RawServer = .{ .io = &server_io, .listener = listener, .reply = reply };
    server_io.accept(*RawServer, &raw, RawServer.on_accept, &raw.completion, listener);
    var client = try client_module.Client(SimIo).init(std.testing.allocator, &client_io, bound, .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 1024,
        .limits = .{ .head_size_max = 512, .body_size_max = 64 },
    });
    defer client.deinit();
    try client.request(*Body, body, Body.on_response, .GET, "/", &.{}, "");
    world.run_for_ns(std.time.ns_per_s);
    if (raw.fd) |fd| server_io.close_now(fd);
    world.run_for_ns(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 1), body.calls);
    try std.testing.expect(!client.busy());
}

test "http: client reads a close-delimited response body" {
    var body: Body = .{};
    const reply = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed until close";
    try run_exchange(71, reply, &body);
    try std.testing.expectEqual(@as(?client_module.Error, null), body.err);
    try expectEqualStrings("streamed until close", body.text[0..body.size]);
    // A length-framed response cut short by the close is an error, not a short body.
    var cut: Body = .{};
    try run_exchange(72, "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\npartial", &cut);
    try std.testing.expectEqual(@as(?client_module.Error, error.ConnectionClosed), cut.err);
}
