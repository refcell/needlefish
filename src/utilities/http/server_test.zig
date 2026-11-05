//! HTTP server + client end-to-end tests over SimIo and over the production backend.

const std = @import("std");
const builtin = @import("builtin");

const io = @import("../io/root.zig");
const parser = @import("parser.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");

const Address = io.Address;

const Echo = struct {
    fn handle(
        echo: *Echo,
        request: *const parser.Request,
        response: *server_module.ResponseBuilder,
    ) void {
        _ = echo;
        if (request.method != .POST) return response.fail(405);
        response.writer().print("{s}:{s}", .{ request.target, request.body }) catch
            return response.fail(500);
    }
};

fn SimServer() type {
    return server_module.Server(io.SimIo, *Echo, Echo.handle);
}

fn CollectorFor(comptime ClientType: type) type {
    return struct {
        const Self = @This();
        state: Collector = .{},
        fn on_response(
            self: *Self,
            client: *ClientType,
            result: client_module.Error!*const parser.Response,
        ) void {
            _ = client;
            self.state.record(result);
        }
    };
}

const Collector = struct {
    responses: [8][64]u8 = undefined,
    sizes: [8]usize = @splat(0),
    statuses: [8]u16 = @splat(0),
    count: u32 = 0,
    errors: u32 = 0,

    fn record(collector: *Collector, result: client_module.Error!*const parser.Response) void {
        const response = result catch {
            collector.errors += 1;
            return;
        };
        const index = collector.count;
        @memcpy(collector.responses[index][0..response.body.len], response.body);
        collector.sizes[index] = response.body.len;
        collector.statuses[index] = response.status;
        collector.count += 1;
    }

    fn body(collector: *const Collector, index: usize) []const u8 {
        return collector.responses[index][0..collector.sizes[index]];
    }
};

const SimHarness = struct {
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,

    fn init(harness: *SimHarness, seed: u64) !void {
        harness.world = try io.SimWorld.init(std.testing.allocator, .{ .seed = seed });
        try io.SimIo.init(&harness.server_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.client_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
    }

    fn deinit(harness: *SimHarness) void {
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }
};

const small_server: server_module.Options = .{
    .connections_max = 2,
    .recv_buffer_size = 4096,
    .send_buffer_size = 4096,
    .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
};
const small_client: client_module.Options = .{
    .send_buffer_size = 4096,
    .recv_buffer_size = 4096,
    .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
};

test "http: server and client keep-alive over SimIo" {
    var harness: SimHarness = undefined;
    try harness.init(21);
    defer harness.deinit();
    var echo: Echo = .{};
    var server: SimServer() = undefined;
    try server.init(std.testing.allocator, &harness.server_io, &echo, small_server);
    defer server.deinit();
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));

    const SimClient = client_module.Client(io.SimIo);
    var client = try SimClient.init(std.testing.allocator, &harness.client_io, bound, small_client);
    defer client.deinit();
    var sink: CollectorFor(SimClient) = .{};
    const collector = &sink.state;
    const bodies = [_][]const u8{ "{\"id\":1}", "{\"id\":2}", "{\"id\":3}" };
    for (bodies) |body| {
        const Sink = @TypeOf(sink);
        try client.request(*Sink, &sink, Sink.on_response, .POST, "/rpc", &.{}, body);
        harness.world.run_for_ns(std.time.ns_per_s);
    }
    try std.testing.expectEqual(@as(u32, 3), collector.count);
    try std.testing.expectEqual(@as(u32, 0), collector.errors);
    try std.testing.expectEqualStrings("/rpc:{\"id\":3}", collector.body(2));
    try std.testing.expectEqual(@as(u64, 3), server.requests_handled);
    try std.testing.expectEqual(@as(u32, 1), server.connections_open()); // Reused.

    try client.request(*@TypeOf(sink), &sink, @TypeOf(sink).on_response, .GET, "/", &.{}, "");
    harness.world.run_for_ns(std.time.ns_per_s);
    try std.testing.expectEqual(@as(u16, 405), collector.statuses[3]);
}

test "http: client retries once after the server drops an idle connection" {
    var harness: SimHarness = undefined;
    try harness.init(22);
    defer harness.deinit();
    var echo: Echo = .{};
    var server: SimServer() = undefined;
    try server.init(std.testing.allocator, &harness.server_io, &echo, small_server);
    defer server.deinit();
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    const SimClient = client_module.Client(io.SimIo);
    var client = try SimClient.init(std.testing.allocator, &harness.client_io, bound, small_client);
    defer client.deinit();
    var sink: CollectorFor(SimClient) = .{};
    const collector = &sink.state;
    try client.request(*@TypeOf(sink), &sink, @TypeOf(sink).on_response, .POST, "/a", &.{}, "1");
    harness.world.run_for_ns(std.time.ns_per_s);
    // Reset the kept-alive connection from the client side, as an idle timeout would.
    harness.client_io.reset_connection(client.fd.?);
    harness.world.run_for_ns(std.time.ns_per_s);
    try client.request(*@TypeOf(sink), &sink, @TypeOf(sink).on_response, .POST, "/b", &.{}, "2");
    harness.world.run_for_ns(std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 0), collector.errors);
    try std.testing.expectEqual(@as(u32, 2), collector.count);
    try std.testing.expectEqualStrings("/b:2", collector.body(1));
}

/// Raw pipelined requests and a malformed one, checked at the byte level.
const RawPeer = struct {
    io: *io.SimIo,
    fd: io.SimIo.Fd,
    completion: io.SimIo.Completion = .{},
    request: []const u8,
    received: [2048]u8 = undefined,
    received_size: usize = 0,
    closed: bool = false,

    fn on_connect(
        peer: *RawPeer,
        completion: *io.SimIo.Completion,
        result: io.ConnectError!void,
    ) void {
        result catch unreachable;
        peer.io.send(*RawPeer, peer, on_send, completion, peer.fd, peer.request);
    }

    fn on_send(peer: *RawPeer, completion: *io.SimIo.Completion, result: io.SendError!usize) void {
        const size = result catch unreachable;
        std.debug.assert(size == peer.request.len); // Small enough for one segment.
        peer.io.recv(*RawPeer, peer, on_recv, completion, peer.fd, &peer.received);
    }

    fn on_recv(peer: *RawPeer, completion: *io.SimIo.Completion, result: io.RecvError!usize) void {
        const size = result catch 0;
        if (size == 0) {
            peer.closed = true;
            return;
        }
        peer.received_size += size;
        const free = peer.received[peer.received_size..];
        peer.io.recv(*RawPeer, peer, on_recv, completion, peer.fd, free);
    }
};

fn raw_exchange(request: []const u8, seed: u64) !struct { [2048]u8, usize, bool } {
    var harness: SimHarness = undefined;
    try harness.init(seed);
    defer harness.deinit();
    var echo: Echo = .{};
    var server: SimServer() = undefined;
    try server.init(std.testing.allocator, &harness.server_io, &echo, small_server);
    defer server.deinit();
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 80));
    var peer: RawPeer = .{
        .io = &harness.client_io,
        .fd = try harness.client_io.open_socket_tcp(.ip4),
        .request = request,
    };
    const client_io = &harness.client_io;
    client_io.connect(*RawPeer, &peer, RawPeer.on_connect, &peer.completion, peer.fd, bound);
    harness.world.run_for_ns(2 * std.time.ns_per_s);
    if (!peer.closed) harness.client_io.close_now(peer.fd);
    harness.world.run_for_ns(std.time.ns_per_s);
    return .{ peer.received, peer.received_size, peer.closed };
}

test "http: server answers pipelined requests in order" {
    const request = "POST /1 HTTP/1.1\r\nContent-Length: 1\r\n\r\na" ++
        "POST /2 HTTP/1.1\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb";
    const received, const size, const closed = try raw_exchange(request, 23);
    const text = received[0..size];
    const first = std.mem.find(u8, text, "/1:a").?;
    const second = std.mem.find(u8, text, "/2:b").?;
    try std.testing.expect(first < second);
    try std.testing.expect(closed);
}

test "http: server rejects malformed request with 400 and closes" {
    const received, const size, const closed = try raw_exchange("BAD\r\n\r\n", 24);
    const status_line = "HTTP/1.1 400 Bad Request\r\n";
    try std.testing.expect(std.mem.startsWith(u8, received[0..size], status_line));
    try std.testing.expect(closed);
}

test "http: server and client over the OS backend" {
    var os_io = if (builtin.os.tag == .linux)
        io.IO.init(.{}) catch return error.SkipZigTest
    else
        try io.IO.init();
    defer os_io.deinit();
    var echo: Echo = .{};
    const OsServer = server_module.Server(io.IO, *Echo, Echo.handle);
    var server: OsServer = undefined;
    try server.init(std.testing.allocator, &os_io, &echo, small_server);
    defer server.deinit();
    const bound = try server.listen(Address.loopback(0));
    defer server.stop();
    const OsClient = client_module.Client(io.IO);
    var client = try OsClient.init(std.testing.allocator, &os_io, bound, small_client);
    defer client.deinit();
    var sink: CollectorFor(OsClient) = .{};
    const collector = &sink.state;
    try client.request(*@TypeOf(sink), &sink, @TypeOf(sink).on_response, .POST, "/x", &.{}, "hi");
    var rounds: u32 = 0;
    while (collector.count + collector.errors == 0 and rounds < 200) : (rounds += 1) {
        try os_io.run_for_ns(10 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(u32, 1), collector.count);
    try std.testing.expectEqualStrings("/x:hi", collector.body(0));
}
