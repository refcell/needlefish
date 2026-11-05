//! Deferred responses over SimIo: resume, timeout (504 and a stale token), stop (503), and a
//! pipelined request queued behind a deferred one.

const std = @import("std");

const io = @import("../io/root.zig");
const io_common = @import("../io/common.zig");
const parser = @import("parser.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");

const Address = io.Address;
const SimIo = io.SimIo;
const ms = std.time.ns_per_ms;

/// Defers requests to `/defer`, answers everything else at once.
const Parker = struct {
    token: ?server_module.Deferred = null,
    /// The deferred request's target, a slice into the server's receive buffer.
    target: []const u8 = "",

    fn handle(
        parker: *Parker,
        request: *const parser.Request,
        response: *server_module.ResponseBuilder,
    ) void {
        if (std.mem.startsWith(u8, request.target, "/defer")) {
            response.writer().writeAll("discarded") catch unreachable;
            parker.token = response.defer_response();
            parker.target = request.target;
            return;
        }
        response.writer().print("now:{s}", .{request.target}) catch unreachable;
    }

    fn write(parker: *Parker, response: *server_module.ResponseBuilder) void {
        response.status = 201;
        response.writer().print("later:{s}", .{parker.target}) catch unreachable;
    }
};

const Server = server_module.Server(SimIo, *Parker, Parker.handle);
const Client = client_module.Client(SimIo);

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,
    parker: Parker = .{},
    server: Server,
    bound: Address,

    fn init(harness: *Harness, seed: u64) !void {
        harness.world = try io.SimWorld.init(std.testing.allocator, .{ .seed = seed });
        try SimIo.init(&harness.server_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try SimIo.init(&harness.client_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.parker = .{};
        try harness.server.init(std.testing.allocator, &harness.server_io, &harness.parker, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
            .idle_timeout_ns = 5000 * ms,
            .io_timeout_ns = 200 * ms,
        });
        harness.bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    }

    fn deinit(harness: *Harness) void {
        if (!harness.server.stopping) harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(ms);
        }
        harness.server.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }

    fn client(harness: *Harness) !Client {
        return Client.init(std.testing.allocator, &harness.client_io, harness.bound, .{
            .send_buffer_size = 1024,
            .recv_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
        });
    }

    fn run_ticking(harness: *Harness, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ms) {
            harness.world.run_for_ns(10 * ms);
            harness.server.tick();
        }
    }
};

const Result = struct {
    status: u16 = 0,
    body: [64]u8 = undefined,
    body_size: usize = 0,
    calls: u32 = 0,
    failed: bool = false,

    fn on_response(
        result: *Result,
        client: *Client,
        response: client_module.Error!*const parser.Response,
    ) void {
        _ = client;
        result.calls += 1;
        const r = response catch {
            result.failed = true;
            return;
        };
        result.status = r.status;
        @memcpy(result.body[0..r.body.len], r.body);
        result.body_size = r.body.len;
    }

    fn text(result: *const Result) []const u8 {
        return result.body[0..result.body_size];
    }
};

test "http deferred: handler defers, owner resumes later" {
    var harness: Harness = undefined;
    try harness.init(41);
    defer harness.deinit();
    var client = try harness.client();
    defer client.deinit();
    var result: Result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/defer/1", &.{}, "{}");
    harness.run_ticking(100 * ms);
    try std.testing.expectEqual(@as(u32, 0), result.calls);
    const token = harness.parker.token.?;
    try std.testing.expect(harness.server.deferred_valid(token));
    try std.testing.expect(harness.server.resume_deferred(token, &harness.parker, Parker.write));
    try std.testing.expect(!harness.server.deferred_valid(token));
    // A second resume with the same token is stale.
    try std.testing.expect(!harness.server.resume_deferred(token, &harness.parker, Parker.write));
    harness.run_ticking(100 * ms);
    try std.testing.expectEqual(@as(u32, 1), result.calls);
    try std.testing.expectEqual(@as(u16, 201), result.status);
    try std.testing.expectEqualStrings("later:/defer/1", result.text());
    // The connection is kept alive and serves the next request normally.
    result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/next", &.{}, "{}");
    harness.run_ticking(100 * ms);
    try std.testing.expectEqualStrings("now:/next", result.text());
    try std.testing.expectEqual(@as(u32, 1), harness.server.connections_open());
}

test "http deferred: timeout answers 504 and the token goes stale" {
    var harness: Harness = undefined;
    try harness.init(42);
    defer harness.deinit();
    var client = try harness.client();
    defer client.deinit();
    var result: Result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/defer/2", &.{}, "{}");
    harness.run_ticking(100 * ms);
    const token = harness.parker.token.?;
    harness.run_ticking(200 * ms); // io_timeout is 200 ms.
    try std.testing.expectEqual(@as(u32, 1), result.calls);
    try std.testing.expectEqual(@as(u16, 504), result.status);
    try std.testing.expect(!harness.server.deferred_valid(token));
    try std.testing.expect(!harness.server.resume_deferred(token, &harness.parker, Parker.write));
    try std.testing.expectEqual(@as(u64, 1), harness.server.deferred_abandoned);
    harness.run_ticking(50 * ms);
    try std.testing.expectEqual(@as(u32, 0), harness.server.connections_open());
}

test "http deferred: stop answers 503 and closes it" {
    var harness: Harness = undefined;
    try harness.init(43);
    defer harness.deinit();
    var client = try harness.client();
    defer client.deinit();
    var result: Result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/defer/3", &.{}, "{}");
    harness.run_ticking(100 * ms);
    const token = harness.parker.token.?;
    harness.server.stop();
    try std.testing.expect(!harness.server.resume_deferred(token, &harness.parker, Parker.write));
    harness.run_ticking(100 * ms);
    try std.testing.expectEqual(@as(u16, 503), result.status);
    try std.testing.expect(harness.server.stopped());
}

/// Sends raw bytes once and collects everything the server sends back.
const RawPeer = struct {
    io: *SimIo,
    fd: SimIo.Fd,
    completion: SimIo.Completion = .{},
    request: []const u8,
    received: [1024]u8 = undefined,
    received_size: usize = 0,
    closed: bool = false,

    fn on_connect(
        peer: *RawPeer,
        completion: *SimIo.Completion,
        result: io_common.ConnectError!void,
    ) void {
        result catch unreachable;
        peer.io.send(*RawPeer, peer, on_send, completion, peer.fd, peer.request);
    }

    fn on_send(
        peer: *RawPeer,
        completion: *SimIo.Completion,
        result: io_common.SendError!usize,
    ) void {
        const size = result catch unreachable;
        std.debug.assert(size == peer.request.len);
        peer.io.recv(*RawPeer, peer, on_recv, completion, peer.fd, &peer.received);
    }

    fn on_recv(
        peer: *RawPeer,
        completion: *SimIo.Completion,
        result: io_common.RecvError!usize,
    ) void {
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

test "http deferred: a pipelined request waits behind the deferred one" {
    var harness: Harness = undefined;
    try harness.init(44);
    defer harness.deinit();
    const request = "POST /defer/a HTTP/1.1\r\nContent-Length: 1\r\n\r\na" ++
        "POST /b HTTP/1.1\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb";
    const client_io = &harness.client_io;
    const fd = try client_io.open_socket_tcp(.ip4);
    var peer: RawPeer = .{ .io = client_io, .fd = fd, .request = request };
    const bound = harness.bound;
    client_io.connect(*RawPeer, &peer, RawPeer.on_connect, &peer.completion, fd, bound);
    harness.run_ticking(100 * ms);
    try std.testing.expectEqual(@as(usize, 0), peer.received_size);
    const token = harness.parker.token.?;
    try std.testing.expect(harness.server.resume_deferred(token, &harness.parker, Parker.write));
    harness.run_ticking(100 * ms);
    const text = peer.received[0..peer.received_size];
    const first = std.mem.find(u8, text, "later:/defer/a").?;
    const second = std.mem.find(u8, text, "now:/b").?;
    try std.testing.expect(first < second);
    try std.testing.expect(peer.closed);
    harness.client_io.close_now(peer.fd);
}
