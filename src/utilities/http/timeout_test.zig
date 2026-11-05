//! HTTP server idle/io timeouts and client request timeouts over SimIo.

const std = @import("std");

const io = @import("../io/root.zig");
const io_common = @import("../io/common.zig");
const parser = @import("parser.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");

const Address = io.Address;
const SimIo = io.SimIo;
const ms = std.time.ns_per_ms;

const Ok = struct {
    fn handle(
        context: void,
        request: *const parser.Request,
        response: *server_module.ResponseBuilder,
    ) void {
        _ = context;
        _ = request;
        response.writer().writeAll("ok") catch unreachable;
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,

    fn init(harness: *Harness, seed: u64) !void {
        harness.world = try io.SimWorld.init(std.testing.allocator, .{ .seed = seed });
        try SimIo.init(&harness.server_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try SimIo.init(&harness.client_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
    }

    fn deinit(harness: *Harness) void {
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }

    /// Advances time in steps, calling `tick` on `component` after each.
    fn run_ticking(harness: *Harness, component: anytype, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ms) {
            harness.world.run_for_ns(10 * ms);
            component.tick();
        }
    }
};

const server_options: server_module.Options = .{
    .connections_max = 2,
    .recv_buffer_size = 4096,
    .send_buffer_size = 4096,
    .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
    .idle_timeout_ns = 500 * ms,
    .io_timeout_ns = 200 * ms,
};

const Result = struct {
    status: u16 = 0,
    err: ?client_module.Error = null,
    calls: u32 = 0,

    fn on_response(
        result: *Result,
        client: *client_module.Client(SimIo),
        response: client_module.Error!*const parser.Response,
    ) void {
        _ = client;
        result.calls += 1;
        if (response) |r| result.status = r.status else |err| result.err = err;
    }
};

test "http: server closes idle keep-alive connections" {
    var harness: Harness = undefined;
    try harness.init(31);
    defer harness.deinit();
    var server: server_module.Server(SimIo, void, Ok.handle) = undefined;
    try server.init(std.testing.allocator, &harness.server_io, {}, server_options);
    defer server.deinit();
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    const Client = client_module.Client(SimIo);
    var client = try Client.init(std.testing.allocator, &harness.client_io, bound, .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 4096,
        .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
    });
    defer client.deinit();
    var result: Result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/", &.{}, "{}");
    harness.run_ticking(&server, 100 * ms);
    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqual(@as(u32, 1), server.connections_open());
    // Idle past 500 ms: the server shuts the connection down.
    harness.run_ticking(&server, 700 * ms);
    try std.testing.expectEqual(@as(u32, 0), server.connections_open());
    try std.testing.expectEqual(@as(u64, 1), server.connections_timed_out);
    // The client notices on its next request and reconnects transparently.
    result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/", &.{}, "{}");
    harness.run_ticking(&server, 100 * ms);
    try std.testing.expectEqual(@as(u16, 200), result.status);
}

const Partial = struct {
    io: *SimIo,
    fd: SimIo.Fd,
    completion: SimIo.Completion = .{},
    eof: bool = false,
    buffer: [64]u8 = undefined,

    fn on_connect(
        partial: *Partial,
        completion: *SimIo.Completion,
        result: io_common.ConnectError!void,
    ) void {
        result catch unreachable;
        const head = "POST / HTTP/1.1\r\nContent-Le"; // Never finished.
        partial.io.send(*Partial, partial, on_send, completion, partial.fd, head);
    }

    fn on_send(
        partial: *Partial,
        completion: *SimIo.Completion,
        result: io_common.SendError!usize,
    ) void {
        _ = result catch unreachable;
        partial.io.recv(*Partial, partial, on_recv, completion, partial.fd, &partial.buffer);
    }

    fn on_recv(
        partial: *Partial,
        completion: *SimIo.Completion,
        result: io_common.RecvError!usize,
    ) void {
        _ = completion;
        const size = result catch 0;
        partial.eof = size == 0;
    }
};

test "http: server times out a stalled partial request" {
    var harness: Harness = undefined;
    try harness.init(32);
    defer harness.deinit();
    var server: server_module.Server(SimIo, void, Ok.handle) = undefined;
    try server.init(std.testing.allocator, &harness.server_io, {}, server_options);
    defer server.deinit();
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    const client_io = &harness.client_io;
    var partial: Partial = .{ .io = client_io, .fd = try client_io.open_socket_tcp(.ip4) };
    const completion = &partial.completion;
    client_io.connect(*Partial, &partial, Partial.on_connect, completion, partial.fd, bound);
    harness.run_ticking(&server, 100 * ms);
    try std.testing.expectEqual(@as(u32, 1), server.connections_open());
    harness.run_ticking(&server, 300 * ms); // io_timeout is 200 ms, below the idle timeout.
    try std.testing.expectEqual(@as(u32, 0), server.connections_open());
    try std.testing.expect(partial.eof);
    harness.client_io.close_now(partial.fd);
}

test "http: client request times out when the server never answers" {
    var harness: Harness = undefined;
    try harness.init(33);
    defer harness.deinit();
    // A listener that never accepts: connect succeeds, the request is buffered, no reply.
    const listener = try harness.server_io.open_socket_tcp(.ip4);
    defer harness.server_io.close_now(listener);
    const address = Address.ip4(.{ 10, 0, 0, 1 }, 8545);
    const bound = try harness.server_io.listen(listener, address, 4);
    const Client = client_module.Client(SimIo);
    var client = try Client.init(std.testing.allocator, &harness.client_io, bound, .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 4096,
        .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
        .request_timeout_ns = 300 * ms,
    });
    defer client.deinit();
    var result: Result = .{};
    try client.request(*Result, &result, Result.on_response, .POST, "/", &.{}, "{}");
    harness.run_ticking(&client, 200 * ms);
    try std.testing.expectEqual(@as(u32, 0), result.calls);
    harness.run_ticking(&client, 200 * ms);
    try std.testing.expectEqual(@as(u32, 1), result.calls);
    try std.testing.expectEqual(@as(?client_module.Error, error.Timeout), result.err);
    try std.testing.expect(!client.busy());
}
