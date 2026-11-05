//! WebSocket server tests: the ws client against the ws server over SimIo.

const std = @import("std");

const io = @import("../io/root.zig");
const http = @import("../http/root.zig");
const client_module = @import("client.zig");
const server_module = @import("server.zig");

const SimIo = io.SimIo;
const Address = io.Address;

fn HubFor(comptime IO: type) type {
    return struct {
        const Self = @This();
        opened: u32 = 0,
        messages: u32 = 0,
        closed: u32 = 0,
        last_error: ?server_module.Error = null,
        echo: bool = true,

        const WsServer = server_module.Server(IO, *Self);
        const handlers: server_module.Handlers(WsServer, *Self) = .{
            .on_open = on_open,
            .on_message = on_message,
            .on_close = on_close,
        };

        fn on_open(hub: *Self, server: *WsServer, id: server_module.ConnectionId) void {
            hub.opened += 1;
            server.send(id, .text, "welcome") catch unreachable;
        }

        fn on_message(
            hub: *Self,
            server: *WsServer,
            id: server_module.ConnectionId,
            incoming: server_module.Message,
        ) void {
            hub.messages += 1;
            if (hub.echo) server.send(id, incoming.opcode, incoming.payload) catch unreachable;
        }

        fn on_close(
            hub: *Self,
            server: *WsServer,
            id: server_module.ConnectionId,
            closed: server_module.Closed,
        ) void {
            _ = server;
            _ = id;
            hub.closed += 1;
            if (closed.err) |err| hub.last_error = err;
        }
    };
}

const Hub = HubFor(SimIo);

fn SubscriberFor(comptime IO: type) type {
    return struct {
        const Self = @This();
        opened: bool = false,
        received: u32 = 0,
        last: [16]u8 = undefined,
        last_size: usize = 0,
        closed: ?client_module.Closed = null,
        close_after: u32 = std.math.maxInt(u32),

        const WsClient = client_module.Client(IO, *Self);
        const handlers: client_module.Handlers(WsClient, *Self) = .{
            .on_open = on_open,
            .on_message = on_message,
            .on_close = on_close,
        };

        fn on_open(subscriber: *Self, client: *WsClient) void {
            subscriber.opened = true;
            client.send_text("echo-me") catch unreachable;
        }

        fn on_message(
            subscriber: *Self,
            client: *WsClient,
            incoming: client_module.Message,
        ) void {
            subscriber.received += 1;
            const size = @min(incoming.payload.len, subscriber.last.len);
            @memcpy(subscriber.last[0..size], incoming.payload[0..size]);
            subscriber.last_size = size;
            if (subscriber.received == subscriber.close_after) client.close(.going_away);
        }

        fn on_close(subscriber: *Self, client: *WsClient, closed: client_module.Closed) void {
            _ = client;
            subscriber.closed = closed;
        }
    };
}

const Subscriber = SubscriberFor(SimIo);

const subscribers_max = 3;

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,
    hub: Hub = .{},
    server: Hub.WsServer,
    bound: Address,
    subscribers: [subscribers_max]Subscriber = @splat(.{}),
    clients: [subscribers_max]Subscriber.WsClient,

    fn init(harness: *Harness, seed: u64, options: server_module.Options) !void {
        harness.world = try io.SimWorld.init(std.testing.allocator, .{
            .seed = seed,
            .segment_size_max = 13,
        });
        const server_host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try SimIo.init(&harness.server_io, std.testing.allocator, &harness.world, .{
            .host = server_host,
        });
        try SimIo.init(&harness.client_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.hub = .{};
        try harness.server.init(
            std.testing.allocator,
            &harness.server_io,
            &harness.hub,
            &Hub.handlers,
            options,
        );
        harness.bound = try harness.server.listen(server_host.with_port(8546));
        harness.subscribers = @splat(.{});
        for (&harness.clients, &harness.subscribers, 0..) |*client, *subscriber, index| {
            client.* = try Subscriber.WsClient.init(
                std.testing.allocator,
                &harness.client_io,
                harness.bound,
                .{ .message_size_max = 256, .send_buffer_size = 1024, .seed = seed + index },
                subscriber,
                &Subscriber.handlers,
            );
        }
    }

    fn run_until(harness: *Harness, comptime done: fn (*Harness) bool) !void {
        var rounds: u32 = 0;
        while (!done(harness) and rounds < 20_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        try std.testing.expect(done(harness));
    }

    fn deinit(harness: *Harness) void {
        harness.server.stop();
        harness.world.run_for_ns(10 * std.time.ns_per_ms);
        for (&harness.clients) |*client| {
            client.abort();
        }
        harness.world.run_for_ns(10 * std.time.ns_per_ms);
        for (&harness.clients) |*client| client.deinit();
        harness.server.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }
};

fn all_closed(harness: *Harness) bool {
    for (harness.subscribers) |subscriber| if (subscriber.closed == null) return false;
    return harness.hub.closed == subscribers_max;
}

fn all_open(harness: *Harness) bool {
    for (harness.subscribers) |subscriber| if (subscriber.received < 2) return false;
    return true;
}

test "ws: server echoes and completes client-initiated close" {
    for (0..6) |seed| {
        var harness: Harness = undefined;
        try harness.init(seed, .{ .connections_max = 4, .message_size_max = 256 });
        defer harness.deinit();
        for (&harness.clients, &harness.subscribers) |*client, *subscriber| {
            subscriber.close_after = 2; // "welcome" and the echo.
            client.connect();
        }
        try harness.run_until(all_closed);
        for (harness.subscribers) |subscriber| {
            try std.testing.expectEqual(@as(u32, 2), subscriber.received);
            try std.testing.expectEqual(@as(?u16, 1001), subscriber.closed.?.code);
            try std.testing.expectEqual(@as(?client_module.Error, null), subscriber.closed.?.err);
        }
        try std.testing.expectEqual(@as(u32, subscribers_max), harness.hub.messages);
        try std.testing.expectEqual(@as(?server_module.Error, null), harness.hub.last_error);
        try std.testing.expectEqual(@as(u32, 0), harness.server.connections_open());
    }
}

test "ws: broadcast reaches every subscriber and drops slow consumers" {
    var harness: Harness = undefined;
    try harness.init(9, .{
        .connections_max = 4,
        .message_size_max = 256,
        .send_buffer_size = 256,
    });
    defer harness.deinit();
    for (&harness.clients) |*client| client.connect();
    try harness.run_until(all_open);
    const delivered = harness.server.broadcast(.text, "tick");
    try std.testing.expectEqual(@as(u32, subscribers_max), delivered);
    harness.world.run_for_ns(100 * std.time.ns_per_ms);
    for (harness.subscribers) |subscriber| {
        try std.testing.expectEqual(@as(u32, 3), subscriber.received);
        try std.testing.expectEqualStrings("tick", subscriber.last[0..subscriber.last_size]);
    }
    // Without running the event loop the 256-byte send buffers fill up: everyone is dropped.
    const payload: [100]u8 = @splat('x');
    var rounds: u32 = 0;
    while (harness.server.broadcast(.binary, &payload) > 0 and rounds < 10) rounds += 1;
    try harness.run_until(all_closed);
    try std.testing.expectEqual(@as(u64, subscribers_max), harness.server.slow_consumers_dropped);
    const last_error = harness.hub.last_error;
    try std.testing.expectEqual(@as(?server_module.Error, error.SlowConsumer), last_error);
}

test "ws: server rejects plain http and extra connections" {
    var harness: Harness = undefined;
    try harness.init(5, .{ .connections_max = 1, .message_size_max = 256 });
    defer harness.deinit();
    harness.clients[0].connect();
    harness.clients[1].connect();
    harness.hub.echo = false;
    var rounds: u32 = 0;
    while (!one_open_one_rejected(&harness) and rounds < 5000) : (rounds += 1) {
        harness.world.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expect(one_open_one_rejected(&harness));
    try std.testing.expectEqual(@as(u64, 1), harness.server.connections_rejected);
    const winner: usize = if (harness.subscribers[0].opened) 0 else 1;
    harness.clients[winner].close(.normal);
    rounds = 0;
    while (harness.hub.closed < 1 and rounds < 5000) : (rounds += 1) {
        harness.world.run_for_ns(std.time.ns_per_ms);
    }

    // The freed slot now takes a plain HTTP request, which gets a 400.
    var http_client = try HttpClient.init(
        std.testing.allocator,
        &harness.client_io,
        harness.bound,
        .{
            .send_buffer_size = 1024,
            .recv_buffer_size = 2048,
            .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
        },
    );
    defer http_client.deinit();
    var status: Status = .{};
    try http_client.request(*Status, &status, Status.on_response, .GET, "/", &.{}, "");
    rounds = 0;
    while (status.value == 0 and rounds < 5000) : (rounds += 1) {
        harness.world.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(u16, 400), status.value);
    const last_error = harness.hub.last_error;
    try std.testing.expectEqual(@as(?server_module.Error, error.HandshakeFailed), last_error);
}

fn one_open_one_rejected(harness: *Harness) bool {
    const a = harness.subscribers[0];
    const b = harness.subscribers[1];
    const a_rejected = !a.opened and a.closed != null and a.closed.?.err != null;
    const b_rejected = !b.opened and b.closed != null and b.closed.?.err != null;
    return (a.opened and b_rejected) or (b.opened and a_rejected);
}

const HttpClient = http.Client(SimIo);

const Status = struct {
    value: u16 = 0,

    fn on_response(
        status: *Status,
        client: *HttpClient,
        result: http.client.Error!*const http.Response,
    ) void {
        _ = client;
        const response = result catch {
            status.value = 1;
            return;
        };
        status.value = response.status;
    }
};

test "ws: client and server over the OS backend" {
    const OsHub = HubFor(io.IO);
    const OsSubscriber = SubscriberFor(io.IO);
    var os_io = try io.init_for_test();
    defer os_io.deinit();
    var hub: OsHub = .{};
    var server: OsHub.WsServer = undefined;
    try server.init(std.testing.allocator, &os_io, &hub, &OsHub.handlers, .{
        .connections_max = 2,
        .message_size_max = 256,
        .send_buffer_size = 1024,
    });
    defer server.deinit();
    const bound = try server.listen(Address.loopback(0));
    var subscriber: OsSubscriber = .{ .close_after = 2 };
    var client = try OsSubscriber.WsClient.init(
        std.testing.allocator,
        &os_io,
        bound,
        .{ .message_size_max = 256, .send_buffer_size = 1024, .seed = 1 },
        &subscriber,
        &OsSubscriber.handlers,
    );
    defer client.deinit();
    client.connect();
    var rounds: u32 = 0;
    while ((subscriber.closed == null or hub.closed == 0) and rounds < 1000) : (rounds += 1) {
        try os_io.run_for_ns(5 * std.time.ns_per_ms);
    }
    server.stop();
    try os_io.run_for_ns(5 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 2), subscriber.received);
    try std.testing.expectEqual(@as(?u16, 1001), subscriber.closed.?.code);
    try std.testing.expectEqual(@as(?client_module.Error, null), subscriber.closed.?.err);
    try std.testing.expectEqual(@as(u32, 1), hub.closed);
}

test "ws: request target is exposed, oversized targets are rejected" {
    var harness: Harness = undefined;
    try harness.init(11, .{ .connections_max = 4, .message_size_max = 256 });
    defer harness.deinit();
    harness.clients[0].options.target = "/ws?block_number=5&flashblock_index=2";
    harness.clients[0].connect();
    var rounds: u32 = 0;
    while (!harness.subscribers[0].opened and rounds < 5000) : (rounds += 1) {
        harness.world.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expect(harness.subscribers[0].opened);
    const id: server_module.ConnectionId = .{ .index = 0, .generation = 1 };
    const target = harness.server.request_target(id).?;
    try std.testing.expectEqualStrings("/ws?block_number=5&flashblock_index=2", target);
    try std.testing.expectEqual(@as(?[]const u8, null), harness.server.request_target(.{
        .index = 0,
        .generation = 2,
    }));

    var long_target: [server_module.request_target_size_max + 2]u8 = @splat('a');
    long_target[0] = '/';
    harness.clients[1].options.target = &long_target;
    harness.clients[1].connect();
    rounds = 0;
    while (harness.subscribers[1].closed == null and rounds < 5000) : (rounds += 1) {
        harness.world.run_for_ns(std.time.ns_per_ms);
    }
    const closed = harness.subscribers[1].closed.?;
    try std.testing.expectEqual(@as(?client_module.Error, error.HandshakeFailed), closed.err);
    try std.testing.expect(!harness.subscribers[1].opened);
}
