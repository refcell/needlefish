//! JSON-RPC over WebSocket: `WsClient` against a ws server running a `Router` over SimIo.

const std = @import("std");

const io = @import("../io/root.zig");
const json = @import("../json/root.zig");
const ws = @import("../ws/root.zig");
const rpc = @import("root.zig");
const rpc_ws = @import("ws.zig");

const SimIo = io.SimIo;
const Address = io.Address;

const Node = struct {
    subscriber: ?ws.server.ConnectionId = null,
    current: ws.server.ConnectionId = undefined,

    fn chain_id(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        _ = node;
        try call.params.finish();
        try call.writer.quantity(@as(u64, 8453));
    }

    fn subscribe(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        const kind = try call.params.string();
        try call.params.finish();
        if (!std.mem.eql(u8, kind, "newHeads")) {
            return call.fail(rpc.code.invalid_params, "unknown subscription");
        }
        node.subscriber = node.current;
        try call.writer.string("0x1");
    }

    const methods = [_]rpc.Method(*Node){
        .{ .name = "eth_chainId", .handler = chain_id },
        .{ .name = "eth_subscribe", .handler = subscribe },
    };
    const Router = rpc.Router(*Node, &methods);
};

const Hub = struct {
    node: Node = .{},
    scratch: [4096]u8 = undefined,

    const Server = ws.Server(SimIo, *Hub);
    const handlers: ws.server.Handlers(Server, *Hub) = .{
        .on_open = on_open,
        .on_message = on_message,
        .on_close = on_close,
    };

    fn on_open(hub: *Hub, server: *Server, id: ws.server.ConnectionId) void {
        _ = hub;
        _ = server;
        _ = id;
    }

    fn on_message(
        hub: *Hub,
        server: *Server,
        id: ws.server.ConnectionId,
        message: ws.server.Message,
    ) void {
        hub.node.current = id;
        rpc_ws.serve_message(Node.Router, &hub.node, server, id, message, &hub.scratch) catch
            unreachable; // The test's send buffers are far larger than any response.
    }

    fn on_close(
        hub: *Hub,
        server: *Server,
        id: ws.server.ConnectionId,
        closed: ws.server.Closed,
    ) void {
        _ = server;
        _ = closed;
        if (hub.node.subscriber) |subscriber| {
            if (subscriber.index == id.index) hub.node.subscriber = null;
        }
    }

    fn push_head(hub: *Hub, server: *Server, number: u64) !void {
        var out: std.Io.Writer = .fixed(&hub.scratch);
        try rpc_ws.write_notification(&out, "0x1", number, write_head);
        try server.send(hub.node.subscriber.?, .text, out.buffered());
    }

    fn write_head(number: u64, writer: *json.Writer) json.Writer.WriteError!void {
        try writer.begin_object();
        try writer.key("number");
        try writer.quantity(number);
        try writer.end_object();
    }
};

const Recorder = struct {
    opened: bool = false,
    closed: bool = false,
    results: [8]struct { id: u64, text: [64]u8, size: usize, failed: bool } = undefined,
    result_count: usize = 0,
    heads: [8]u64 = undefined,
    head_count: usize = 0,

    const Client = rpc_ws.WsClient(SimIo, *Recorder);
    const handlers: rpc_ws.Handlers(Client, *Recorder) = .{
        .on_open = on_open,
        .on_result = on_result,
        .on_notification = on_notification,
        .on_close = on_close,
    };

    fn on_open(recorder: *Recorder, client: *Client) void {
        _ = client;
        recorder.opened = true;
    }

    fn on_result(
        recorder: *Recorder,
        client: *Client,
        id: u64,
        result: rpc_ws.CallError!rpc_ws.Result,
    ) void {
        _ = client;
        const entry = &recorder.results[recorder.result_count];
        recorder.result_count += 1;
        entry.id = id;
        const value = result catch {
            entry.failed = true;
            entry.size = 0;
            return;
        };
        const text = switch (value) {
            .ok => |raw| raw,
            .rpc_error => "error",
        };
        entry.failed = false;
        @memcpy(entry.text[0..text.len], text);
        entry.size = text.len;
    }

    fn on_notification(
        recorder: *Recorder,
        client: *Client,
        notification: rpc_ws.Notification,
    ) void {
        _ = client;
        std.debug.assert(std.mem.eql(u8, notification.method, "eth_subscription"));
        std.debug.assert(std.mem.eql(u8, notification.subscription, "\"0x1\""));
        const number = json.find_path(notification.result, &.{"number"}) catch unreachable;
        recorder.heads[recorder.head_count] =
            json.parse_quantity(u64, number.?[1 .. number.?.len - 1]) catch unreachable;
        recorder.head_count += 1;
    }

    fn on_close(recorder: *Recorder, client: *Client, closed: ws.client.Closed) void {
        _ = client;
        _ = closed;
        recorder.closed = true;
    }

    fn result_text(recorder: *const Recorder, index: usize) []const u8 {
        return recorder.results[index].text[0..recorder.results[index].size];
    }
};

fn subscribe_params(kind: []const u8, writer: *json.Writer) json.Writer.WriteError!void {
    try writer.string(kind);
}

test "rpc: JSON-RPC over WebSocket with subscriptions" {
    const allocator = std.testing.allocator;
    var world = try io.SimWorld.init(allocator, .{ .seed = 81, .segment_size_max = 9 });
    defer world.deinit();
    var server_io: SimIo = undefined;
    try SimIo.init(&server_io, allocator, &world, .{ .host = Address.ip4(.{ 10, 0, 0, 1 }, 0) });
    defer server_io.deinit();
    var client_io: SimIo = undefined;
    try SimIo.init(&client_io, allocator, &world, .{ .host = Address.ip4(.{ 10, 0, 0, 2 }, 0) });
    defer client_io.deinit();

    var hub: Hub = .{};
    var server: Hub.Server = undefined;
    try server.init(allocator, &server_io, &hub, &Hub.handlers, .{
        .connections_max = 2,
        .message_size_max = 4096,
        .send_buffer_size = 16 * 1024,
    });
    defer {
        server.stop();
        var rounds: u32 = 0;
        while (!server.stopped() and rounds < 1000) : (rounds += 1) {
            world.run_for_ns(std.time.ns_per_ms);
        }
        server.deinit();
    }
    const bound = try server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8546));

    var recorder: Recorder = .{};
    var client: Recorder.Client = undefined;
    try client.init(allocator, &client_io, bound, .{
        .ws = .{ .message_size_max = 4096, .send_buffer_size = 8192, .seed = 3 },
        .request_size_max = 1024,
    }, &recorder, &Recorder.handlers);
    defer client.deinit();
    client.connect();
    world.run_for_ns(100 * std.time.ns_per_ms);
    try std.testing.expect(recorder.opened);

    // Two calls in flight, matched by id.
    const first = try client.call("eth_chainId", {}, rpc.client.no_params);
    const second = try client.call("eth_subscribe", @as([]const u8, "newHeads"), subscribe_params);
    try std.testing.expectEqual(@as(u32, 2), client.pending_count);
    world.run_for_ns(100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 2), recorder.result_count);
    try std.testing.expectEqual(first, recorder.results[0].id);
    try std.testing.expectEqualStrings("\"0x2105\"", recorder.result_text(0));
    try std.testing.expectEqual(second, recorder.results[1].id);
    try std.testing.expectEqualStrings("\"0x1\"", recorder.result_text(1));
    try std.testing.expectEqual(@as(u32, 0), client.pending_count);

    // Server pushes reach the subscription handler in order.
    try hub.push_head(&server, 100);
    try hub.push_head(&server, 101);
    world.run_for_ns(100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 2), recorder.head_count);
    try std.testing.expectEqualSlices(u64, &.{ 100, 101 }, recorder.heads[0..2]);

    // An RPC error is a result, not a transport failure.
    _ = try client.call("eth_subscribe", @as([]const u8, "logs"), subscribe_params);
    world.run_for_ns(100 * std.time.ns_per_ms);
    try std.testing.expectEqualStrings("error", recorder.result_text(2));

    // Pending calls fail before `on_close` when the connection goes away.
    const lost = try client.call("eth_chainId", {}, rpc.client.no_params);
    client.abort();
    world.run_for_ns(100 * std.time.ns_per_ms);
    try std.testing.expect(recorder.closed);
    try std.testing.expectEqual(lost, recorder.results[3].id);
    try std.testing.expect(recorder.results[3].failed);
    try std.testing.expectEqual(@as(u64, 0), client.invalid_messages);
}

test "rpc: parse_notification" {
    const ok = try rpc_ws.parse_notification(
        \\{"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"0xab","result":[1]}}
    );
    try std.testing.expectEqualStrings("eth_subscription", ok.method);
    try std.testing.expectEqualStrings("\"0xab\"", ok.subscription);
    try std.testing.expectEqualStrings("[1]", ok.result);
    const bad = [_][]const u8{
        "{\"method\":\"m\",\"params\":{\"result\":1}}",
        "{\"method\":1,\"params\":{\"subscription\":\"0x1\",\"result\":1}}",
        "{\"params\":{\"subscription\":\"0x1\",\"result\":1}}",
        "{\"method\":\"m\",\"params\":{\"subscription\":\"0x1\",\"result\":1}} trailing",
        "[]",
        "",
    };
    for (bad) |payload| {
        try std.testing.expectError(error.InvalidNotification, rpc_ws.parse_notification(payload));
    }
}

fn notification_arbitrary(payload: []const u8) !void {
    const parsed = rpc_ws.parse_notification(payload) catch return;
    try json.validate(parsed.subscription);
    try json.validate(parsed.result);
}

test "rpc: seeded fuzz parse_notification" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x75b);
    const pieces = [_][]const u8{
        "{",       "}", ":", ",",                "\"method\"", "\"params\"",
        "\"0x1\"", "[", "]", "\"subscription\"", "\"result\"", "null",
    };
    var buffer: [256]u8 = undefined;
    for (0..3000) |_| {
        var size: usize = 0;
        for (0..prng.below(20)) |_| {
            const piece = pieces[prng.below(pieces.len)];
            if (size + piece.len > buffer.len) break;
            @memcpy(buffer[size..][0..piece.len], piece);
            size += piece.len;
        }
        try notification_arbitrary(buffer[0..size]);
    }
}

fn fuzz_notification(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var buffer: [256]u8 = undefined;
    try notification_arbitrary(buffer[0..smith.slice(&buffer)]);
}

test "rpc: fuzz parse_notification" {
    try std.testing.fuzz({}, fuzz_notification, .{});
}
