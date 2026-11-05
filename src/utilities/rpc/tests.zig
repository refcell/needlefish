//! JSON-RPC tests: router dispatch, errors, notifications, batches, params cursor, response
//! parsing, an end-to-end client/server exchange over SimIo, and fuzz targets.

const std = @import("std");
const rpc = @import("root.zig");
const json = @import("../json/root.zig");
const io = @import("../io/root.zig");
const http = @import("../http/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;

const Node = struct {
    head: u64 = 0x1234,
    calls: u32 = 0,

    fn chain_id(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        node.calls += 1;
        try call.params.finish();
        try call.writer.quantity(@as(u64, 8453));
    }

    fn block_number(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        node.calls += 1;
        try call.writer.quantity(node.head);
    }

    fn get_balance(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        node.calls += 1;
        const address = try call.params.fixed(20);
        const tag = try call.params.string();
        try call.params.finish();
        if (!std.mem.eql(u8, tag, "latest")) {
            return call.fail(rpc.code.server_error, "unknown block");
        }
        try call.writer.quantity(@as(u64, address[19]));
    }

    fn half_written(node: *Node, call: *rpc.Call) rpc.HandlerError!void {
        node.calls += 1;
        try call.writer.begin_object();
        try call.writer.key("partial");
        return call.fail(-32001, "boom");
    }
};

const methods = [_]rpc.Method(*Node){
    .{ .name = "eth_chainId", .handler = Node.chain_id },
    .{ .name = "eth_blockNumber", .handler = Node.block_number },
    .{ .name = "eth_getBalance", .handler = Node.get_balance },
    .{ .name = "test_halfWritten", .handler = Node.half_written },
};
const NodeRouter = rpc.Router(*Node, &methods);

fn route(node: *Node, body: []const u8, buffer: []u8) struct { rpc.Outcome, []const u8 } {
    var out: std.Io.Writer = .fixed(buffer);
    const outcome = NodeRouter.handle(node, body, &out);
    return .{ outcome, out.buffered() };
}

test "rpc: dispatches a single request" {
    var node: Node = .{};
    var buffer: [512]u8 = undefined;
    const outcome, const text = route(&node,
        \\{"jsonrpc":"2.0","id":7,"method":"eth_chainId"}
    , &buffer);
    try expectEqual(rpc.Outcome.response, outcome);
    try expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x2105\"}", text);
}

test "rpc: typed params and handler errors" {
    var node: Node = .{};
    var buffer: [512]u8 = undefined;
    const address = "\"0x00000000000000000000000000000000000000ff\"";
    _, var text = route(&node, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"eth_getBalance\"," ++
        "\"params\":[" ++ address ++ ",\"latest\"]}", &buffer);
    try expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"result\":\"0xff\"}", text);
    _, text = route(&node, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[" ++ address ++ ",\"pending\"]}", &buffer);
    try expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":" ++
        "{\"code\":-32000,\"message\":\"unknown block\"}}", text);
    _, text = route(&node, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x01\"]}", &buffer);
    try expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":" ++
        "{\"code\":-32602,\"message\":\"invalid params\"}}", text);
    _, text = route(&node,
        \\{"jsonrpc":"2.0","id":1,"method":"test_halfWritten"}
    , &buffer);
    try expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":" ++
        "{\"code\":-32001,\"message\":\"boom\"}}", text);
}

test "rpc: protocol errors" {
    var node: Node = .{};
    var buffer: [512]u8 = undefined;
    const invalid_request =
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request"}}
    ;
    const cases = [_]struct { []const u8, []const u8 }{
        .{
            "{bad",
            \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}
        },
        .{
            \\{"id":1,"method":"eth_chainId"}
            ,
            invalid_request,
        },
        .{
            \\{"jsonrpc":"2.0","id":1,"method":"nope"}
            ,
            \\{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}
        },
        .{ "[]", invalid_request },
        .{ "7", invalid_request },
    };
    for (cases) |case| {
        const outcome, const text = route(&node, case[0], &buffer);
        try expectEqual(rpc.Outcome.response, outcome);
        try expectEqualStrings(case[1], text);
    }
}

test "rpc: notifications and batches" {
    var node: Node = .{};
    var buffer: [1024]u8 = undefined;
    const outcome, _ = route(&node, "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\"}", &buffer);
    try expectEqual(rpc.Outcome.empty, outcome);
    try expectEqual(@as(u32, 1), node.calls);

    _, const text = route(&node,
        \\[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},
        \\{"jsonrpc":"2.0","method":"eth_chainId"},1,
        \\{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber"}]
    , &buffer);
    try expectEqualStrings(
        \\[{"jsonrpc":"2.0","id":1,"result":"0x2105"},{"jsonrpc":"2.0","id":null,"error":
    ++
        \\{"code":-32600,"message":"invalid request"}},{"jsonrpc":"2.0","id":2,"result":"0x1234"}]
    , text);
    try json.validate(text);

    const only_notifications, _ = route(&node,
        \\[{"jsonrpc":"2.0","method":"eth_chainId"}]
    , &buffer);
    try expectEqual(rpc.Outcome.empty, only_notifications);
}

test "rpc: response parsing" {
    const ok = try rpc.client.parse_response(
        \\{"jsonrpc":"2.0","id":3,"result":{"a":[1]}}
    , 3);
    try expectEqualStrings("{\"a\":[1]}", ok.ok);
    const failed = try rpc.client.parse_response("{\"jsonrpc\":\"2.0\",\"id\":3," ++
        "\"error\":{\"code\":-38002,\"message\":\"Invalid forkchoice state\"}}", 3);
    try expectEqual(@as(i64, -38002), failed.rpc_error.code);
    try std.testing.expectError(error.IdMismatch, rpc.client.parse_response(
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":null}",
        3,
    ));
}

const Answer = struct {
    result: [64]u8 = undefined,
    size: usize = 0,
    done: bool = false,

    fn on_result(
        answer: *Answer,
        client: *rpc.Client(io.SimIo),
        result: rpc.client.Error!rpc.client.Result,
    ) void {
        _ = client;
        const value = result catch unreachable;
        @memcpy(answer.result[0..value.ok.len], value.ok);
        answer.size = value.ok.len;
        answer.done = true;
    }
};

fn rpc_handler(node: *Node, request: *const http.Request, response: *http.ResponseBuilder) void {
    const outcome = NodeRouter.handle(node, request.body, response.writer());
    if (outcome == .empty) response.status = 204;
}

fn write_balance_params(context: void, writer: *json.Writer) json.Writer.WriteError!void {
    _ = context;
    try writer.data(&(@as([19]u8, @splat(0)) ++ [_]u8{0x2a}));
    try writer.string("latest");
}

test "rpc: client and server over SimIo" {
    var world = try io.SimWorld.init(std.testing.allocator, .{ .seed = 31 });
    defer world.deinit();
    var server_io: io.SimIo = undefined;
    const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
    try io.SimIo.init(&server_io, std.testing.allocator, &world, .{ .host = server_host });
    defer server_io.deinit();
    var client_io: io.SimIo = undefined;
    const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
    try io.SimIo.init(&client_io, std.testing.allocator, &world, .{ .host = client_host });
    defer client_io.deinit();

    var node: Node = .{};
    const Server = http.Server(io.SimIo, *Node, rpc_handler);
    var server: Server = undefined;
    const limits: http.Limits = .{ .head_size_max = 1024, .body_size_max = 2048 };
    try server.init(std.testing.allocator, &server_io, &node, .{
        .connections_max = 2,
        .recv_buffer_size = 4096,
        .send_buffer_size = 4096,
        .limits = limits,
    });
    defer {
        server.stop();
        var rounds: u32 = 0;
        while (!server.stopped() and rounds < 10_000) : (rounds += 1) {
            world.run_for_ns(std.time.ns_per_ms);
        }
        server.deinit();
    }
    const bound = try server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));

    var client = try rpc.Client(io.SimIo).init(std.testing.allocator, &client_io, bound, .{
        .send_buffer_size = 4096,
        .recv_buffer_size = 4096,
        .limits = limits,
    }, 2048);
    defer client.deinit();
    var answer: Answer = .{};
    try client.call(*Answer, &answer, Answer.on_result, "eth_getBalance", {}, write_balance_params);
    world.run_for_ns(std.time.ns_per_s);
    try std.testing.expect(answer.done);
    try expectEqualStrings("\"0x2a\"", answer.result[0..answer.size]);
}

/// Routing arbitrary bodies never crashes and always yields valid JSON or nothing.
fn route_arbitrary(body: []const u8) !void {
    var node: Node = .{};
    var buffer: [4096]u8 = undefined;
    const outcome, const text = route(&node, body, &buffer);
    switch (outcome) {
        .empty => try expectEqual(@as(usize, 0), text.len),
        .response => try json.validate(text),
    }
}

test "rpc: seeded fuzz of mutated requests" {
    var prng = Prng.init(0x7c);
    const seeds = [_][]const u8{
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x00","latest"]}
        ,
        \\[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","method":"x"}]
        ,
    };
    var body: [256]u8 = undefined;
    for (0..3000) |_| {
        const seed = seeds[prng.below(seeds.len)];
        @memcpy(body[0..seed.len], seed);
        var size = seed.len;
        for (0..prng.range(0, 3)) |_| {
            const position = prng.below(size);
            switch (prng.below(3)) {
                0 => body[position] = "{}[],:\"0x1n"[prng.below(11)],
                1 => size = position + 1,
                2 => body[position] = prng.int(u8),
                else => unreachable,
            }
        }
        try route_arbitrary(body[0..size]);
    }
}

fn fuzz_route(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var body: [1024]u8 = undefined;
    const size = smith.slice(&body);
    try route_arbitrary(body[0..size]);
}

test "rpc: fuzz router" {
    try std.testing.fuzz({}, fuzz_route, .{});
}
