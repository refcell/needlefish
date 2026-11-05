//! Simulated-network tests: a fake node answers `eth_getBalance`, the exporter polls it,
//! and HTTP requests are handed to the exporter directly.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const exporter_module = @import("root.zig");

const Address = io.Address;
const ns_per_s = std.time.ns_per_s;
const account: [20]u8 = @splat(0x33);

const FakeNode = struct {
    balance: u256 = 0,
    fail: bool = false,

    fn get_balance(node: *FakeNode, call: *rpc.Call) rpc.HandlerError!void {
        _ = try call.params.fixed(20);
        _ = try call.params.string();
        try call.params.finish();
        if (node.fail) return call.fail(rpc.code.internal_error, "unavailable");
        try call.writer.quantity(node.balance);
    }

    const methods = [_]rpc.Method(*FakeNode){
        .{ .name = "eth_getBalance", .handler = get_balance },
    };
    const Router = rpc.Router(*FakeNode, &methods);

    fn handle(node: *FakeNode, request: *const http.Request, response: *http.ResponseBuilder) void {
        _ = Router.handle(node, request.body, response.writer());
    }
};

const Harness = struct {
    world: io.SimWorld,
    node_io: io.SimIo,
    tool_io: io.SimIo,
    node: FakeNode = .{},
    server: http.Server(io.SimIo, *FakeNode, FakeNode.handle),
    exporter: exporter_module.Exporter(io.SimIo),
    buffer: [8192]u8 = undefined,

    fn init(harness: *Harness, seed: u64) !void {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 64 });
        try io.SimIo.init(&harness.node_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.tool_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.node = .{};
        try harness.server.init(allocator, &harness.node_io, &harness.node, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
        });
        const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        try harness.exporter.init(allocator, &harness.tool_io, bound, account, .{
            .monitor = .{ .poll_interval_ns = 10 * ns_per_s },
            .version = "v-test",
        });
    }

    fn deinit(harness: *Harness) void {
        harness.exporter.stop();
        harness.server.stop();
        var rounds: u32 = 0;
        while (rounds < 1000) : (rounds += 1) {
            if (harness.exporter.stopped() and harness.server.stopped()) break;
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.exporter.deinit();
        harness.server.deinit();
        harness.tool_io.deinit();
        harness.node_io.deinit();
        harness.world.deinit();
    }

    fn get(harness: *Harness, target: []const u8) http.ResponseBuilder {
        var response = http.ResponseBuilder.init(&harness.buffer);
        const request: http.Request = .{
            .method = .GET,
            .method_text = "GET",
            .target = target,
            .version = .http_1_1,
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
        harness.exporter.handle(&request, &response);
        return response;
    }
};

test "balance_monitor exporter: metrics, readiness, and staleness" {
    var harness: Harness = undefined;
    try harness.init(11);
    defer harness.deinit();
    try testing.expectEqual(@as(u16, 503), harness.get("/readyz").status);
    var response = harness.get("/metrics");
    try testing.expect(std.mem.indexOf(u8, response.body.buffered(), "age_seconds -1") != null);

    harness.node.balance = 3 * 1_000_000_000_000_000_000 + 5;
    harness.exporter.start();
    harness.world.run_for_ns(ns_per_s);
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz").status);
    response = harness.get("/metrics");
    const text = response.body.buffered();
    const gwei_line = "balance_monitor_balance_gwei 3000000000";
    try testing.expect(std.mem.indexOf(u8, text, gwei_line) != null);
    try testing.expect(std.mem.indexOf(u8, text, "balance_monitor_reads_total 1") != null);

    // The node fails: reads stop and readiness lapses after three intervals.
    harness.node.fail = true;
    harness.world.run_for_ns(25 * ns_per_s);
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz").status);
    harness.world.run_for_ns(10 * ns_per_s);
    try testing.expectEqual(@as(u16, 503), harness.get("/readyz").status);
    response = harness.get("/metrics");
    try testing.expect(std.mem.indexOf(u8, response.body.buffered(), "failures_total 3") != null);

    harness.node.fail = false;
    harness.world.run_for_ns(10 * ns_per_s);
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz").status);
}

test "balance_monitor exporter: health and unknown paths" {
    var harness: Harness = undefined;
    try harness.init(12);
    defer harness.deinit();
    var response = harness.get("/healthz");
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", response.body.buffered());
    try testing.expectEqual(@as(u16, 200), harness.get("/").status);
    try testing.expectEqual(@as(u16, 404), harness.get("/nope").status);
    try testing.expectEqual(@as(u16, 200), harness.get("/metrics?x=1").status);
}
