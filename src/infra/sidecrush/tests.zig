//! Simulated-network tests: a fake node serves `latest`, the checker polls it, and HTTP
//! requests are handed to the checker directly.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const sidecrush = @import("root.zig");

const Address = io.Address;
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const FakeNode = struct {
    io: *io.SimIo,
    number: u64 = 1,
    /// Seconds subtracted from the wall clock in the header timestamp.
    behind_s: u64 = 0,
    fail: bool = false,

    fn latest(node: *FakeNode, call: *rpc.Call) rpc.HandlerError!void {
        _ = try call.params.string();
        _ = try call.params.boolean();
        try call.params.finish();
        if (node.fail) return call.fail(rpc.code.internal_error, "unavailable");
        const now_s = node.io.now_realtime_ns() / ns_per_s;
        try call.writer.begin_object();
        try call.writer.key("number");
        try call.writer.quantity(node.number);
        try call.writer.key("timestamp");
        try call.writer.quantity(now_s -| node.behind_s);
        try call.writer.end_object();
    }

    const methods = [_]rpc.Method(*FakeNode){
        .{ .name = "eth_getBlockByNumber", .handler = latest },
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
    node: FakeNode,
    server: http.Server(io.SimIo, *FakeNode, FakeNode.handle),
    checker: sidecrush.Checker(io.SimIo),
    buffer: [8192]u8 = undefined,

    fn init(harness: *Harness, seed: u64, new_instance: bool) !void {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 64 });
        try io.SimIo.init(&harness.node_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.tool_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.node = .{ .io = &harness.node_io };
        try harness.server.init(allocator, &harness.node_io, &harness.node, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
        });
        const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        try harness.checker.init(allocator, &harness.tool_io, bound, .{
            .new_instance = new_instance,
            .version = "v-test",
        });
    }

    fn deinit(harness: *Harness) void {
        harness.checker.stop();
        harness.server.stop();
        var rounds: u32 = 0;
        while (rounds < 1000) : (rounds += 1) {
            if (harness.checker.stopped() and harness.server.stopped()) break;
            harness.world.run_for_ns(ns_per_ms);
        }
        harness.checker.deinit();
        harness.server.deinit();
        harness.tool_io.deinit();
        harness.node_io.deinit();
        harness.world.deinit();
    }

    /// Advances `blocks` 200 ms slots, producing a block in each when `produce`.
    fn run_blocks(harness: *Harness, blocks: u32, produce: bool) void {
        for (0..blocks) |_| {
            if (produce) harness.node.number += 1;
            harness.world.run_for_ns(200 * ns_per_ms);
        }
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
        harness.checker.handle(&request, &response);
        return response;
    }
};

fn contains(response: *http.ResponseBuilder, text: []const u8) bool {
    return std.mem.indexOf(u8, response.body.buffered(), text) != null;
}

test "sidecrush: 200 ms blocks are healthy; a stall degrades, recovery heals" {
    const harness = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(harness);
    try harness.init(21, false);
    defer harness.deinit();
    try testing.expectEqual(sidecrush.State.@"error", harness.checker.state());
    harness.checker.start();
    harness.run_blocks(20, true);
    try testing.expectEqual(sidecrush.State.healthy, harness.checker.state());
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz").status);
    // Production stops: delayed after the 2 s grace, unhealthy at 3 s.
    harness.run_blocks(12, false);
    try testing.expectEqual(sidecrush.State.delayed, harness.checker.state());
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz").status);
    harness.run_blocks(4, false);
    try testing.expectEqual(sidecrush.State.unhealthy, harness.checker.state());
    try testing.expectEqual(@as(u16, 503), harness.get("/readyz").status);
    harness.run_blocks(2, true);
    try testing.expectEqual(sidecrush.State.healthy, harness.checker.state());
    var response = harness.get("/metrics");
    try testing.expect(contains(&response, "sidecrush_state 0"));
    try testing.expect(contains(&response, "sidecrush_head_number 23"));
    try testing.expect(!contains(&response, "sidecrush_unhealthy_ticks_total 0"));
}

test "sidecrush: RPC failure is error; a syncing new instance stays healthy" {
    const harness = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(harness);
    try harness.init(22, true);
    defer harness.deinit();
    harness.node.behind_s = 600; // Syncing: heads ten minutes old, and stalled.
    harness.checker.start();
    harness.run_blocks(30, false);
    try testing.expectEqual(sidecrush.State.healthy, harness.checker.state());
    // Caught up: the stall now counts.
    harness.node.behind_s = 0;
    harness.run_blocks(1, true);
    harness.run_blocks(20, false);
    try testing.expectEqual(sidecrush.State.unhealthy, harness.checker.state());
    harness.node.fail = true;
    harness.run_blocks(2, false);
    try testing.expectEqual(sidecrush.State.@"error", harness.checker.state());
    var response = harness.get("/metrics");
    try testing.expect(contains(&response, "sidecrush_state 3"));
    try testing.expect(!contains(&response, "sidecrush_poll_failures_total 0"));
    try testing.expectEqual(@as(u16, 503), harness.get("/readyz").status);
    try testing.expectEqual(@as(u16, 404), harness.get("/nope").status);
}
