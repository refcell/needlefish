const std = @import("std");

const io = @import("../io/root.zig");
const http = @import("../http/root.zig");
const rpc = @import("../rpc/root.zig");
const balance_monitor = @import("root.zig");

const Address = io.Address;
const ns_per_s = std.time.ns_per_s;

const account: [20]u8 = @as([19]u8, @splat(0x11)) ++ [_]u8{0x22};

const FakeNode = struct {
    balance: u256 = 0,
    fail: bool = false,
    calls: u32 = 0,

    fn get_balance(node: *FakeNode, call: *rpc.Call) rpc.HandlerError!void {
        node.calls += 1;
        const address = try call.params.fixed(20);
        const tag = try call.params.string();
        try call.params.finish();
        std.debug.assert(std.mem.eql(u8, &address, &account));
        std.debug.assert(std.mem.eql(u8, tag, "latest"));
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
    monitor_io: io.SimIo,
    node: FakeNode = .{},
    server: http.Server(io.SimIo, *FakeNode, FakeNode.handle),
    monitor: balance_monitor.Monitor(io.SimIo),

    fn init(harness: *Harness, seed: u64) !void {
        const allocator = std.testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 11 });
        try io.SimIo.init(&harness.node_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.monitor_io, allocator, &harness.world, .{
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
        try harness.monitor.init(allocator, &harness.monitor_io, bound, account, .{
            .poll_interval_ns = 12 * ns_per_s,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.monitor.stop();
        harness.server.stop();
        var rounds: u32 = 0;
        while (rounds < 1000) : (rounds += 1) {
            if (harness.monitor.stopped() and harness.server.stopped()) break;
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.monitor.deinit();
        harness.server.deinit();
        harness.monitor_io.deinit();
        harness.node_io.deinit();
        harness.world.deinit();
    }
};

test "balance_monitor: publishes immediately, then every interval" {
    var harness: Harness = undefined;
    try harness.init(5);
    defer harness.deinit();
    const monitor = &harness.monitor;
    harness.node.balance = 1_000_000_000_000_000_000;
    monitor.start();
    harness.world.run_for_ns(ns_per_s); // Well before the 12 s interval.
    try std.testing.expectEqual(@as(u64, 1), monitor.updates);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), monitor.balance);

    // Unchanged balances still publish (watch-channel semantics).
    harness.world.run_for_ns(12 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 2), monitor.updates);
    // A balance beyond u128 round-trips.
    harness.node.balance = std.math.maxInt(u256) - 7;
    harness.world.run_for_ns(12 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 3), monitor.updates);
    try std.testing.expectEqual(std.math.maxInt(u256) - 7, monitor.balance);
    try std.testing.expectEqual(@as(u64, 0), monitor.failures);
}

test "balance_monitor: failed reads count and keep the last balance" {
    var harness: Harness = undefined;
    try harness.init(6);
    defer harness.deinit();
    const monitor = &harness.monitor;
    harness.node.balance = 42;
    monitor.start();
    harness.world.run_for_ns(ns_per_s);
    try std.testing.expectEqual(@as(u256, 42), monitor.balance);
    harness.node.fail = true;
    harness.world.run_for_ns(24 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 2), monitor.failures);
    try std.testing.expectEqual(@as(u64, 1), monitor.updates);
    try std.testing.expectEqual(@as(u256, 42), monitor.balance);
    harness.node.fail = false; // Recovers on the next poll.
    harness.node.balance = 43;
    harness.world.run_for_ns(12 * ns_per_s);
    try std.testing.expectEqual(@as(u256, 43), monitor.balance);
}

test "balance_monitor: a stuck read skips polls, then times out" {
    var harness: Harness = undefined;
    try harness.init(7);
    defer harness.deinit();
    const monitor = &harness.monitor;
    harness.node.balance = 9;
    monitor.start();
    harness.world.run_for_ns(ns_per_s);
    try std.testing.expectEqual(@as(u64, 1), monitor.updates);
    // The keep-alive connection now stalls: the read sent at 12 s hangs, and the ticks at
    // 24 s and 36 s find it in flight.
    harness.world.partition(harness.monitor_io.index, harness.node_io.index);
    harness.world.run_for_ns(36 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 2), monitor.polls_skipped);
    try std.testing.expectEqual(@as(u64, 0), monitor.failures);
    // The 48 s tick fails the read (30 s request timeout); the retry cannot connect yet.
    harness.world.run_for_ns(12 * ns_per_s);
    try std.testing.expect(monitor.failures >= 1);
    try std.testing.expectEqual(@as(u64, 1), monitor.updates);
    harness.world.heal_all();
    harness.node.balance = 10;
    harness.world.run_for_ns(12 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 2), monitor.updates);
    try std.testing.expectEqual(@as(u256, 10), monitor.balance);
}

test "balance_monitor: parse_balance" {
    try std.testing.expectEqual(@as(u256, 0), try balance_monitor.parse_balance("\"0x0\""));
    try std.testing.expectEqual(@as(u256, 255), try balance_monitor.parse_balance(" \"0xff\" "));
    const bad = [_][]const u8{ "0x1", "\"0x\"", "\"0x01\"", "null", "\"", "", "\"1\"" };
    for (bad) |raw| {
        try std.testing.expectError(error.InvalidBalance, balance_monitor.parse_balance(raw));
    }
    const too_big = "\"0x1" ++ @as([64]u8, @splat('0')) ++ "\"";
    try std.testing.expectError(error.InvalidBalance, balance_monitor.parse_balance(too_big));
}

fn fuzz_parse(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var buffer: [80]u8 = undefined;
    const size = smith.slice(&buffer);
    const value = balance_monitor.parse_balance(buffer[0..size]) catch return;
    // Accepted inputs re-encode to the same digits.
    var out: [2 + 64]u8 = undefined;
    const text = @import("../json/root.zig").format_quantity(value, &out);
    const trimmed = std.mem.trim(u8, buffer[0..size], " \t\r\n");
    try std.testing.expect(std.ascii.eqlIgnoreCase(text, trimmed[1 .. trimmed.len - 1]));
}

test "balance_monitor: fuzz parse_balance" {
    try std.testing.fuzz({}, fuzz_parse, .{});
}
