//! Metrics endpoint tests: real HTTP requests over SimIo and over the OS backend.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const tx_manager = @import("../tx_manager/root.zig");
const endpoint_module = @import("root.zig");

const Address = io.Address;
const client_options: http.client.Options = .{
    .send_buffer_size = 4096,
    .recv_buffer_size = 72 * 1024,
    .limits = .{ .head_size_max = 4096, .body_size_max = 64 * 1024 },
};

fn Sink(comptime Client: type) type {
    return struct {
        const Self = @This();
        status: u16 = 0,
        body: [64 * 1024]u8 = undefined,
        size: usize = 0,
        errors: u32 = 0,

        fn on_response(
            sink: *Self,
            client: *Client,
            result: http.client.Error!*const http.Response,
        ) void {
            _ = client;
            const response = result catch {
                sink.errors += 1;
                return;
            };
            sink.status = response.status;
            @memcpy(sink.body[0..response.body.len], response.body);
            sink.size = response.body.len;
        }

        fn text(sink: *const Self) []const u8 {
            return sink.body[0..sink.size];
        }
    };
}

const SimEndpoint = endpoint_module.Endpoint(io.SimIo, tx_manager.metrics.entries_count + 1);

const Harness = struct {
    world: io.SimWorld,
    tool_io: io.SimIo,
    scraper_io: io.SimIo,
    endpoint: SimEndpoint,
    tx_metrics: tx_manager.metrics.Metrics = .{},
    extra: metrics.Counter = .{},

    fn init(harness: *Harness) !Address {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 7 });
        try io.SimIo.init(&harness.tool_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.scraper_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.tx_metrics = .{};
        harness.extra = .{};
        try harness.endpoint.init(allocator, &harness.tool_io, "v-test");
        try harness.tx_metrics.register(&harness.endpoint.pages.registry);
        try harness.endpoint.pages.registry.counter("tool_sent_total", "Sent.", &harness.extra);
        return harness.endpoint.listen(Address.ip4(.{ 10, 0, 0, 1 }, 7300));
    }

    fn deinit(harness: *Harness) void {
        harness.endpoint.deinit();
        harness.scraper_io.deinit();
        harness.tool_io.deinit();
        harness.world.deinit();
    }
};

test "metrics endpoint: serves tx_manager metrics, health, and 404 over SimIo" {
    var harness: Harness = undefined;
    const bound = try harness.init();
    defer harness.deinit();
    const Client = http.client.Client(io.SimIo);
    var client = try Client.init(testing.allocator, &harness.scraper_io, bound, client_options);
    defer client.deinit();
    const sink = try testing.allocator.create(Sink(Client));
    defer testing.allocator.destroy(sink);
    sink.* = .{};
    const S = Sink(Client);

    harness.tx_metrics.on_submit();
    harness.tx_metrics.set_pending(1);
    endpoint_module.sync_counter(&harness.extra, 5);
    try client.request(*S, sink, S.on_response, .GET, "/metrics", &.{}, "");
    // The tool's sleep serves the scrape.
    try harness.endpoint.wait_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 200), sink.status);
    try testing.expect(std.mem.indexOf(u8, sink.text(), "tx_manager_submitted_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, sink.text(), "tx_manager_pending 1") != null);
    try testing.expect(std.mem.indexOf(u8, sink.text(), "tool_sent_total 5") != null);

    try client.request(*S, sink, S.on_response, .GET, "/healthz", &.{}, "");
    try harness.endpoint.wait_ns(std.time.ns_per_s);
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", sink.text());
    try client.request(*S, sink, S.on_response, .GET, "/nope", &.{}, "");
    try harness.endpoint.wait_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 404), sink.status);
    try client.request(*S, sink, S.on_response, .POST, "/metrics", &.{}, "x");
    try harness.endpoint.wait_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 405), sink.status);
    try testing.expectEqual(@as(u32, 0), sink.errors);
    try testing.expectEqual(@as(u64, 1), harness.endpoint.pages.scrapes);
}

test "metrics endpoint: sync_counter follows a cumulative count" {
    var counter: metrics.Counter = .{};
    endpoint_module.sync_counter(&counter, 0);
    endpoint_module.sync_counter(&counter, 3);
    endpoint_module.sync_counter(&counter, 3);
    try testing.expectEqual(@as(u64, 3), counter.get());
}

test "metrics endpoint: scrape over the OS backend while the tool waits" {
    var os_io = try io.init_for_test();
    defer os_io.deinit();
    const OsEndpoint = endpoint_module.Endpoint(io.IO, 1);
    var endpoint: OsEndpoint = undefined;
    try endpoint.init(testing.allocator, &os_io, "v-os");
    defer endpoint.deinit();
    var sent: metrics.Counter = .{};
    try endpoint.pages.registry.counter("tool_sent_total", "Sent.", &sent);
    const bound = try endpoint.listen(Address.loopback(0));
    sent.add(9);
    const Client = http.client.Client(io.IO);
    var client = try Client.init(testing.allocator, &os_io, bound, client_options);
    defer client.deinit();
    const S = Sink(Client);
    const sink = try testing.allocator.create(S);
    defer testing.allocator.destroy(sink);
    sink.* = .{};
    try client.request(*S, sink, S.on_response, .GET, "/metrics", &.{}, "");
    var rounds: u32 = 0;
    while (sink.status == 0 and sink.errors == 0 and rounds < 200) : (rounds += 1) {
        try endpoint.wait_ns(10 * std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(u16, 200), sink.status);
    try testing.expect(std.mem.indexOf(u8, sink.text(), "tool_sent_total 9") != null);
}
