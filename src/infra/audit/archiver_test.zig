//! The archiver over SimIo: a Vector-like client posts NDJSON batches over HTTP, then
//! queries them back over JSON-RPC; plus health, metrics, oversized bodies, and retention.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const audit = @import("root.zig");
const line = @import("ingest_test.zig").line;

const Address = io.Address;
const SimIo = io.SimIo;
const Archiver = audit.archiver.Archiver(SimIo);
const Client = http.Client(SimIo);
const ms = std.time.ns_per_ms;
const day_ns = 86_400 * std.time.ns_per_s;
/// SimIo's default wall clock starts at 2023-11-14T22:13:20Z.
const now_text = "2023-11-14T22:13:20Z";

const limits: http.Limits = .{ .head_size_max = 1024, .body_size_max = 8 * 1024 };

const Result = struct {
    status: u16 = 0,
    body: [8192]u8 = undefined,
    body_size: usize = 0,
    calls: u32 = 0,

    fn on_response(
        result: *Result,
        client: *Client,
        response: http.client.Error!*const http.Response,
    ) void {
        _ = client;
        result.calls += 1;
        const value = response catch return;
        result.status = value.status;
        @memcpy(result.body[0..value.body.len], value.body);
        result.body_size = value.body.len;
    }

    fn text(result: *const Result) []const u8 {
        return result.body[0..result.body_size];
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,
    archiver: Archiver,
    bound: Address,

    fn init(harness: *Harness, seed: u64) !void {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 512 });
        try SimIo.init(&harness.server_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try SimIo.init(&harness.client_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        try harness.archiver.init(allocator, &harness.server_io, .{
            .store = .{
                .events_max = 4,
                .arena_bytes = 4096,
                .retention_ns = .init(.{
                    .hot = 3 * day_ns,
                    .warm = 7 * day_ns,
                    .cold = 30 * day_ns,
                }),
            },
            .ingest = .{
                .batch_max = 8,
                .request_bytes_max = 6 * 1024,
                .event = .{ .event_bytes_max = 1024, .data_bytes_max = 512 },
            },
            .server = .{
                .connections_max = 4,
                .recv_buffer_size = limits.head_size_max + limits.body_size_max,
                .send_buffer_size = 16 * 1024,
                .limits = limits,
            },
            .version = "v-test",
        });
        harness.bound = try harness.archiver.listen(Address.ip4(.{ 10, 0, 0, 1 }, 9100));
    }

    fn deinit(harness: *Harness) void {
        harness.archiver.stop();
        var rounds: u32 = 0;
        while (rounds < 10_000 and !harness.archiver.stopped()) : (rounds += 1) {
            harness.world.run_for_ns(ms);
        }
        std.debug.assert(harness.archiver.stopped());
        harness.archiver.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }

    fn post(harness: *Harness, target: []const u8, body: []const u8, result: *Result) !void {
        var client = try Client.init(testing.allocator, &harness.client_io, harness.bound, .{
            .send_buffer_size = 16 * 1024,
            .recv_buffer_size = 16 * 1024,
            .limits = .{ .head_size_max = 1024, .body_size_max = 15 * 1024 },
        });
        defer client.deinit();
        result.* = .{};
        try client.request(*Result, result, Result.on_response, .POST, target, &.{}, body);
        var elapsed_ns: u64 = 0;
        while (result.calls == 0 and elapsed_ns < 2000 * ms) : (elapsed_ns += 10 * ms) {
            harness.world.run_for_ns(10 * ms);
            harness.archiver.tick();
        }
        try testing.expectEqual(@as(u32, 1), result.calls);
    }

    fn get(harness: *Harness, target: []const u8, buffer: []u8) http.ResponseBuilder {
        var response = http.ResponseBuilder.init(buffer);
        const request: http.Request = .{
            .method = .GET,
            .method_text = "GET",
            .target = target,
            .version = .http_1_1,
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
        harness.archiver.handle(&request, &response);
        return response;
    }
};

fn contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestUnexpectedResult;
    }
}

const by_hash = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"base_getTransactionEventsByHash\"," ++
    "\"params\":[\"0x1111111111111111111111111111111111111111111111111111111111111111\"]}";

test "archiver: ingest over HTTP, then query over JSON-RPC" {
    var harness: Harness = undefined;
    try harness.init(21);
    defer harness.deinit();
    var lines: [2][512]u8 = undefined;
    var body: [1200]u8 = undefined;
    const batch = try std.fmt.bufPrint(&body, "{s}\n{s}\n", .{
        line(&lines[0], "event-1", now_text, ""),
        line(&lines[1], "event-2", now_text, ""),
    });
    const result = try testing.allocator.create(Result);
    defer testing.allocator.destroy(result);
    try harness.post(audit.ingest.default_path, batch, result);
    try testing.expectEqual(@as(u16, 200), result.status);
    try contains(result.text(), "\"status\":\"accepted\",\"accepted\":2");
    try harness.post(audit.ingest.default_path, batch, result);
    try contains(result.text(), "\"status\":\"duplicate\",\"accepted\":0,\"duplicate\":2");
    try harness.post("/", by_hash, result);
    try testing.expectEqual(@as(u16, 200), result.status);
    const head = "\"id\":7,\"result\":[{\"schema_version\":\"transaction-event/v1\"";
    try contains(result.text(), head);
    try contains(result.text(), "\"event_id\":\"event-2\"");
    // Retired write RPCs fail explicitly.
    const retired = "{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"method\":\"base_persistBatchedBundleEvent\",\"params\":[[]]}";
    try harness.post("/", retired, result);
    try contains(result.text(), "\"code\":-32601");
    var buffer: [16 * 1024]u8 = undefined;
    const metrics_text = harness.get("/metrics", &buffer).body.buffered();
    try contains(metrics_text, "audit_transaction_events_received_total 4");
    try contains(metrics_text, "audit_transaction_events_persisted_total 2");
    try contains(metrics_text, "audit_transaction_events_duplicate_total 2");
    try contains(metrics_text, "audit_transaction_events_stored 2");
    try contains(metrics_text, "audit_rpc_requests_total 2");
}

test "archiver: capacity eviction, oversized bodies, and health" {
    var harness: Harness = undefined;
    try harness.init(22);
    defer harness.deinit();
    var lines: [6][512]u8 = undefined;
    var body: [4000]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&body);
    for (&lines, 0..) |*buffer, index| {
        var id: [16]u8 = undefined;
        const event_id = try std.fmt.bufPrint(&id, "event-{d}", .{index});
        try writer.print("{s}\n", .{line(buffer, event_id, now_text, "")});
    }
    const result = try testing.allocator.create(Result);
    defer testing.allocator.destroy(result);
    try harness.post(audit.ingest.default_path, writer.buffered(), result);
    try contains(result.text(), "\"accepted\":6");
    try testing.expectEqual(@as(u32, 4), harness.archiver.store.count);
    try testing.expect(harness.archiver.store.find_event_id("event-1") == null);
    var buffer: [16 * 1024]u8 = undefined;
    try contains(
        harness.get("/metrics", &buffer).body.buffered(),
        "audit_transaction_events_evicted_total{reason=\"capacity\"} 2",
    );
    // Over the ingest limit (6 KiB) but within the HTTP limit (8 KiB): 413.
    const large: [7000]u8 = @splat(' ');
    try harness.post(audit.ingest.default_path, &large, result);
    try testing.expectEqual(@as(u16, 413), result.status);
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz", &buffer).status);
    const healthz = harness.get("/healthz", &buffer).body.buffered();
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", healthz);
    try testing.expectEqual(@as(u16, 404), harness.get("/nope", &buffer).status);
}

test "archiver: retention evicts expired events as time passes" {
    var harness: Harness = undefined;
    try harness.init(23);
    defer harness.deinit();
    var lines: [512]u8 = undefined;
    const result = try testing.allocator.create(Result);
    defer testing.allocator.destroy(result);
    try harness.post(audit.ingest.default_path, line(&lines, "event-1", now_text, ""), result);
    try testing.expectEqual(@as(u32, 1), harness.archiver.store.count);
    // BUILDER_ACCEPTED is hot (3 days); four days later it is gone.
    harness.world.run_for_ns(4 * day_ns);
    harness.archiver.tick();
    try testing.expectEqual(@as(u32, 0), harness.archiver.store.count);
    try harness.post("/", by_hash, result);
    try contains(result.text(), "\"result\":[]");
    try testing.expectEqual(@as(u64, 1), harness.archiver.store.stats.evicted_retention);
}
