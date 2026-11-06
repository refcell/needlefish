//! JSON-RPC query tests: each method, limits, invalid params, and retired write methods.

const std = @import("std");
const testing = std.testing;

const rpc_module = @import("rpc.zig");
const store_module = @import("store.zig");
const time = @import("time.zig");

const day_ns = 86_400 * std.time.ns_per_s;

const Harness = struct {
    store: store_module.Store,
    context: rpc_module.Context,
    out: [16 * 1024]u8 = undefined,
    response: []const u8 = "",

    fn init(harness: *Harness) !void {
        harness.store = try store_module.Store.init(testing.allocator, .{
            .events_max = 16,
            .arena_bytes = 4096,
            .retention_ns = .initFill(30 * day_ns),
        });
        harness.context = .{
            .store = &harness.store,
            .now_ns = try time.parse("2026-11-05T12:00:00Z"),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.store.deinit(testing.allocator);
    }

    fn add(harness: *Harness, value: store_module.Record) void {
        _ = harness.store.insert(&value);
    }

    fn call(harness: *Harness, method: []const u8, params: []const u8) []const u8 {
        var body: [1024]u8 = undefined;
        const text = std.fmt.bufPrint(&body, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\"," ++
            "\"params\":{s}}}", .{ method, params }) catch unreachable;
        var writer: std.Io.Writer = .fixed(&harness.out);
        _ = rpc_module.Router.handle(&harness.context, text, &writer);
        harness.response = writer.buffered();
        return harness.response;
    }

    fn ids(harness: *const Harness, buffer: []u8) []const u8 {
        var writer: std.Io.Writer = .fixed(buffer);
        var rest = harness.response;
        while (std.mem.indexOf(u8, rest, "\"event_id\":\"")) |index| {
            rest = rest[index + 12 ..];
            const end = std.mem.indexOfScalar(u8, rest, '"').?;
            writer.print("{s},", .{rest[0..end]}) catch unreachable;
        }
        return writer.buffered();
    }
};

fn record(id: []const u8, offset_s: u64, extra: struct {
    tx: ?u8 = null,
    block: ?u64 = null,
    block_hash: ?u8 = null,
    bundle_id: ?[]const u8 = null,
    event_type: @import("event.zig").EventType = .builder_accepted,
}) store_module.Record {
    const base_ns = time.parse("2026-11-05T11:00:00Z") catch unreachable;
    return .{ .ingested_at_ns = base_ns + 3600 * std.time.ns_per_s, .event = .{
        .event_id = id,
        .event_time_ns = base_ns + offset_s * std.time.ns_per_s,
        .producer = .base_builder,
        .event_type = extra.event_type,
        .network = "base-mainnet",
        .tx_hash = if (extra.tx) |byte| @splat(byte) else null,
        .block_hash = if (extra.block_hash) |byte| @splat(byte) else null,
        .block_number = extra.block,
        .data = "{\"position\":1}",
        .bundle_id = extra.bundle_id,
    } };
}

const hash_11 = "\"0x1111111111111111111111111111111111111111111111111111111111111111\"";

test "rpc: getTransactionEventsByHash returns full records, oldest first" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.add(record("b", 2, .{ .tx = 0x11 }));
    harness.add(record("a", 1, .{ .tx = 0x11, .block = 7 }));
    const response = harness.call("base_getTransactionEventsByHash", "[" ++ hash_11 ++ "]");
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"result":[{"schema_version":"transaction-event/v1",
    ++
        \\"event_id":"a","event_time":"2026-11-05T11:00:01Z","producer":"base-builder",
    ++
        \\"event_type":"BUILDER_ACCEPTED","network":"base-mainnet","tx_hash":
    ++ hash_11 ++
        \\,"block_hash":null,"block_number":7,"payload_id":null,"request_id":null,
    ++
        \\"data":{"position":1},"ingested_at":"2026-11-05T12:00:00Z"},
    ++
        \\{"schema_version":"transaction-event/v1","event_id":"b","event_time":
    ++
        \\"2026-11-05T11:00:02Z","producer":"base-builder","event_type":"BUILDER_ACCEPTED",
    ++
        \\"network":"base-mainnet","tx_hash":
    ++ hash_11 ++
        \\,"block_hash":null,"block_number":null,"payload_id":null,"request_id":null,
    ++
        \\"data":{"position":1},"ingested_at":"2026-11-05T12:00:00Z"}]}
    , response);
    var buffer: [64]u8 = undefined;
    // Upper-case and unprefixed hashes match; a limit trims; a non-hash matches nothing.
    const upper = "[\"1111111111111111111111111111111111111111111111111111111111111111\",1]";
    _ = harness.call("base_getTransactionEventsByHash", upper);
    try testing.expectEqualStrings("a,", harness.ids(&buffer));
    _ = harness.call("base_getTransactionEventsByHash", "[\"not-a-hash\"]");
    const empty = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}";
    try testing.expectEqualStrings(empty, harness.response);
}

test "rpc: block number, block hash, and bundle queries" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.add(record("a", 1, .{ .block = 9, .bundle_id = "bundle-1" }));
    harness.add(record("b", 2, .{ .block = 9, .block_hash = 0x22 }));
    harness.add(record("c", 3, .{ .block = 10, .block_hash = 0x22, .bundle_id = "bundle-1" }));
    var buffer: [64]u8 = undefined;
    _ = harness.call("base_getTransactionEventsByBlockNumber", "[9]");
    try testing.expectEqualStrings("a,b,", harness.ids(&buffer));
    _ = harness.call("base_getTransactionEventsByBlockNumber", "[9, null]");
    try testing.expectEqualStrings("a,b,", harness.ids(&buffer));
    const hash_22 = "2222222222222222222222222222222222222222222222222222222222222222";
    const block_hash = "[\"0x" ++ hash_22 ++ "\", 500]";
    _ = harness.call("base_getTransactionEventsByBlockHash", block_hash);
    try testing.expectEqualStrings("b,c,", harness.ids(&buffer));
    _ = harness.call("base_getTransactionEventsByBundle", "[\"bundle-1\"]");
    try testing.expectEqualStrings("a,c,", harness.ids(&buffer));
    _ = harness.call("base_getTransactionEventsByBundle", "[\"bundle-1\", -5]");
    try testing.expectEqualStrings("a,", harness.ids(&buffer));
    const long_key: [400]u8 = @splat('k');
    var params: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&params, "[\"{s}\"]", .{long_key});
    _ = harness.call("base_getTransactionEventsByBundle", text);
    try testing.expectEqualStrings("", harness.ids(&buffer));
}

test "rpc: getRejectedTransactionEvents filters and orders newest first" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.add(record("r1", 10, .{ .block = 1, .event_type = .builder_rejected }));
    harness.add(record("r2", 20, .{ .block = 2, .event_type = .simulation_failed }));
    harness.add(record("r3", 30, .{ .event_type = .builder_expired }));
    harness.add(record("ok", 40, .{ .block = 2 }));
    var buffer: [64]u8 = undefined;
    _ = harness.call("base_getRejectedTransactionEvents", "[{}]");
    try testing.expectEqualStrings("r3,r2,r1,", harness.ids(&buffer));
    _ = harness.call("base_getRejectedTransactionEvents", "[{\"fromBlock\":2,\"toBlock\":5}]");
    try testing.expectEqualStrings("r2,", harness.ids(&buffer));
    const window = "[{\"fromTime\":\"2026-11-05T11:00:10Z\",\"toTime\":\"2026-11-05T11:00:30Z\"," ++
        "\"limit\":1,\"other\":[1]}]";
    _ = harness.call("base_getRejectedTransactionEvents", window);
    try testing.expectEqualStrings("r2,", harness.ids(&buffer));
    _ = harness.call("base_getRejectedTransactionEvents", "[{\"fromTime\":\"yesterday\"}]");
    try testing.expect(std.mem.indexOf(u8, harness.response, "-32602") != null);
}

test "rpc: invalid params, retired write methods, unknown methods" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const invalid = [_][2][]const u8{
        .{ "base_getTransactionEventsByHash", "[]" },
        .{ "base_getTransactionEventsByHash", "[1]" },
        .{ "base_getTransactionEventsByHash", "[\"0x\", 1.5]" },
        .{ "base_getTransactionEventsByBlockNumber", "[\"0x1\"]" },
        .{ "base_getTransactionEventsByBlockNumber", "[-1]" },
        .{ "base_getTransactionEventsByBundle", "[\"a\", 1, 2]" },
        .{ "base_getRejectedTransactionEvents", "[[]]" },
        .{ "base_getRejectedTransactionEvents", "[{\"fromBlock\":\"1\"}]" },
    };
    for (invalid) |case| {
        const response = harness.call(case[0], case[1]);
        try testing.expect(std.mem.indexOf(u8, response, "\"code\":-32602") != null);
    }
    const too_big = harness.call("base_getTransactionEventsByBlockNumber", "[9223372036854775808]");
    try testing.expect(std.mem.indexOf(u8, too_big, "\"code\":-32603") != null);
    const retired = [_][]const u8{
        "base_persistBatchedBundleEvent", "base_persistRejectedTransactionBatch", "eth_chainId",
    };
    for (retired) |method| {
        const response = harness.call(method, "[[]]");
        try testing.expect(std.mem.indexOf(u8, response, "\"code\":-32601") != null);
        try testing.expect(std.mem.indexOf(u8, response, "\"result\"") == null);
    }
}

test "rpc: rejected query parser" {
    const query = try rpc_module.parse_rejected_query(
        "{\"fromBlock\":null,\"toBlock\":3,\"limit\":5000}",
    );
    try testing.expect(query.from_block == null);
    try testing.expectEqual(@as(u64, 3), query.to_block.?);
    try testing.expectEqual(@as(u32, 2000), query.limit);
    try testing.expectError(error.Invalid, rpc_module.parse_rejected_query("{\"limit\":\"1\"}"));
    try testing.expectError(error.Invalid, rpc_module.parse_rejected_query("{\"toBlock\":{}}"));
}
