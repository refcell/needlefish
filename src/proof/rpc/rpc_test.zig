//! The typed proof clients against a canned JSON-RPC server over SimIo: requests carry the
//! expected methods and params, results are decoded, and failures stay clean.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const json = @import("../../utilities/json/root.zig");
const endpoint_module = @import("endpoint.zig");
const clients = @import("clients.zig");
const contracts = @import("../contracts/root.zig");
const keccak256 = @import("../../common/primitives/root.zig").keccak256;

const Endpoint = endpoint_module.Endpoint(io.SimIo);

/// A public Sepolia block (number 12090253) as `eth_getBlockByHash` returns it.
const sepolia_header = @embedFile(
    "../../consensus/sources/testdata/sepolia_l1_12090253_header.json",
);
const sepolia_hash = "bb528dde0066f2187e97eddaba129037d4421843720843ab3ddb961729c13b0b";

const hash_a = "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";

/// Answers by method; records the last request body.
const Canned = struct {
    last: [1024]u8 = undefined,
    last_size: usize = 0,
    /// Answer `debug_*` with "method not found", like public L1 endpoints.
    debug_missing: bool = false,

    fn handle(canned: *Canned, request: *const http.Request, response: *http.ResponseBuilder) void {
        const body = request.body;
        canned.last_size = @min(body.len, canned.last.len);
        @memcpy(canned.last[0..canned.last_size], body[0..canned.last_size]);
        const method_raw = (json.find_path(body, &.{"method"}) catch null) orelse "";
        const debug = std.mem.startsWith(u8, method_raw, "\"debug_");
        const result = if (canned.debug_missing and debug) method_missing else answer(method_raw);
        const out = response.writer();
        out.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},", .{
            (json.find_path(body, &.{"id"}) catch null) orelse "0",
        }) catch return;
        out.print("{s}}}", .{result}) catch return;
    }

    fn answer(method: []const u8) []const u8 {
        const table = .{
            .{ "\"eth_blockNumber\"", "\"result\":\"0x2a\"" },
            .{
                "\"eth_call\"",
                "\"result\":\"0x00000000000000000000000000000000" ++
                    "00000000000000000000000000000007\"",
            },
            .{ "\"eth_getBalance\"", "\"result\":\"0xde0b6b3a7640000\"" },
            .{ "\"eth_getBlockByHash\"", "\"result\":" ++ sepolia_header },
            .{ "\"debug_getRawHeader\"", "\"result\":\"0xc0\"" },
            .{
                "\"optimism_outputAtBlock\"",
                "\"result\":{\"outputRoot\":" ++ hash_a ++ ",\"blockRef\":{\"hash\":" ++
                    hash_a ++ ",\"number\":12}}",
            },
            .{
                "\"optimism_syncStatus\"",
                "\"result\":{\"current_l1\":{\"hash\":" ++ hash_a ++ ",\"number\":3}," ++
                    "\"head_l1\":{\"hash\":" ++ hash_a ++ ",\"number\":4}," ++
                    "\"finalized_l1\":{\"hash\":" ++ hash_a ++ ",\"number\":2}," ++
                    "\"safe_l2\":{\"hash\":" ++ hash_a ++ ",\"number\":10}," ++
                    "\"finalized_l2\":{\"hash\":" ++ hash_a ++ ",\"number\":8," ++
                    "\"l1origin\":{\"hash\":" ++ hash_a ++ ",\"number\":2}}," ++
                    "\"unsafe_l2\":{\"hash\":" ++ hash_a ++ ",\"number\":11}}",
            },
        };
        inline for (table) |row| if (std.mem.eql(u8, method, row[0])) return row[1];
        return method_missing;
    }

    const method_missing = "\"error\":{\"code\":-32601,\"message\":\"method not found\"}";
};

const Server = http.Server(io.SimIo, *Canned, Canned.handle);

const Harness = struct {
    canned: Canned = .{},
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    server: Server,
    client: Endpoint.Client,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        harness.* = .{
            .world = undefined,
            .server_io = undefined,
            .client_io = undefined,
            .server = undefined,
            .client = undefined,
        };
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 61 });
        errdefer harness.world.deinit();
        const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{ .host = server_host });
        errdefer harness.server_io.deinit();
        const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
        try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{ .host = client_host });
        errdefer harness.client_io.deinit();
        try harness.server.init(allocator, &harness.server_io, &harness.canned, .{
            .connections_max = 2,
            .recv_buffer_size = 8192,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 4096 },
        });
        errdefer harness.server.deinit();
        const bound = try harness.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        harness.client = try .init(allocator, &harness.client_io, bound, .{
            .send_buffer_size = 4096,
            .recv_buffer_size = 16384,
            .limits = .{ .head_size_max = 1024, .body_size_max = 8192 },
        }, 4096);
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.client.deinit();
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
        testing.allocator.destroy(harness);
    }

    fn step(context: *anyopaque) anyerror!void {
        const harness: *Harness = @ptrCast(@alignCast(context));
        harness.world.run_for_ns(std.time.ns_per_ms);
    }

    fn last(harness: *const Harness) []const u8 {
        return harness.canned.last[0..harness.canned.last_size];
    }
};

test "rpc: typed execution and rollup calls over HTTP" {
    const harness = try Harness.create();
    defer harness.destroy();
    var endpoint: Endpoint = .init(testing.allocator, &harness.client, .{
        .context = harness,
        .step = Harness.step,
    }, 10_000);
    defer endpoint.deinit();
    const execution: clients.Execution(Endpoint) = .{ .endpoint = &endpoint };
    const rollup: clients.Rollup(Endpoint) = .{ .endpoint = &endpoint };

    try testing.expectEqual(@as(u64, 42), try execution.block_number());
    try testing.expectEqualSlices(u8, &.{0xc0}, try execution.raw_header(.safe));
    try testing.expect(std.mem.indexOf(u8, harness.last(), "[\"safe\"]") != null);
    const balance = try execution.balance(@splat(1), .latest);
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), balance);

    var calldata: [64]u8 = undefined;
    const factory = contracts.dispute_game_factory;
    const data = try contracts.abi.encode_call(&calldata, factory.game_count, &.{});
    const returned = try execution.call_contract(@splat(0xfa), data, .{ .number = 9 });
    const count = try (contracts.abi.Decoder{ .data = returned }).uint(u64, 0);
    try testing.expectEqual(@as(u64, 7), count);
    try testing.expect(std.mem.indexOf(u8, harness.last(), "\"0x9\"") != null);

    const status = try rollup.sync_status();
    try testing.expectEqual(@as(u64, 10), status.safe_l2.number);
    try testing.expectEqual(@as(u64, 2), status.finalized_l1.number);
    try testing.expectEqual(@as(u64, 8), status.finalized_l2.number);
    try testing.expectEqual(@as(u64, 2), status.finalized_l2_origin);
    const output = try rollup.output_at_block(12);
    try testing.expectEqual(@as(u8, 0xaa), output.output_root[0]);
    // The node answered for block 12; asking for another block is a mismatch.
    try testing.expectError(error.CallFailed, rollup.output_at_block(13));
    try testing.expectError(error.NotFound, endpoint.call("eth_unknown", &.{}));
    try testing.expectEqual(@as(u64, 8), endpoint.calls);
}

test "rpc: raw headers fall back to block JSON where debug methods are missing" {
    const harness = try Harness.create();
    defer harness.destroy();
    harness.canned.debug_missing = true;
    var endpoint: Endpoint = .init(testing.allocator, &harness.client, .{
        .context = harness,
        .step = Harness.step,
    }, 10_000);
    defer endpoint.deinit();
    const execution: clients.Execution(Endpoint) = .{ .endpoint = &endpoint };
    var hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hash, sepolia_hash);

    const header = try execution.raw_header_by_hash(hash);
    try testing.expectEqualSlices(u8, &hash, &keccak256(header).bytes);
    try testing.expect(endpoint.debug_raw_missing);
    try testing.expectEqual(@as(u64, 2), endpoint.calls); // debug, then the JSON block.
    // Remembered: the next header goes straight to the JSON method.
    _ = try execution.raw_header_by_hash(hash);
    try testing.expectEqual(@as(u64, 3), endpoint.calls);
    // The node returns that block whatever hash is asked for: it must not be accepted.
    var other = hash;
    other[31] ^= 1;
    try testing.expectError(error.CallFailed, execution.raw_header_by_hash(other));
}
