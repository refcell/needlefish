//! `debug_executionWitness` over the real HTTP server on SimIo, with a send buffer smaller
//! than the witness: the handler sizes the response up front and the server moves it into a
//! shared large send buffer. The body must equal the router's direct output (whose witness
//! `debug_test.zig` re-executes statelessly) byte for byte. Witnesses over the configured
//! bound, or over the large buffer, still fail with -32000 "witness too large", and the
//! connection's own send buffer serves the next response again.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const fixture = @import("../node/test_fixture.zig");
const db_module = @import("../db/root.zig");
const eth = @import("eth.zig");
const debug = @import("debug.zig");
const engine_types = @import("../engine/root.zig").types;

const send_buffer_size = 2048;
const large_send_buffer_size = 64 * 1024;
const body_size_max = 128 * 1024;

const generator_config: db_module.witness_block.Config = .{
    .builder = .{
        .sparse = .{
            .nodes_max = 1024,
            .node_bytes_max = 1 << 18,
            .codes_max = 16,
            .code_bytes_max = 1 << 16,
            .headers_max = 16,
            .trie_nodes_max = 4096,
            .storage_tries_max = 32,
        },
        .keys = .{ .accounts_max = 64, .slots_max = 256, .codes_max = 16, .block_numbers_max = 16 },
    },
    .witness = .{
        .state_nodes_max = 1024,
        .state_bytes_max = 1 << 18,
        .codes_max = 16,
        .code_bytes_max = 1 << 16,
        .keys_max = 64 + 256,
        .headers_max = 16,
        .header_bytes_max = 1 << 14,
    },
    .overlay = .{ .accounts_max = 256, .slots_max = 1024, .codes_max = 64 },
    .changeset = .{
        .accounts_max = 256,
        .storage_max = 1024,
        .codes_max = 64,
        .code_bytes_max = 1 << 16,
    },
    .depth_max = 8,
};

fn handle_rpc(api: *eth.Api, request: *const http.Request, response: *http.ResponseBuilder) void {
    const outcome = eth.Router.handle(api, request.body, response.writer());
    if (outcome == .empty) response.status = 204;
}

const Server = http.Server(io.SimIo, *eth.Api, handle_rpc);
const Client = http.Client(io.SimIo);

const Answer = struct {
    body: [body_size_max]u8 = undefined,
    size: usize = 0,
    status: u16 = 0,
    done: bool = false,

    fn on_response(
        answer: *Answer,
        client: *Client,
        result: http.client.Error!*const http.Response,
    ) void {
        _ = client;
        const response = result catch return;
        assert(response.body.len <= answer.body.len);
        @memcpy(answer.body[0..response.body.len], response.body);
        answer.size = response.body.len;
        answer.status = response.status;
        answer.done = true;
    }

    fn text(answer: *const Answer) []const u8 {
        return answer.body[0..answer.size];
    }
};

const Harness = struct {
    node: *fixture.Node,
    api: eth.Api,
    generator: db_module.witness_block.Generator,
    scratch: [1 << 16]u8 = undefined,
    out: [body_size_max]u8 = undefined,
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    server: Server,
    client: Client,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        harness.node = try fixture.Node.create();
        errdefer harness.node.destroy();
        const state = harness.node.db.state;
        harness.generator =
            try db_module.witness_block.Generator.init(allocator, state, generator_config);
        errdefer harness.generator.deinit(allocator);
        harness.api = .{
            .spec = fixture.spec,
            .chain = &harness.node.chain,
            .pool = &harness.node.pool,
            .scratch = &harness.scratch,
            .witness = &harness.generator,
        };
        try harness.init_network();
        return harness;
    }

    fn init_network(harness: *Harness) !void {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 47 });
        errdefer harness.world.deinit();
        const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{ .host = server_host });
        errdefer harness.server_io.deinit();
        const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
        try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{ .host = client_host });
        errdefer harness.client_io.deinit();
        const limits: http.Limits = .{ .head_size_max = 1024, .body_size_max = body_size_max };
        try harness.server.init(allocator, &harness.server_io, &harness.api, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = send_buffer_size,
            .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
            .large_send_buffers_max = 1,
            .large_send_buffer_size = large_send_buffer_size,
        });
        errdefer harness.server.deinit();
        const bound = try harness.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        harness.client = try Client.init(allocator, &harness.client_io, bound, .{
            .send_buffer_size = 4096,
            .recv_buffer_size = body_size_max + 4096,
            .limits = limits,
        });
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
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
        harness.generator.deinit(allocator);
        harness.node.destroy();
        allocator.destroy(harness);
    }

    /// One request over HTTP; returns the response body.
    fn post(harness: *Harness, answer: *Answer, body: []const u8) ![]const u8 {
        answer.* = .{};
        const headers = [_]http.parser.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        try harness.client.request(*Answer, answer, Answer.on_response, .POST, "/", &headers, body);
        harness.world.run_for_ns(std.time.ns_per_s);
        try testing.expect(answer.done);
        try testing.expectEqual(@as(u16, 200), answer.status);
        try json.validate(answer.text());
        return answer.text();
    }

    /// The same request through the router alone, into a buffer larger than any response.
    fn direct(harness: *Harness, body: []const u8) []const u8 {
        var out: std.Io.Writer = .fixed(&harness.out);
        _ = eth.Router.handle(&harness.api, body, &out);
        return out.buffered();
    }

    /// Two transfers, then one block on the head made canonical.
    fn mine(harness: *Harness) !void {
        const node = harness.node;
        var buffers: [2][256]u8 = undefined;
        try fixture.submit(node, 1, 0, 1000, &buffers[0]);
        try fixture.submit(node, 2, 0, 7, &buffers[1]);
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, 12, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, 12);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
    }
};

const witness_request =
    \\{"jsonrpc":"2.0","id":1,"method":"debug_executionWitness","params":["0x1"]}
;
const number_request =
    \\{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}
;

fn expect_too_large(text: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, text, "\"code\":-32000") != null);
    try testing.expect(std.mem.indexOf(u8, text, debug.witness_too_large) != null);
}

test "debug_executionWitness over HTTP: a witness larger than the send buffer is served" {
    const harness = try Harness.create();
    defer harness.destroy();
    try harness.mine();
    const expected = harness.direct(witness_request);
    const length = debug.witness_json_length(&harness.generator.witness);
    try testing.expect(length > send_buffer_size);
    try testing.expect(length < large_send_buffer_size);

    var answer: Answer = .{};
    const text = try harness.post(&answer, witness_request);
    try testing.expectEqualStrings(expected, text);
    const result = (try json.find_path(text, &.{"result"})).?;
    try testing.expectEqual(length, @as(u64, result.len));
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    for (harness.server.connections) |*connection| {
        try testing.expect(connection.large_index == null);
    }

    // The next response on the same connection uses its own buffer again; the large
    // buffer, released after the send, serves the next witness.
    try testing.expectEqualStrings("\"0x1\"", (try json.find_path(
        try harness.post(&answer, number_request),
        &.{"result"},
    )).?);
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    try testing.expectEqualStrings(expected, try harness.post(&answer, witness_request));
    try testing.expectEqual(@as(u64, 2), harness.server.responses_grown);
}

test "debug_executionWitness over HTTP: over the bound or the large buffer fails cleanly" {
    const harness = try Harness.create();
    defer harness.destroy();
    try harness.mine();
    const expected = harness.direct(witness_request);
    const length = debug.witness_json_length(&harness.generator.witness);
    var answer: Answer = .{};

    // The configured bound: one byte short fails before any buffer is taken.
    harness.generator.response_bytes_max = @intCast(length - 1);
    try expect_too_large(try harness.post(&answer, witness_request));
    try testing.expectEqual(@as(u64, 0), harness.server.responses_grown);
    harness.generator.response_bytes_max = @intCast(length);
    try testing.expectEqualStrings(expected, try harness.post(&answer, witness_request));

    // A response larger than the large buffer cannot grow: the same error, from the
    // connection's own buffer.
    harness.server.options.large_send_buffer_size = @intCast(length);
    try expect_too_large(try harness.post(&answer, witness_request));
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    harness.server.options.large_send_buffer_size = large_send_buffer_size;
    try testing.expectEqualStrings(expected, try harness.post(&answer, witness_request));
}
