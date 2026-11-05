//! The RPC source against the execution node's real JSON-RPC server over SimIo: the
//! program's L1 provider reads a mined block through an empty store that the hint handler
//! fills over HTTP, and the payload witness hint stores the node's execution witness.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const db_module = @import("../../execution/db/root.zig");
const eth = @import("../../execution/rpc/eth.zig");
const engine_types = @import("../../execution/engine/root.zig").types;
const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const program = @import("../program/root.zig");
const handler_module = @import("handler.zig");
const store_module = @import("store.zig");
const rpc_source = @import("rpc_source.zig");

const body_size_max = 1 << 18;
const Source = rpc_source.RpcSource(io.SimIo);

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

const Harness = struct {
    node: *fixture.Node,
    api: eth.Api,
    generator: db_module.witness_block.Generator,
    scratch: [1 << 16]u8 = undefined,
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    server: Server,
    l1: Source.Client,
    l2: Source.Client,

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
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 53 });
        errdefer harness.world.deinit();
        const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{ .host = server_host });
        errdefer harness.server_io.deinit();
        const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
        try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{ .host = client_host });
        errdefer harness.client_io.deinit();
        try harness.server.init(allocator, &harness.server_io, &harness.api, .{
            .connections_max = 4,
            .recv_buffer_size = 8192,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 4096 },
            .large_send_buffers_max = 2,
            .large_send_buffer_size = body_size_max,
        });
        errdefer harness.server.deinit();
        const bound = try harness.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        const options: http.client.Options = .{
            .send_buffer_size = 4096,
            .recv_buffer_size = body_size_max + 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = body_size_max },
        };
        harness.l1 = try .init(allocator, &harness.client_io, bound, options, 4096);
        errdefer harness.l1.deinit();
        harness.l2 = try .init(allocator, &harness.client_io, bound, options, 4096);
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
        harness.l2.deinit();
        harness.l1.deinit();
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

    fn step(context: *anyopaque) anyerror!void {
        const harness: *Harness = @ptrCast(@alignCast(context));
        harness.world.run_for_ns(std.time.ns_per_ms);
    }

    /// Two transfers in one canonical block on the head; returns its hash.
    fn mine(harness: *Harness) ![32]u8 {
        const node = harness.node;
        var buffers: [2][256]u8 = undefined;
        try fixture.submit(node, 1, 0, 1000, &buffers[0]);
        try fixture.submit(node, 2, 0, 7, &buffers[1]);
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, 12, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, 12);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        return hash.bytes;
    }
};

test "rpc source: L1 provider reads a mined block through hints served over HTTP" {
    const harness = try Harness.create();
    defer harness.destroy();
    const genesis_hash = harness.node.chain.head_hash();
    const block_hash = try harness.mine();
    var source: Source = .init(testing.allocator, &harness.l1, &harness.l2, .{
        .context = harness,
        .step = Harness.step,
    }, .{ .steps_max = 10_000 });
    defer source.deinit();
    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    var handler: handler_module.Handler = .{ .store = &store, .source = source.as_source() };
    var harness_oracle: preimage.InProcess = undefined;
    const options: preimage.in_process.Options = .{ .channel_bytes = 1 << 12 };
    try harness_oracle.init(testing.allocator, store.fetcher(), handler.router(), options);
    defer harness_oracle.deinit(testing.allocator);
    const reader = harness_oracle.oracle_reader();
    var resolver: mpt.OracleResolver = try .init(testing.allocator, reader, .{
        .bytes_max = 1 << 18,
        .entries_max = 1024,
    });
    defer resolver.deinit(testing.allocator);
    const hints = harness_oracle.hint_writer();
    var l1: program.L1ChainProvider = try .init(testing.allocator, &resolver, hints, block_hash, .{
        .items_max = 8,
        .logs_max = 8,
        .topics_max = 8,
        .blob_hashes_max = 8,
    });
    defer l1.deinit(testing.allocator);
    const found = try l1.l1_transactions_by_hash(.{ .bytes = block_hash });
    try testing.expectEqual(@as(usize, 2), found.len);
    const receipts = try l1.l1_receipts_by_hash(.{ .bytes = block_hash });
    try testing.expectEqual(@as(usize, 2), receipts.len);
    try testing.expect(receipts[1].success);
    const parent = try l1.l1_block_info_by_number(0);
    try testing.expect(parent.hash.eql(.{ .bytes = genesis_hash }));
    try testing.expect(source.calls() >= 4);

    // The payload witness of the canonical child of genesis.
    const count = store.count();
    var data: [32 + 2]u8 = undefined;
    data[0..32].* = genesis_hash;
    data[32..].* = "{}".*;
    try handler.handle(.l2_payload_witness, &data);
    try testing.expect(store.count() > count);
    const root = harness.node.chain.record(genesis_hash).?.header.state_root.bytes;
    try testing.expect(store.get(.keccak256(root)) != null);

    // An unknown block is a clean failure, not a stored value.
    const unknown: [32]u8 = @splat(0x42);
    try testing.expectError(error.NotFound, handler.handle(.l1_block_header, &unknown));
}
