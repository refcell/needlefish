//! The RPC source against the execution node's real JSON-RPC server over SimIo: the
//! program's L1 provider reads a mined block through an empty store that the hint handler
//! fills over HTTP, and the payload witness hint stores the node's execution witness.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const db_module = @import("../../execution/db/root.zig");
const eth = @import("../../execution/rpc/eth.zig");
const eth_proof = @import("../../execution/rpc/eth_proof.zig");
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
    /// Serves `eth_getProof` below the head, as a `--proofs-history` node does.
    history: db_module.history.Store,
    /// Large enough for `eth_getProof`'s buffers, historical ones included.
    scratch: [@max(1 << 18, @sizeOf(eth_proof.Scratch) + 64)]u8 = undefined,
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
        harness.history = try .init(allocator, .{
            .window_blocks = 8,
            .paths_max = 1 << 12,
            .small_versions_max = 1 << 12,
            .large_versions_max = 1 << 10,
            .prune_per_commit = 256,
        });
        errdefer harness.history.deinit(allocator);
        // A message passer no mined block touches, with storage (a withdrawal).
        const passer = consensus.predeploys.l2_to_l1_message_passer.bytes;
        try harness.node.db.put_account(passer, 0, 0, &.{0x00});
        try harness.node.db.put_storage(passer, 1, 1);
        try harness.node.db.trie().track_changes(allocator);
        try harness.node.chain.attach_history(&harness.history);
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
        harness.history.deinit(allocator);
        allocator.destroy(harness);
    }

    fn step(context: *anyopaque) anyerror!void {
        const harness: *Harness = @ptrCast(@alignCast(context));
        harness.world.run_for_ns(std.time.ns_per_ms);
    }

    /// Two transfers (senders' `nonce`) in one canonical block on the head; returns its hash.
    fn mine(harness: *Harness, nonce: u64, timestamp: u64) ![32]u8 {
        const node = harness.node;
        var buffers: [2][256]u8 = undefined;
        try fixture.submit(node, 1, nonce, 1000, &buffers[0]);
        try fixture.submit(node, 2, nonce, 7, &buffers[1]);
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, timestamp, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, timestamp);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        return hash.bytes;
    }
};

test "rpc source: L1 provider reads a mined block through hints served over HTTP" {
    const harness = try Harness.create();
    defer harness.destroy();
    const genesis_hash = harness.node.chain.head_hash();
    const block_hash = try harness.mine(0, 12);
    _ = try harness.mine(1, 24);
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

    // The payload witness of the canonical child of block 1 (below the head: history).
    const count = store.count();
    var data: [32 + 2]u8 = undefined;
    data[0..32].* = block_hash;
    data[32..].* = "{}".*;
    try handler.handle(.l2_payload_witness, &data);
    try testing.expect(store.count() > count);
    const parent_root = harness.node.chain.record(block_hash).?.header.state_root.bytes;
    try testing.expect(store.get(.keccak256(parent_root)) != null);
    // It also holds the L2ToL1MessagePasser's account in the parent state, which the block
    // never touches (the client reads the passer's storage root to seal the block).
    const keccak = @import("../../common/crypto/keccak.zig");
    const passer = consensus.predeploys.l2_to_l1_message_passer;
    var scratch: @import("../../execution/trie/root.zig").RlpNode = .{};
    resolver.reset();
    const passer_key = keccak.keccak256(&passer.bytes);
    const trie_reader = resolver.resolver();
    const passer_leaf = try mpt.key_reader.get(trie_reader, parent_root, &passer_key, &scratch);
    try testing.expect(passer_leaf != null);

    // A storage proof hint stores the account path in block 1's state (EIP-2935 leaps).
    var proof_data: [60]u8 = undefined;
    std.mem.writeInt(u64, proof_data[0..8], 1, .big);
    const account = fixture.address_of(1).bytes;
    proof_data[8..28].* = account;
    proof_data[28..60].* = @splat(0);
    try handler.handle(.l2_account_storage_proof, &proof_data);
    const state_root = harness.node.chain.record(block_hash).?.header.state_root.bytes;
    resolver.reset();
    const account_key = keccak.keccak256(&account);
    const leaf = try mpt.key_reader.get(resolver.resolver(), state_root, &account_key, &scratch);
    try testing.expect(leaf != null);
    try testing.expectError(error.InvalidHintData, handler.handle(.l2_account_storage_proof, ""));

    // An unknown block is a clean failure, not a stored value.
    const unknown: [32]u8 = @splat(0x42);
    try testing.expectError(error.NotFound, handler.handle(.l1_block_header, &unknown));
}
