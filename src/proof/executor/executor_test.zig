//! End to end: the node builds L2 blocks; their execution witnesses and the chain's
//! headers are served through the in-process preimage oracle; the stateless builder
//! rebuilds each block from its parent header and attributes alone and must reach the
//! node's block hash, state root and output root.

const std = @import("std");
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const db_module = @import("../../execution/db/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const node_witness = @import("../../execution/node/witness.zig");
const engine_types = @import("../../execution/engine/root.zig").types;
const builder_module = @import("builder.zig");

const Hash = [32]u8;
const Builder = builder_module.Builder;
const spec = &chainspec.ChainSpec.presets.base_devnet;

const sparse_config: db_module.witness.SparseState.Config = .{
    .nodes_max = 1024,
    .node_bytes_max = 1 << 18,
    .codes_max = 16,
    .code_bytes_max = 1 << 16,
    .headers_max = 16,
    .trie_nodes_max = 4096,
    .storage_tries_max = 32,
};

const changeset_config: db_module.changeset.Config = .{
    .accounts_max = 256,
    .storage_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 1 << 16,
};

const generator_config: db_module.witness_block.Config = .{
    .builder = .{ .sparse = sparse_config, .keys = .{
        .accounts_max = 64,
        .slots_max = 256,
        .codes_max = 16,
        .block_numbers_max = 16,
    } },
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
    .changeset = changeset_config,
    .depth_max = 8,
};

const builder_config: builder_module.Config = .{
    .sparse = sparse_config,
    .changeset = changeset_config,
    .executor = .{
        .scratch_bytes = 1 << 20,
        .transactions_max = 64,
        .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
        .limits = .{
            .accounts_max = 256,
            .slots_max = 1024,
            .transient_slots_max = 64,
            .journal_entries_max = 4096,
            .logs_max = 64,
            .log_data_bytes_max = 4096,
            .code_bytes_max = 1 << 16,
        },
    },
    .resolver = .{ .bytes_max = 1 << 20, .entries_max = 4096 },
};

/// Keccak preimages (trie nodes, codes, headers) and the hints the client sent.
const Host = struct {
    map: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    arena: std.heap.ArenaAllocator,
    witness_hints: u32 = 0,
    other_hints: u32 = 0,

    fn put(host: *Host, bytes: []const u8) !void {
        const copy = try host.arena.allocator().dupe(u8, bytes);
        const key = preimage.Key.keccak256(primitives.keccak256(copy).bytes);
        try host.map.put(testing.allocator, key.to_bytes(), copy);
    }

    fn put_header(host: *Host, header: consensus.Header) !void {
        var buffer: [2048]u8 = undefined;
        try host.put(rlp.encode_to(&buffer, header));
    }

    fn get_preimage(
        context: *anyopaque,
        key: preimage.Key,
    ) preimage.oracle.FetchError![]const u8 {
        const host: *Host = @ptrCast(@alignCast(context));
        return host.map.get(key.to_bytes()) orelse error.KeyNotFound;
    }

    fn route_hint(context: *anyopaque, text: []const u8) preimage.hint.RouteError!void {
        const host: *Host = @ptrCast(@alignCast(context));
        var data: [4096]u8 = undefined;
        const parsed = preimage.Hint.parse(text, &data) catch return error.HintRejected;
        if (std.mem.eql(u8, parsed.type_name, "l2-payload-witness")) {
            if (parsed.data.len <= 32 or parsed.data[32] != '{') return error.HintRejected;
            host.witness_hints += 1;
        } else {
            host.other_hints += 1;
        }
    }
};

const Harness = struct {
    node: *fixture.Node,
    generator: db_module.witness_block.Generator,
    host: Host,
    in_process: preimage.InProcess,
    builder: Builder,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        harness.node = try fixture.Node.create_for(spec);
        errdefer harness.node.destroy();
        const state = harness.node.db.state;
        harness.generator = try .init(allocator, state, generator_config);
        errdefer harness.generator.deinit(allocator);
        harness.host = .{ .arena = .init(allocator) };
        errdefer harness.host.arena.deinit();
        const host = &harness.host;
        const fetcher: preimage.Fetcher = .{ .context = host, .get_preimage = Host.get_preimage };
        const router: preimage.Router = .{ .context = host, .route_hint = Host.route_hint };
        try harness.in_process.init(allocator, fetcher, router, .{
            .channel_bytes = 1 << 18,
            .hint_bytes = 1 << 14,
        });
        errdefer harness.in_process.deinit(allocator);
        const oracle = harness.in_process.oracle_reader();
        const hints = harness.in_process.hint_writer();
        try harness.builder.init(allocator, spec, oracle, hints, builder_config);
        return harness;
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
        harness.builder.deinit(allocator);
        harness.in_process.deinit(allocator);
        harness.host.map.deinit(allocator);
        harness.host.arena.deinit();
        harness.generator.deinit(allocator);
        harness.node.destroy();
        allocator.destroy(harness);
    }

    /// Two transfers, then one block on the head made canonical.
    fn mine(harness: *Harness, nonce: u64, timestamp: u64) !Hash {
        const node = harness.node;
        var buffers: [2][256]u8 = undefined;
        try fixture.submit(node, 1, nonce, 1000 + nonce, &buffers[0]);
        try fixture.submit(node, 2, nonce, 7, &buffers[1]);
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, timestamp, 0xfe);
        const version = engine_types.forkchoice_version(spec, timestamp);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        return hash.bytes;
    }

    /// Serves block `hash`'s witness and its parent chain's headers through the host.
    fn serve(harness: *Harness, hashes: []const Hash, index: usize) !void {
        const chain = &harness.node.chain;
        try node_witness.execution_witness(chain, &harness.generator, hashes[index]);
        const witness = &harness.generator.witness;
        for (0..witness.state.count) |i| try harness.host.put(witness.state.get(@intCast(i)));
        for (0..witness.codes.count) |i| try harness.host.put(witness.codes.get(@intCast(i)));
        for (hashes[0..index]) |hash| try harness.host.put_header(chain.header(hash).?);
    }

    /// Rebuilds block `hash` statelessly and checks it against the node's.
    fn rebuild(harness: *Harness, hash: Hash) !void {
        const chain = &harness.node.chain;
        var stored = chain.record(hash).?;
        var transactions: [64][]const u8 = undefined;
        var count: usize = 0;
        while (!stored.transactions.is_empty()) : (count += 1) {
            transactions[count] = try stored.transactions.bytes();
        }
        try testing.expect(count > 0);
        const parent = chain.header(stored.header.parent_hash.bytes).?;
        var attributes = fixture.attributes_l2(stored.header.timestamp, 0xfe);
        attributes.transactions = transactions[0..count];
        attributes.no_tx_pool = true;
        const parent_hash = stored.header.parent_hash.bytes;
        const outcome = try harness.builder.build_block(&parent, parent_hash, &attributes);
        try testing.expectEqual(stored.header.state_root, outcome.header.state_root);
        try testing.expectEqual(stored.header.receipts_root, outcome.header.receipts_root);
        try testing.expectEqual(stored.header.withdrawals_root, outcome.header.withdrawals_root);
        try testing.expectEqualSlices(u8, &hash, &outcome.hash);
        const output_root = try harness.builder.output_root(&outcome.header, outcome.hash);
        const expected = builder_module.output_root_from_parts(
            stored.header.state_root.bytes,
            stored.header.withdrawals_root.?.bytes,
            hash,
        );
        try testing.expectEqualSlices(u8, &expected, &output_root);
    }
};

test "executor: stateless rebuild of node-built L2 blocks over the oracle" {
    const harness = try Harness.create();
    defer harness.destroy();
    var hashes: [4]Hash = undefined;
    hashes[0] = harness.node.chain.head_hash();
    for (1..4) |number| hashes[number] = try harness.mine(number - 1, 2 * number);
    for (1..4) |index| {
        try harness.serve(&hashes, index);
        try harness.rebuild(hashes[index]);
    }
    try testing.expectEqual(@as(u32, 3), harness.host.witness_hints);
}

test "executor: a missing preimage fails the build instead of a wrong root" {
    const harness = try Harness.create();
    defer harness.destroy();
    const genesis = harness.node.chain.head_hash();
    const first = try harness.mine(0, 2);
    // Serve headers only: the parent state's root node is missing.
    try harness.host.put_header(harness.node.chain.header(genesis).?);
    const stored = harness.node.chain.record(first).?;
    const parent = harness.node.chain.header(genesis).?;
    var attributes = fixture.attributes_l2(stored.header.timestamp, 0xfe);
    attributes.no_tx_pool = true;
    const result = harness.builder.build_block(&parent, genesis, &attributes);
    try testing.expectError(error.StateUnavailable, result);
}

test "executor: output root from parts" {
    const zero: Hash = @splat(0);
    var preimage_bytes: [128]u8 = @splat(0);
    preimage_bytes[127] = 1;
    var block_hash = zero;
    block_hash[31] = 1;
    const expected = primitives.keccak256(&preimage_bytes).bytes;
    const actual = builder_module.output_root_from_parts(zero, zero, block_hash);
    try testing.expectEqualSlices(u8, &expected, &actual);
}

test "executor: Denim children may share their parent's second" {
    const harness = try Harness.create();
    defer harness.destroy();
    const genesis = harness.node.chain.head_hash();
    const parent = harness.node.chain.header(genesis).?;
    try harness.host.put_header(parent);
    var attributes = fixture.attributes_l2(parent.timestamp, 0xfe);
    attributes.no_tx_pool = true;
    const before = harness.builder.build_block(&parent, genesis, &attributes);
    try testing.expectError(error.InvalidAttributes, before);
    // With Denim active the same-second child passes the timestamp check and goes on to
    // need the parent state, which this test leaves unserved.
    var denim = spec.*;
    for (&denim.upgrades) |*activation| {
        if (activation.* != null) activation.* = 0;
    }
    denim.upgrades[@backingInt(chainspec.Upgrade.denim)] = 0;
    harness.builder.spec = &denim;
    const after = harness.builder.build_block(&parent, genesis, &attributes);
    try testing.expectError(error.StateUnavailable, after);
}
