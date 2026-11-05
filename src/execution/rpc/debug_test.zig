//! `debug_executionWitness` through the JSON-RPC router on a fixture node: each block's
//! witness is decoded from the response, loaded into a `SparseState`, and the block is
//! re-executed statelessly with the node's executor over `SparseState.database()`; the
//! post root must equal the header's. The head and its state are unchanged by the call.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const fixture = @import("../node/test_fixture.zig");
const node_module = @import("../node/root.zig");
const db_module = @import("../db/root.zig");
const payload = @import("../payload/root.zig");
const eth = @import("eth.zig");
const debug = @import("debug.zig");
const engine_types = @import("../engine/root.zig").types;

const chain_module = node_module.chain;
const Hash = [32]u8;
const request_prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"";

const sparse_config: db_module.witness.SparseState.Config = .{
    .nodes_max = 1024,
    .node_bytes_max = 1 << 18,
    .codes_max = 16,
    .code_bytes_max = 1 << 16,
    .headers_max = 16,
    .trie_nodes_max = 4096,
    .storage_tries_max = 32,
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
    .changeset = .{
        .accounts_max = 256,
        .storage_max = 1024,
        .codes_max = 64,
        .code_bytes_max = 1 << 16,
    },
    .depth_max = 8,
};

const Harness = struct {
    node: *fixture.Node,
    api: eth.Api,
    generator: db_module.witness_block.Generator,
    sparse: db_module.witness.SparseState,
    changeset: db_module.Changeset,
    scratch: [1 << 16]u8 = undefined,
    out: [1 << 20]u8 = undefined,
    item: [1 << 16]u8 = undefined,

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
        harness.sparse = try db_module.witness.SparseState.init(allocator, sparse_config);
        errdefer harness.sparse.deinit(allocator);
        harness.changeset = try db_module.Changeset.init(allocator, generator_config.changeset);
        harness.api = .{
            .spec = fixture.spec,
            .chain = &harness.node.chain,
            .pool = &harness.node.pool,
            .scratch = &harness.scratch,
            .witness = &harness.generator,
        };
        return harness;
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
        harness.changeset.deinit(allocator);
        harness.sparse.deinit(allocator);
        harness.generator.deinit(allocator);
        harness.node.destroy();
        allocator.destroy(harness);
    }

    fn request(harness: *Harness, comptime params: []const u8) ![]const u8 {
        return harness.request_into(params, &harness.out);
    }

    /// As `request`, with the response limited to `buffer` (an HTTP send buffer).
    fn request_into(harness: *Harness, comptime params: []const u8, buffer: []u8) ![]const u8 {
        const body = request_prefix ++ "debug_executionWitness\",\"params\":" ++ params ++ "}";
        var out: std.Io.Writer = .fixed(buffer);
        _ = eth.Router.handle(&harness.api, body, &out);
        const text = out.buffered();
        try json.validate(text);
        return text;
    }

    /// Two transfers, then one block on the head made canonical.
    fn mine(harness: *Harness, nonce: u64, timestamp: u64) !Hash {
        const node = harness.node;
        var buffers: [2][256]u8 = undefined;
        try fixture.submit(node, 1, nonce, 1000 + nonce, &buffers[0]);
        try fixture.submit(node, 2, nonce, 7, &buffers[1]);
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, timestamp, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, timestamp);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        return hash.bytes;
    }

    /// Loads one hex array of the `result` into the sparse state.
    fn load(harness: *Harness, text: []const u8, comptime name: []const u8) !u32 {
        const raw = (try json.find_path(text, &.{ "result", name })).?;
        var scanner = json.Scanner.init(raw);
        try testing.expectEqual(json.TokenTag.array_begin, (try scanner.next()).tag);
        var count: u32 = 0;
        while (count <= raw.len) : (count += 1) {
            const token = try scanner.next();
            if (token.tag == .array_end) return count;
            const bytes = try json.parse_data(token.bytes, &harness.item);
            const sparse = &harness.sparse;
            if (comptime std.mem.eql(u8, name, "state")) try sparse.add_node(bytes);
            if (comptime std.mem.eql(u8, name, "codes")) try sparse.add_code(bytes);
            if (comptime std.mem.eql(u8, name, "headers")) try sparse.add_header(bytes);
        }
        unreachable; // Each array item consumes input bytes.
    }

    /// Re-executes `hash` with the node's executor over the witness alone.
    fn reexecute(harness: *Harness, hash: Hash) !Hash {
        const node = harness.node;
        var stored = node.chain.record(hash).?;
        var transactions: [64][]const u8 = undefined;
        var count: usize = 0;
        while (!stored.transactions.is_empty()) : (count += 1) {
            transactions[count] = try stored.transactions.bytes();
        }
        var withdrawals_buffer: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
        const withdrawals = if (stored.withdrawals) |list|
            chain_module.convert_withdrawals(list, &withdrawals_buffer)
        else
            null;
        const env = chain_module.env_of(&stored.header);
        const executor = &node.executor;
        executor.state.reset(harness.sparse.database());
        defer {
            executor.abort_block();
            executor.state.reset(node.db.database());
        }
        try executor.execute_uncommitted(&env, transactions[0..count], withdrawals);
        try testing.expect(!harness.sparse.incomplete);
        try harness.sparse.apply_evm(executor.state, &harness.changeset);
        try testing.expect(!harness.sparse.incomplete);
        return harness.sparse.state_root();
    }
};

test "debug_executionWitness: stateless re-execution of each block matches its root" {
    const harness = try Harness.create();
    defer harness.destroy();
    var hashes: [4]Hash = undefined;
    hashes[0] = harness.node.chain.head_hash();
    for (1..4) |number| hashes[number] = try harness.mine(number - 1, 12 * number);

    const chain = &harness.node.chain;
    const head = chain.head_hash();
    const head_root = try harness.node.db.root();
    inline for (.{ "0x1", "0x2", "0x3" }, 1..) |param, number| {
        const text = try harness.request("[\"" ++ param ++ "\"]");
        const parent = chain.header(hashes[number - 1]).?;
        harness.sparse.reset(parent.state_root.bytes);
        try testing.expect(try harness.load(text, "state") > 0);
        _ = try harness.load(text, "codes");
        try testing.expect(try harness.load(text, "headers") >= 1);
        try testing.expect((try json.find_path(text, &.{ "result", "keys" })) != null);
        const root = try harness.reexecute(hashes[number]);
        try testing.expectEqual(chain.header(hashes[number]).?.state_root.bytes, root);
        try testing.expectEqual(head, chain.head_hash());
        try testing.expectEqual(head_root, try harness.node.db.root());
    }

    // Genesis and unknown blocks are refused without moving the head.
    const refused = try harness.request("[\"0x0\"]");
    try testing.expect(std.mem.indexOf(u8, refused, "BlockUnavailable") != null);
    const unknown = try harness.request("[\"0x9\"]");
    try testing.expect(std.mem.indexOf(u8, unknown, "block not found") != null);
    try testing.expectEqual(head_root, try harness.node.db.root());

    // The head's own witness still works after the refusals (state intact).
    const text = try harness.request("[\"latest\"]");
    harness.sparse.reset(chain.header(hashes[2]).?.state_root.bytes);
    _ = try harness.load(text, "state");
    _ = try harness.load(text, "codes");
    _ = try harness.load(text, "headers");
    const head_header = chain.header(hashes[3]).?;
    try testing.expectEqual(head_header.state_root.bytes, try harness.reexecute(hashes[3]));
}

test "debug_executionWitness: a witness over the response bound fails cleanly" {
    const harness = try Harness.create();
    defer harness.destroy();
    _ = try harness.mine(0, 12);
    const head_root = try harness.node.db.root();
    const text = try harness.request("[\"0x1\"]");
    const result = (try json.find_path(text, &.{"result"})).?;
    const length = debug.witness_json_length(&harness.generator.witness);
    try testing.expectEqual(@as(u64, result.len), length);

    // The configured bound: one byte short fails, the exact length passes.
    harness.generator.response_bytes_max = @intCast(length - 1);
    const refused = try harness.request("[\"0x1\"]");
    try testing.expect(std.mem.indexOf(u8, refused, "\"code\":-32000") != null);
    try testing.expect(std.mem.indexOf(u8, refused, debug.witness_too_large) != null);
    try testing.expectEqual(head_root, try harness.node.db.root());
    harness.generator.response_bytes_max = @intCast(length);
    try testing.expectEqualStrings(text, try harness.request("[\"0x1\"]"));

    // The response buffer: the full response must fit with one byte to spare.
    const fitting = try harness.request_into("[\"0x1\"]", harness.out[0 .. text.len + 1]);
    try testing.expectEqualStrings(text, fitting);
    const small = try harness.request_into("[\"0x1\"]", harness.out[0..text.len]);
    try testing.expect(std.mem.indexOf(u8, small, debug.witness_too_large) != null);

    // Output buffers too small for the witness report the same error.
    harness.generator.witness.state.bytes.len = 1;
    const full = harness.request("[\"0x1\"]");
    harness.generator.witness.state.bytes.len = generator_config.witness.state_bytes_max;
    try testing.expect(std.mem.indexOf(u8, try full, debug.witness_too_large) != null);
    try testing.expectEqual(head_root, try harness.node.db.root());
}
