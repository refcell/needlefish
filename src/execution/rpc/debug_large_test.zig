//! `debug_executionWitness` for a real block whose witness JSON is over 1 MiB, served over
//! the HTTP server on SimIo with the node's 1 MiB connection send buffer and a shared large
//! send buffer. The client decodes the response, loads a `SparseState` bound to the block's
//! parent, re-executes the block statelessly with the node's executor, and checks the root
//! against the header. Without a free large buffer big enough (pool disabled, too small, or
//! busy with another witness) the same request fails with -32000 "witness too large".
//!
//! Block shape: the cheapest way past 1 MiB of hex in Debug is contract code. The genesis
//! holds `contracts_count` contracts of `code_bytes` (the EIP-170 limit) each, distinct by a
//! per-contract padding; the block has one call per contract from distinct senders, and each
//! call writes one slot (`SSTORE(0, 1)`), so the witness carries every code (2 hex chars per
//! byte: 24 x 24 KiB = 1.18 MB of JSON) plus the account and storage proofs. A storage-heavy
//! block (thousands of slots over a large pre-state) needs far more state and runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const txpool = @import("../txpool/root.zig");
const payload = @import("../payload/root.zig");
const fixture = @import("../node/test_fixture.zig");
const node_module = @import("../node/root.zig");
const db_module = @import("../db/root.zig");
const eth = @import("eth.zig");
const debug = @import("debug.zig");
const engine_types = @import("../engine/root.zig").types;

const chain_module = node_module.chain;
const Hash = [32]u8;
const SparseState = db_module.witness.SparseState;

const contracts_count = 24;
/// EIP-170 maximum code size.
const code_bytes = 24 * 1024;
const call_gas_limit: u64 = 100_000;
/// The node's default connection send buffer (`node.service`): the path before large
/// send buffers existed.
const send_buffer_size = 1 << 20;
const large_send_buffer_size = 2 << 20;
const body_size_max = large_send_buffer_size;
const code_store_bytes = 1 << 20;

comptime {
    assert(contracts_count * code_bytes * 2 > send_buffer_size);
    assert(contracts_count * code_bytes * 2 < large_send_buffer_size - (64 << 10));
    assert(contracts_count * code_bytes < code_store_bytes);
}

const state_config: node_module.state_db.Config = blk: {
    var config = fixture.Node.state_config;
    config.code_bytes_max = code_store_bytes;
    break :blk config;
};

const sparse_config: SparseState.Config = .{
    .nodes_max = 1024,
    .node_bytes_max = 1 << 18,
    .codes_max = 2 * contracts_count,
    .code_bytes_max = code_store_bytes,
    .headers_max = 16,
    .trie_nodes_max = 4096,
    .storage_tries_max = 2 * contracts_count,
};

const generator_config: db_module.witness_block.Config = .{
    .builder = .{ .sparse = sparse_config, .keys = .{
        .accounts_max = 128,
        .slots_max = 256,
        .codes_max = 2 * contracts_count,
        .block_numbers_max = 16,
    } },
    .witness = .{
        .state_nodes_max = 1024,
        .state_bytes_max = 1 << 18,
        .codes_max = 2 * contracts_count,
        .code_bytes_max = code_store_bytes,
        .keys_max = 128 + 256,
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

fn sender_key(index: u32) [32]u8 {
    assert(index < contracts_count);
    return fixture.key(@intCast(index + 1));
}

fn contract_address(index: u32) primitives.Address {
    assert(index < contracts_count);
    var address: primitives.Address = .{ .bytes = @splat(0xc0) };
    address.bytes[19] = @intCast(index);
    return address;
}

/// `SSTORE(0, 1); STOP`, padded to `code_bytes` with a per-contract byte (distinct hashes).
fn contract_code(index: u32, code: *[code_bytes]u8) void {
    assert(index < contracts_count);
    const prefix = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 };
    @memcpy(code[0..prefix.len], &prefix);
    @memset(code[prefix.len..], @intCast(index + 1));
    assert(code[code_bytes - 1] != 0);
}

/// A dev node like `fixture.Node.create`, with a code store holding the contracts and the
/// genesis funding one sender per contract.
fn create_node() !*fixture.Node {
    const allocator = testing.allocator;
    const node = try allocator.create(fixture.Node);
    errdefer allocator.destroy(node);
    node.spec = fixture.spec;
    node.db = try node_module.StateDb.init(allocator, state_config);
    errdefer node.db.deinit(allocator);
    var code: [code_bytes]u8 = undefined;
    var index: u32 = 0;
    while (index < contracts_count) : (index += 1) {
        const sender = consensus.signature.address_from_private(sender_key(index)).?;
        try node.db.put_account(sender.bytes, fixture.eth, 0, &.{});
        contract_code(index, &code);
        try node.db.put_account(contract_address(index).bytes, 0, 1, &code);
    }
    node.executor = try node_module.Executor.init(allocator, fixture.spec, &node.db, .{
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
    });
    errdefer node.executor.deinit(allocator);
    node.pool = try txpool.Pool.init(allocator, .{});
    errdefer node.pool.deinit(allocator);
    const genesis = fixture.genesis_header(try node.db.root());
    const executor = &node.executor;
    node.chain = try fixture.Chain.init(allocator, fixture.spec, &node.db, executor, &genesis, .{
        .store = .{ .blocks_max = 16, .bytes_max = 1 << 20 },
        .staging_bytes = 1 << 18,
        .select_max = 64,
        .build_bytes = 1 << 16,
    });
    node.chain.pool = &node.pool;
    node.engine = fixture.Engine.init(fixture.spec, &node.chain);
    return node;
}

/// Pools a call from sender `index` to contract `index`.
fn submit_call(node: *fixture.Node, index: u32, buffer: []u8) !void {
    const tx: consensus.Eip1559 = .{
        .chain_id = node.spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = call_gas_limit,
        .to = .{ .call = contract_address(index) },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, sender_key(index));
    const raw = envelope.encode_to(buffer);
    const sender = consensus.signature.address_from_private(sender_key(index)).?;
    const account = node.db.get_account(sender.bytes).?;
    assert(account.nonce == 0);
    _ = try node.pool.add(.{
        .hash = envelope.hash(),
        .sender = sender,
        .nonce = 0,
        .tx_type = 2,
        .gas_limit = tx.gas_limit,
        .max_fee_per_gas = tx.max_fee_per_gas,
        .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
        .value = 0,
        .raw = raw,
    }, .{ .nonce = account.nonce, .balance = account.balance });
}

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
        assert(answer.done);
        return answer.body[0..answer.size];
    }
};

const witness_request =
    \\{"jsonrpc":"2.0","id":1,"method":"debug_executionWitness","params":["0x1"]}
;

const Harness = struct {
    node: *fixture.Node,
    api: eth.Api,
    generator: db_module.witness_block.Generator,
    sparse: SparseState,
    changeset: db_module.Changeset,
    scratch: [1 << 16]u8 = undefined,
    item: [1 << 16]u8 = undefined,
    answers: [2]Answer = .{ .{}, .{} },
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    server: Server,
    clients: [2]Client,
    block_hash: Hash,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        harness.* = .{
            .node = undefined,
            .api = undefined,
            .generator = undefined,
            .sparse = undefined,
            .changeset = undefined,
            .world = undefined,
            .server_io = undefined,
            .client_io = undefined,
            .server = undefined,
            .clients = undefined,
            .block_hash = undefined,
        };
        harness.node = try create_node();
        errdefer harness.node.destroy();
        const state = harness.node.db.state;
        harness.generator =
            try db_module.witness_block.Generator.init(allocator, state, generator_config);
        errdefer harness.generator.deinit(allocator);
        harness.sparse = try SparseState.init(allocator, sparse_config);
        errdefer harness.sparse.deinit(allocator);
        harness.changeset = try db_module.Changeset.init(allocator, generator_config.changeset);
        errdefer harness.changeset.deinit(allocator);
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
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 61 });
        errdefer harness.world.deinit();
        const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{ .host = server_host });
        errdefer harness.server_io.deinit();
        const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
        try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{ .host = client_host });
        errdefer harness.client_io.deinit();
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
        const limits: http.Limits = .{ .head_size_max = 1024, .body_size_max = body_size_max };
        const client_options: http.client.Options = .{
            .send_buffer_size = 4096,
            .recv_buffer_size = body_size_max + 4096,
            .limits = limits,
        };
        harness.clients[0] = try Client.init(allocator, &harness.client_io, bound, client_options);
        errdefer harness.clients[0].deinit();
        harness.clients[1] = try Client.init(allocator, &harness.client_io, bound, client_options);
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
        for (&harness.clients) |*client| client.deinit();
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
        harness.changeset.deinit(allocator);
        harness.sparse.deinit(allocator);
        harness.generator.deinit(allocator);
        harness.node.destroy();
        allocator.destroy(harness);
    }

    /// One call per contract, then one block on genesis made canonical.
    fn mine(harness: *Harness) !void {
        const node = harness.node;
        var buffers: [contracts_count][256]u8 = undefined;
        var index: u32 = 0;
        while (index < contracts_count) : (index += 1) {
            try submit_call(node, index, &buffers[index]);
        }
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, 12, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, 12);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        try testing.expectEqual(hash.bytes, node.chain.head_hash());
        var record = node.chain.record(hash.bytes).?;
        var count: u32 = 0;
        while (!record.transactions.is_empty()) : (count += 1) {
            _ = try record.transactions.bytes();
        }
        try testing.expectEqual(@as(u32, contracts_count), count);
        harness.block_hash = hash.bytes;
    }

    /// Sends `witness_request` on `count` clients at once; returns once all answered.
    fn post(harness: *Harness, count: u32) !void {
        assert(count >= 1 and count <= harness.clients.len);
        const headers = [_]http.parser.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        for (harness.clients[0..count], harness.answers[0..count]) |*client, *answer| {
            answer.* = .{};
            const body = witness_request;
            try client.request(*Answer, answer, Answer.on_response, .POST, "/", &headers, body);
        }
        harness.world.run_for_ns(4 * std.time.ns_per_s);
        for (harness.answers[0..count]) |*answer| {
            try testing.expect(answer.done);
            try testing.expectEqual(@as(u16, 200), answer.status);
            try json.validate(answer.text());
        }
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

    /// Re-executes the mined block with the node's executor over the witness alone.
    fn reexecute(harness: *Harness) !Hash {
        const node = harness.node;
        var stored = node.chain.record(harness.block_hash).?;
        var transactions: [contracts_count][]const u8 = undefined;
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

    fn expect_released(harness: *Harness) !void {
        for (harness.server.connections) |*connection| {
            try testing.expect(connection.large_index == null);
        }
    }
};

fn expect_too_large(text: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, text, "\"code\":-32000") != null);
    try testing.expect(std.mem.indexOf(u8, text, debug.witness_too_large) != null);
}

test "debug_executionWitness over HTTP: a real witness over 1 MiB re-executes statelessly" {
    const harness = try Harness.create();
    defer harness.destroy();
    try harness.mine();
    const head_root = try harness.node.db.root();

    try harness.post(1);
    const text = harness.answers[0].text();
    const length = debug.witness_json_length(&harness.generator.witness);
    try testing.expect(length > send_buffer_size);
    const result = (try json.find_path(text, &.{"result"})).?;
    try testing.expectEqual(length, @as(u64, result.len));
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    try harness.expect_released();

    const chain = &harness.node.chain;
    const header = chain.header(harness.block_hash).?;
    const parent_hash = header.parent_hash.bytes;
    const parent = chain.header(parent_hash).?;
    harness.sparse.reset(parent.state_root.bytes, .{ .number = 0, .hash = parent_hash });
    try testing.expect(try harness.load(text, "state") > 0);
    try testing.expectEqual(@as(u32, contracts_count), try harness.load(text, "codes"));
    try testing.expect(try harness.load(text, "headers") >= 1);
    try harness.sparse.verify_headers();
    try testing.expectEqual(header.state_root.bytes, try harness.reexecute());
    try testing.expectEqual(head_root, try harness.node.db.root());
    try testing.expectEqual(harness.block_hash, chain.head_hash());
}

test "debug_executionWitness over HTTP: a real witness over 1 MiB without a large buffer" {
    const harness = try Harness.create();
    defer harness.destroy();
    try harness.mine();
    try harness.post(1);
    const expected_length = harness.answers[0].size;
    const length = debug.witness_json_length(&harness.generator.witness);
    try testing.expect(length > send_buffer_size);
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);

    // The 1 MiB path (no large buffers): refused from the connection's own buffer.
    harness.server.options.large_send_buffers_max = 0;
    try harness.post(1);
    try expect_too_large(harness.answers[0].text());
    harness.server.options.large_send_buffers_max = 1;

    // A large buffer too small for the response: the same error.
    harness.server.options.large_send_buffer_size = @intCast(length);
    try harness.post(1);
    try expect_too_large(harness.answers[0].text());
    harness.server.options.large_send_buffer_size = large_send_buffer_size;
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);

    // Two witnesses at once with one large buffer: one served, one refused while busy.
    try harness.post(2);
    var served: u32 = 0;
    var refused: u32 = 0;
    for (&harness.answers) |*answer| {
        if (answer.size == expected_length) served += 1;
        if (std.mem.indexOf(u8, answer.text(), debug.witness_too_large) != null) refused += 1;
    }
    try testing.expectEqual(@as(u32, 1), served);
    try testing.expectEqual(@as(u32, 1), refused);
    try testing.expectEqual(@as(u64, 2), harness.server.responses_grown);
    try harness.expect_released();

    // Released after the send: the next witness is served again.
    try harness.post(1);
    try testing.expectEqual(expected_length, harness.answers[0].size);
    try testing.expectEqual(@as(u64, 3), harness.server.responses_grown);
}
