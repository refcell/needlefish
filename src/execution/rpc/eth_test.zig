//! eth namespace tests through the JSON-RPC router on a fixture node: values, blocks,
//! receipts, raw transaction submission, calls, gas estimation, logs, and a fuzz of
//! arbitrary request bodies (never crash, always valid JSON).

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const txpool = @import("../txpool/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const trie_proof = @import("../trie/proof.zig");
const fixture = @import("../node/test_fixture.zig");
const filters_module = @import("filters.zig");
const eth_config = @import("eth_config.zig");
const chainspec = @import("../chainspec/root.zig");
const history_module = @import("../db/history.zig");
const eth = @import("eth.zig");
const send_sync = @import("send_sync.zig");
const chain_module = @import("../node/chain.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const engine_types = @import("../engine/root.zig").types;
const request_prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"";
const request_prefix_format = "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"";
const address_one = "\"0x0000000000000000000000000000000000000001\"";
const address_target = "\"0x1111111111111111111111111111111111111111\"";

const Harness = struct {
    node: *fixture.Node,
    api: eth.Api,
    filters: filters_module.Filters = .{},
    scratch: [1 << 18]u8 = undefined,
    out: [1 << 16]u8 = undefined,

    fn create() !*Harness {
        return create_for(fixture.spec);
    }

    fn create_for(spec: *const chainspec.ChainSpec) !*Harness {
        return create_numbered(spec, 0);
    }

    /// A harness whose genesis block has `genesis_number`.
    fn create_numbered(spec: *const chainspec.ChainSpec, genesis_number: u64) !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try fixture.Node.create_numbered(spec, null, genesis_number);
        harness.api = .{
            .spec = spec,
            .chain = &harness.node.chain,
            .pool = &harness.node.pool,
            .scratch = &harness.scratch,
        };
        harness.filters = .{};
        harness.api.filters = &harness.filters;
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.node.destroy();
        testing.allocator.destroy(harness);
    }

    /// Routes a request body built at runtime and returns the whole response.
    fn request_runtime(harness: *Harness, body: []const u8) ![]const u8 {
        var out: std.Io.Writer = .fixed(&harness.out);
        _ = eth.Router.handle(&harness.api, body, &out);
        try json.validate(out.buffered());
        return out.buffered();
    }

    /// Routes one request and returns the `result` (or `error`) JSON text.
    fn request(
        harness: *Harness,
        comptime method: []const u8,
        comptime params: []const u8,
    ) ![]const u8 {
        const body = request_prefix ++ method ++ "\",\"params\":" ++ params ++ "}";
        var out: std.Io.Writer = .fixed(&harness.out);
        _ = eth.Router.handle(&harness.api, body, &out);
        const text = out.buffered();
        try json.validate(text);
        const prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,";
        try testing.expect(std.mem.startsWith(u8, text, prefix));
        return text[prefix.len .. text.len - 1];
    }

    /// Builds one block on the head and makes it canonical.
    fn mine(harness: *Harness, timestamp: u64) !primitives.B256 {
        const node = harness.node;
        const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
        const hash = try fixture.build(node, head, timestamp, 0xfe);
        const version = engine_types.forkchoice_version(node.spec, timestamp);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        return hash;
    }
};

/// Expects the request to fail with `code` and a message starting with `message`.
fn expect_failure(
    h: *Harness,
    comptime method: []const u8,
    comptime params: []const u8,
    comptime code: []const u8,
    comptime message: []const u8,
) !void {
    const response = try h.request(method, params);
    try expect_contains(response, "{\"code\":" ++ code ++ ",\"message\":\"" ++ message);
}

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "eth: chain values and head block" {
    const h = try Harness.create();
    defer h.destroy();
    try testing.expectEqualStrings("\"result\":\"0x539\"", try h.request("eth_chainId", "[]"));
    try testing.expectEqualStrings("\"result\":\"1337\"", try h.request("net_version", "[]"));
    try testing.expectEqualStrings("\"result\":\"0x0\"", try h.request("eth_blockNumber", "[]"));
    const block = try h.request("eth_getBlockByNumber", "[\"latest\",false]");
    try expect_contains(block, "\"number\":\"0x0\"");
    try expect_contains(block, "\"baseFeePerGas\":\"0x3b9aca00\"");
    const missing = try h.request("eth_getBlockByNumber", "[\"0x5\",false]");
    try testing.expectEqualStrings("\"result\":null", missing);
    const balance = try h.request("eth_getBalance", "[" ++ address_one ++ ",\"latest\"]");
    try expect_contains(balance, "\"0x0\"");
    const future = try h.request("eth_getBalance", "[" ++ address_one ++ ",\"0x9\"]");
    try expect_contains(future, "error");
}

test "eth: miner_setMaxDASize sets the builder DA limits" {
    const h = try Harness.create();
    defer h.destroy();
    const result = try h.request("miner_setMaxDASize", "[\"0x64\",\"0x3e8\"]");
    try testing.expectEqualStrings("\"result\":true", result);
    try testing.expectEqual(@as(u64, 100), h.node.chain.da_limits.tx_bytes_max);
    try testing.expectEqual(@as(u64, 1000), h.node.chain.da_limits.block_bytes_max);
    try expect_contains(try h.request("miner_setMaxDASize", "[\"0x1\"]"), "error");
    try testing.expectEqual(@as(u64, 1000), h.node.chain.da_limits.block_bytes_max);
}

/// Extracts the hex strings of the JSON array under `name` and decodes each into `out`.
fn proof_nodes(text: []const u8, name: []const u8, storage: [][]u8, out: [][]const u8) !u32 {
    const at = std.mem.indexOf(u8, text, name).?;
    var scanner = json.Scanner.init(text[at + name.len + 1 ..]);
    try testing.expectEqual(json.TokenTag.array_begin, (try scanner.next()).tag);
    var count: u32 = 0;
    while (true) : (count += 1) {
        const token = try scanner.next();
        if (token.tag == .array_end) return count;
        out[count] = try json.parse_data(token.bytes, storage[count]);
    }
}

test "eth: getProof account and storage proofs verify against the state root" {
    const h = try Harness.create();
    defer h.destroy();
    var one: [20]u8 = @splat(0);
    one[19] = 1;
    try h.node.db.put_account(one, 5, 0, &.{});
    try h.node.db.put_storage(one, 7, 0x2a);
    _ = try h.mine(12);
    const head = h.node.chain.header(h.node.chain.head_hash()).?;
    const params = "[" ++ address_one ++ ",[\"0x7\",\"0x08\"],\"latest\"]";
    const text = try h.request("eth_getProof", params);
    try expect_contains(text, "\"value\":\"0x2a\"");
    try expect_contains(text, "\"value\":\"0x0\"");
    var storage: [16][700]u8 = undefined;
    var slices: [16][]u8 = undefined;
    for (&slices, &storage) |*slice, *bytes| slice.* = bytes;
    var nodes: [16][]const u8 = undefined;
    const count = try proof_nodes(text, "\"accountProof\"", &slices, &nodes);
    const address_hash = primitives.keccak256(&one).bytes;
    const proven = try trie_proof.verify(head.state_root.bytes, &address_hash, nodes[0..count]);
    try testing.expect(proven != null);
    const storage_root = h.node.db.trie().storage_root(address_hash);
    try expect_contains(text, "\"storageHash\"");
    var slot: [32]u8 = @splat(0);
    slot[31] = 7;
    const storage_count = try proof_nodes(text, "\"proof\"", &slices, &nodes);
    const slot_hash = primitives.keccak256(&slot).bytes;
    const value = try trie_proof.verify(storage_root, &slot_hash, nodes[0..storage_count]);
    try testing.expectEqualSlices(u8, &.{0x2a}, value.?);
    const not_strings = "[" ++ address_one ++ ",[1],\"latest\"]";
    try expect_contains(try h.request("eth_getProof", not_strings), "error");
    const historical = "[" ++ address_one ++ ",[],\"0x9\"]";
    try expect_contains(try h.request("eth_getProof", historical), "error");
}

test "eth: state reads and getProof at an older block from the history window" {
    const h = try Harness.create();
    defer h.destroy();
    var one: [20]u8 = @splat(0);
    one[19] = 1;
    try h.node.db.put_account(one, 5, 0, &.{});
    try h.node.db.put_storage(one, 7, 0x2a);
    // Returns SLOAD(0): PUSH0 SLOAD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN.
    const reader = [_]u8{ 0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3 };
    var two: [20]u8 = @splat(0);
    two[19] = 0x22;
    try h.node.db.put_account(two, 0, 1, &reader);
    try h.node.db.put_storage(two, 0, 0x11);
    var store = try history_module.Store.init(testing.allocator, .{
        .window_blocks = 8,
        .paths_max = 1 << 12,
        .small_versions_max = 1 << 12,
        .large_versions_max = 1 << 10,
        .prune_per_commit = 256,
    });
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    const first = try h.mine(12);
    try h.node.db.put_account(one, 6, 0, &.{});
    try h.node.db.put_storage(one, 7, 0x2b);
    try h.node.db.put_storage(two, 0, 0x33);
    _ = try h.mine(24);
    const reader_address = "\"0x0000000000000000000000000000000000000022\"";
    const call_old = "[{\"to\":" ++ reader_address ++ "},\"0x1\"]";
    try expect_contains(try h.request("eth_call", call_old), "0011\"");
    const call_new = "[{\"to\":" ++ reader_address ++ "},\"latest\"]";
    try expect_contains(try h.request("eth_call", call_new), "0033\"");
    try expect_contains(try h.request("eth_estimateGas", call_old), "\"result\":\"0x");
    const call_genesis = "[{\"to\":" ++ reader_address ++ "},\"0x0\"]";
    try expect_contains(try h.request("eth_call", call_genesis), "historical state");
    const at_one = "[" ++ address_one ++ ",\"0x1\"]";
    try testing.expectEqualStrings("\"result\":\"0x5\"", try h.request("eth_getBalance", at_one));
    const latest = "[" ++ address_one ++ ",\"latest\"]";
    try testing.expectEqualStrings("\"result\":\"0x6\"", try h.request("eth_getBalance", latest));
    const slot_at_one = "[" ++ address_one ++ ",\"0x7\",\"0x1\"]";
    try expect_contains(try h.request("eth_getStorageAt", slot_at_one), "2a\"");
    const nonce_at_one = "[" ++ address_one ++ ",\"0x1\"]";
    const nonce = try h.request("eth_getTransactionCount", nonce_at_one);
    try testing.expectEqualStrings("\"result\":\"0x0\"", nonce);
    const proof_params = "[" ++ address_one ++ ",[\"0x7\"],\"0x1\"]";
    const text = try h.request("eth_getProof", proof_params);
    try expect_contains(text, "\"balance\":\"0x5\"");
    try expect_contains(text, "\"value\":\"0x2a\"");
    var storage: [16][700]u8 = undefined;
    var slices: [16][]u8 = undefined;
    for (&slices, &storage) |*slice, *bytes| slice.* = bytes;
    var nodes: [16][]const u8 = undefined;
    const count = try proof_nodes(text, "\"accountProof\"", &slices, &nodes);
    const root = h.node.chain.header(first.bytes).?.state_root.bytes;
    const address_hash = primitives.keccak256(&one).bytes;
    try testing.expect(try trie_proof.verify(root, &address_hash, nodes[0..count]) != null);
    // Genesis predates the window's first state (the puts changed it): refused.
    const at_genesis = "[" ++ address_one ++ ",\"0x0\"]";
    try expect_contains(try h.request("eth_getBalance", at_genesis), "historical state");
}

/// Decodes a `"result":"0x..."` response into `out`.
fn result_data(text: []const u8, out: []u8) ![]u8 {
    const prefix = "\"result\":\"";
    try testing.expect(std.mem.startsWith(u8, text, prefix));
    return json.parse_data(text[prefix.len .. text.len - 1], out);
}

test "eth: debug raw header, block, receipts and transaction" {
    const h = try Harness.create();
    defer h.destroy();
    var tx_buffer: [256]u8 = undefined;
    try fixture.submit(h.node, 1, 0, 5, &tx_buffer);
    const hash = try h.mine(12);
    var buffer: [4096]u8 = undefined;
    const header = try result_data(try h.request("debug_getRawHeader", "[\"latest\"]"), &buffer);
    try testing.expectEqualSlices(u8, &hash.bytes, &primitives.keccak256(header).bytes);
    const block_bytes = try result_data(try h.request("debug_getRawBlock", "[\"0x1\"]"), &buffer);
    const block = try consensus.block.Block.decode(block_bytes);
    try testing.expectEqualSlices(u8, &hash.bytes, &block.header.hash().bytes);
    try testing.expectEqual(@as(usize, 1), block.body.transactions.count);
    try testing.expect(block.body.withdrawals != null);
    var record = h.node.chain.record(hash.bytes).?;
    const raw_tx = try record.transactions.bytes();
    const tx_hash = primitives.keccak256(raw_tx).bytes;
    var request_buffer: [256]u8 = undefined;
    const tx_request = try std.fmt.bufPrint(
        &request_buffer,
        request_prefix_format ++ "debug_getRawTransaction\",\"params\":[\"0x{x}\"]}}",
        .{&tx_hash},
    );
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, tx_request, &out);
    try expect_contains(out.buffered(), "0x02");
    const receipts = try h.request("debug_getRawReceipts", "[\"latest\"]");
    try expect_contains(receipts, "[\"0x02");
    try expect_contains(try h.request("debug_getRawBlock", "[\"0x7\"]"), "error");
    const by_hash = try std.fmt.bufPrint(
        &request_buffer,
        request_prefix_format ++ "debug_getRawHeader\",\"params\":[\"0x{x}\"]}}",
        .{&hash.bytes},
    );
    out = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, by_hash, &out);
    try expect_contains(out.buffered(), "\"result\":\"0x");
}

test "eth: block transaction counts, by-index lookups, uncles, sha3, txpool_status" {
    const h = try Harness.create();
    defer h.destroy();
    var tx_buffer: [256]u8 = undefined;
    try fixture.submit(h.node, 1, 0, 5, &tx_buffer);
    const status = try h.request("txpool_status", "[]");
    try testing.expectEqualStrings("\"result\":{\"pending\":\"0x1\",\"queued\":\"0x0\"}", status);
    const hash = try h.mine(12);
    const count = try h.request("eth_getBlockTransactionCountByNumber", "[\"latest\"]");
    try testing.expectEqualStrings("\"result\":\"0x1\"", count);
    const genesis_count = try h.request("eth_getBlockTransactionCountByNumber", "[\"0x0\"]");
    try testing.expectEqualStrings("\"result\":\"0x0\"", genesis_count);
    const missing = try h.request("eth_getBlockTransactionCountByNumber", "[\"0x9\"]");
    try testing.expectEqualStrings("\"result\":null", missing);
    const uncles = try h.request("eth_getUncleCountByBlockNumber", "[\"0x1\"]");
    try testing.expectEqualStrings("\"result\":\"0x0\"", uncles);
    const uncle = try h.request("eth_getUncleByBlockNumberAndIndex", "[\"0x1\",\"0x0\"]");
    try testing.expectEqualStrings("\"result\":null", uncle);
    const tx = try h.request("eth_getTransactionByBlockNumberAndIndex", "[\"0x1\",\"0x0\"]");
    try expect_contains(tx, "\"transactionIndex\":\"0x0\"");
    try expect_contains(tx, "\"blockNumber\":\"0x1\"");
    const past_end = try h.request("eth_getTransactionByBlockNumberAndIndex", "[\"0x1\",\"0x1\"]");
    try testing.expectEqualStrings("\"result\":null", past_end);
    // An unknown block is refused (Nethermind's OP module), whatever the index; the raw
    // form and the uncle answer null.
    const unknown = "[\"0x93fbe6f24bf0038f8fafa5fef96df0ec11c066fdf976ecdc649a1aa820365100\",";
    inline for (.{ "\"0x0\"]", "\"0xffffffffffffffffffffffffffffffd7\"]" }) |index| {
        const params = unknown ++ index;
        const method = "eth_getTransactionByBlockHashAndIndex";
        try expect_failure(h, method, params, "-32000", "header not found");
        inline for (.{
            "eth_getRawTransactionByBlockHashAndIndex",
            "eth_getUncleByBlockHashAndIndex",
        }) |null_method| {
            const answer = try h.request(null_method, params);
            try testing.expectEqualStrings("\"result\":null", answer);
        }
    }
    const beyond = "[\"0x9\",\"0x0\"]";
    const method = "eth_getTransactionByBlockNumberAndIndex";
    try expect_failure(h, method, beyond, "-32000", "header not found");
    var request_buffer: [256]u8 = undefined;
    const by_hash = try std.fmt.bufPrint(
        &request_buffer,
        request_prefix_format ++
            "eth_getTransactionByBlockHashAndIndex\",\"params\":[\"0x{x}\",\"0x0\"]}}",
        .{&hash.bytes},
    );
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, by_hash, &out);
    try expect_contains(out.buffered(), "\"transactionIndex\":\"0x0\"");
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_accounts", "[]"));
    // keccak256("") and keccak256(0x68656c6c6f20776f726c64) ("hello world").
    try expect_contains(
        try h.request("web3_sha3", "[\"0x\"]"),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
    try expect_contains(
        try h.request("web3_sha3", "[\"0x68656c6c6f20776f726c64\"]"),
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
    );
}

const log_contract = "\"0x2222222222222222222222222222222222222222\"";

/// Signs a call to the LOG0 contract and submits it through eth_sendRawTransaction.
fn send_log_call(h: *Harness, nonce: u64) ![32]u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = fixture.spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 60_000,
        .to = .{ .call = .{ .bytes = @splat(0x22) } },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    var raw_buffer: [256]u8 = undefined;
    const raw = envelope.encode_to(&raw_buffer);
    var body_buffer: [800]u8 = undefined;
    const send_format = request_prefix_format ++
        "eth_sendRawTransaction\",\"params\":[\"0x{x}\"]}}";
    const body = try std.fmt.bufPrint(&body_buffer, send_format, .{raw});
    try expect_contains(try h.request_runtime(body), "\"result\":\"0x");
    return envelope.hash().bytes;
}

fn expect_empty(h: *Harness, comptime method: []const u8, comptime params: []const u8) !void {
    try testing.expectEqualStrings("\"result\":[]", try h.request(method, params));
}

test "eth: block, pending and log filters report changes once" {
    const h = try Harness.create();
    defer h.destroy();
    // PUSH1 0 PUSH1 0 LOG0 STOP: one empty log from the contract per call.
    try h.node.db.put_account(@splat(0x22), 0, 0, &.{ 0x60, 0x00, 0x60, 0x00, 0xa0, 0x00 });
    try testing.expectEqualStrings("\"result\":\"0x1\"", try h.request("eth_newBlockFilter", "[]"));
    const pending_id = try h.request("eth_newPendingTransactionFilter", "[]");
    try testing.expectEqualStrings("\"result\":\"0x2\"", pending_id);
    const log_id = try h.request("eth_newFilter", "[{\"address\":" ++ log_contract ++ "}]");
    try testing.expectEqualStrings("\"result\":\"0x3\"", log_id);
    const tx_hash = try send_log_call(h, 0);
    var hex: [70]u8 = undefined;
    const tx_hex = try std.fmt.bufPrint(&hex, "0x{x}", .{&tx_hash});
    try expect_contains(try h.request("eth_getFilterChanges", "[\"0x2\"]"), tx_hex);
    try expect_empty(h, "eth_getFilterChanges", "[\"0x2\"]");
    try expect_empty(h, "eth_getFilterChanges", "[\"0x1\"]");
    const block_hash = try h.mine(12);
    const block_hex = try std.fmt.bufPrint(&hex, "0x{x}", .{&block_hash.bytes});
    try expect_contains(try h.request("eth_getFilterChanges", "[\"0x1\"]"), block_hex);
    try expect_empty(h, "eth_getFilterChanges", "[\"0x1\"]");
    const logs = try h.request("eth_getFilterChanges", "[\"0x3\"]");
    try expect_contains(logs, "\"address\":" ++ log_contract);
    try expect_contains(logs, "\"blockNumber\":\"0x1\"");
    try expect_empty(h, "eth_getFilterChanges", "[\"0x3\"]");
    try expect_contains(try h.request("eth_getFilterLogs", "[\"0x3\"]"), "\"logIndex\":\"0x0\"");
    try expect_contains(try h.request("eth_getFilterLogs", "[\"0x1\"]"), "error");
    // A filter for another address sees nothing.
    const other_params = "[{\"address\":" ++ address_one ++ ",\"fromBlock\":\"0x0\"}]";
    const other = try h.request("eth_newFilter", other_params);
    try testing.expectEqualStrings("\"result\":\"0x4\"", other);
    try expect_empty(h, "eth_getFilterLogs", "[\"0x4\"]");
    const removed = try h.request("eth_uninstallFilter", "[\"0x3\"]");
    try testing.expectEqualStrings("\"result\":true", removed);
    const again = try h.request("eth_uninstallFilter", "[\"0x3\"]");
    try testing.expectEqualStrings("\"result\":false", again);
    try expect_contains(try h.request("eth_getFilterChanges", "[\"0x3\"]"), "filter not found");
}

test "eth: send raw transaction, mine, receipt, logs and nonce" {
    const h = try Harness.create();
    defer h.destroy();
    const tx: consensus.Eip1559 = .{
        .chain_id = fixture.spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 21_000,
        .to = .{ .call = fixture.address_of(9) },
        .value = 77,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    var raw_buffer: [256]u8 = undefined;
    const raw = envelope.encode_to(&raw_buffer);
    var hex_buffer: [600]u8 = undefined;
    const hex = try std.fmt.bufPrint(&hex_buffer, "[\"0x{x}\"]", .{raw});
    var body_buffer: [800]u8 = undefined;
    const send_format = request_prefix_format ++ "eth_sendRawTransaction\",\"params\":{s}}}";
    const body = try std.fmt.bufPrint(&body_buffer, send_format, .{hex});
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, body, &out);
    try expect_contains(out.buffered(), "\"result\":\"0x");
    const sender = fixture.address_of(1);
    var nonce_params: [128]u8 = undefined;
    _ = &nonce_params;
    try testing.expectEqual(@as(u32, 1), h.node.pool.count());
    _ = try h.mine(12);
    try testing.expectEqual(@as(u32, 0), h.node.pool.count());
    try testing.expectEqualStrings("\"result\":\"0x1\"", try h.request("eth_blockNumber", "[]"));
    const tx_hash = envelope.hash();
    var receipt_body: [200]u8 = undefined;
    const receipt_format = request_prefix_format ++
        "eth_getTransactionReceipt\",\"params\":[\"0x{x}\"]}}";
    const receipt_request = try std.fmt.bufPrint(&receipt_body, receipt_format, .{&tx_hash.bytes});
    out = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, receipt_request, &out);
    try json.validate(out.buffered());
    try expect_contains(out.buffered(), "\"status\":\"0x1\"");
    try expect_contains(out.buffered(), "\"gasUsed\":\"0x5208\"");
    _ = sender;
    const full = try h.request("eth_getBlockByNumber", "[\"0x1\",true]");
    try expect_contains(full, "\"value\":\"0x4d\"");
    try expect_contains(full, "\"maxFeePerGas\":\"0x2540be400\"");
    const receipts = try h.request("eth_getBlockReceipts", "[\"latest\"]");
    try expect_contains(receipts, "\"cumulativeGasUsed\":\"0x5208\"");
    const logs = try h.request("eth_getLogs", "[{\"fromBlock\":\"0x0\",\"toBlock\":\"latest\"}]");
    try testing.expectEqualStrings("\"result\":[]", logs);
}

test "eth: eth_createAccessList lists touched accounts and slots beyond the pre-warmed set" {
    const h = try Harness.create();
    defer h.destroy();
    // PUSH1 5 SLOAD POP PUSH1 0x44 BALANCE POP STOP.
    const toucher = [_]u8{ 0x60, 0x05, 0x54, 0x50, 0x60, 0x44, 0x31, 0x50, 0x00 };
    var contract: [20]u8 = @splat(0);
    contract[19] = 0x33;
    try h.node.db.put_account(contract, 0, 1, &toucher);
    // PUSH1 1 SLOAD PUSH0 PUSH0 REVERT.
    const reverter = [_]u8{ 0x60, 0x01, 0x54, 0x5f, 0x5f, 0xfd };
    var failing: [20]u8 = @splat(0);
    failing[19] = 0x35;
    try h.node.db.put_account(failing, 0, 1, &reverter);
    _ = try h.mine(12);
    const call = "[{\"to\":\"0x0000000000000000000000000000000000000033\"}]";
    const text = try h.request("eth_createAccessList", call);
    const zeros_31: [62]u8 = @splat('0');
    const zeros_19: [38]u8 = @splat('0');
    const expected = "\"result\":{\"accessList\":[{\"address\":\"0x" ++ zeros_19 ++
        "33\",\"storageKeys\":[\"0x" ++ zeros_31 ++ "05\"]},{\"address\":\"0x" ++ zeros_19 ++
        "44\",\"storageKeys\":[]}],\"gasUsed\":\"0x6d06\"}";
    try testing.expectEqualStrings(expected, text);
    // Plain transfers touch nothing beyond the pre-warmed set.
    const plain = try h.request("eth_createAccessList", "[{\"to\":" ++ address_target ++ "}]");
    try testing.expectEqualStrings("\"result\":{\"accessList\":[],\"gasUsed\":\"0x5208\"}", plain);
    const revert_call = "[{\"to\":\"0x0000000000000000000000000000000000000035\"},\"latest\"]";
    const reverted = try h.request("eth_createAccessList", revert_call);
    try expect_contains(reverted, "\"error\":\"execution reverted\"}");
    try expect_contains(try h.request("eth_createAccessList", "[{\"to\":1}]"), "error");
}

var everest_spec: chainspec.ChainSpec = chainspec.ChainSpec.presets.base_devnet;

const Eip8130Built = struct {
    sender_auth: [65]u8,
    phase_buffer: [256]u8,
    calls_buffer: [512]u8,
    envelope_buffer: [1024]u8,

    fn build(built: *Eip8130Built, nonce_key: u256, sequence: u64) ![]const u8 {
        const eip8130 = consensus.tx.eip8130;
        const target: primitives.Address = .{ .bytes = @splat(0x44) };
        const calls = [_]eip8130.Call{.{ .to = target, .value = 0, .data = &.{} }};
        const phase = eip8130.Phase.build(&built.phase_buffer, &calls);
        var tx: eip8130.TxEip8130 = .{
            .chain_id = everest_spec.chain_id,
            .nonce_key = nonce_key,
            .nonce_sequence = sequence,
            .gas_limit = 300_000,
            .max_fee_per_gas = 10_000_000_000,
            .max_priority_fee_per_gas = 2,
        };
        tx.calls = eip8130.Calls.build(&built.calls_buffer, &.{phase});
        built.sender_auth = try eip8130.sign_sender(tx, fixture.key(1));
        const signed: eip8130.Signed = .{ .tx = tx, .sender_auth = &built.sender_auth };
        return signed.encode_to(&built.envelope_buffer);
    }
};

fn send_raw(h: *Harness, raw: []const u8) ![]const u8 {
    var body: [4096]u8 = undefined;
    const format = request_prefix_format ++ "eth_sendRawTransaction\",\"params\":[\"0x{x}\"]}}";
    const request = try std.fmt.bufPrint(&body, format, .{raw});
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, request, &out);
    try json.validate(out.buffered());
    return out.buffered();
}

test "eth: EIP-8130 transactions pool by nonce channel and are mined in order" {
    everest_spec.upgrades = @splat(0);
    const h = try Harness.create_for(&everest_spec);
    defer h.destroy();
    var built: [3]Eip8130Built = undefined;
    const first = try built[0].build(7, 0);
    const second = try built[1].build(7, 1);
    const gap = try built[2].build(9, 3);
    try expect_contains(try send_raw(h, second), "\"result\":\"0x");
    try expect_contains(try send_raw(h, first), "\"result\":\"0x");
    try expect_contains(try send_raw(h, gap), "\"result\":\"0x");
    try testing.expectEqual(@as(u32, 2), h.node.pool.pending_count);
    try testing.expectEqual(@as(u32, 1), h.node.pool.queued_count);
    const block = try h.mine(12);
    const stored = h.node.chain.header(block.bytes).?;
    try testing.expect(stored.gas_used > 0);
    // Both channel-7 transactions are in; the gapped channel-9 one stays queued.
    try testing.expectEqual(@as(u32, 0), h.node.pool.pending_count);
    try testing.expectEqual(@as(u32, 1), h.node.pool.queued_count);
    const sender = fixture.address_of(1);
    const lane: txpool.eip8130.Lane = .{
        .address = sender,
        .sender = sender,
        .payer = sender,
        .nonce_key = 7,
    };
    try testing.expectEqual(@as(u64, 2), h.node.chain.lane_account(lane).nonce);
    const receipts = try h.request("eth_getBlockReceipts", "[\"latest\"]");
    try testing.expectEqual(@as(usize, 2), count_of(receipts, "\"type\":\"0x79\""));
    try testing.expectEqual(@as(usize, 2), count_of(receipts, "\"status\":\"0x1\""));
    // A replay of a mined sequence is refused by the pool.
    try expect_contains(try send_raw(h, first), "error");
}

/// slot0 += 1, LOG0 and return the new value.
const counter_hex = "0x5f5460010180" ++ "5f555f5260205fa060205ff3";
const counter_at = "\"0x0000000000000000000000000000000000000055\"";
const reverter_at = "\"0x0000000000000000000000000000000000000056\"";

test "eth: eth_simulateV1 carries state across calls and blocks with overrides" {
    const h = try Harness.create();
    defer h.destroy();
    const head_root = try h.node.db.root();
    const word = "0x000000000000000000000000000000000000000000000000000000000000000";
    const counter_call = "{\"to\":" ++ counter_at ++ "}";
    const params = "[{\"blockStateCalls\":[" ++
        "{\"stateOverrides\":{" ++ counter_at ++ ":{\"code\":\"" ++ counter_hex ++ "\"}," ++
        reverter_at ++ ":{\"code\":\"0x5f5ffd\"}}," ++
        "\"calls\":[" ++ counter_call ++ "," ++ counter_call ++ ",{\"to\":" ++ reverter_at ++
        "}]}," ++
        "{\"blockOverrides\":{\"time\":\"0x1000\"},\"stateOverrides\":{" ++ counter_at ++
        ":{\"stateDiff\":{\"" ++ word ++ "0\":\"0x" ++ "000000000000000000000000000000" ++
        "000000000000000000000000000000000a\"}}},\"calls\":[" ++ counter_call ++ "]}," ++
        "{\"stateOverrides\":{" ++ counter_at ++ ":{\"state\":{}}},\"calls\":[" ++ counter_call ++
        "]}" ++
        "]},\"latest\"]";
    const text = try h.request("eth_simulateV1", params);
    try expect_contains(text, "\"returnData\":\"" ++ word ++ "1\"");
    try expect_contains(text, "\"returnData\":\"" ++ word ++ "2\"");
    try expect_contains(text, "\"returnData\":\"0x" ++ "00000000000000000000000000000000" ++
        "0000000000000000000000000000000b\"");
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"returnData\":\"" ++ word ++ "1\""));
    try expect_contains(text, "\"logIndex\":\"0x1\"");
    // A revert without data still reports it, as Nethermind: "0x".
    try expect_contains(text, "\"error\":{\"code\":3,\"message\":\"execution reverted\"," ++
        "\"data\":\"0x\"}");
    try expect_contains(text, "\"number\":\"0x2\"");
    try expect_contains(text, "\"timestamp\":\"0x1000\"");
    // base/base's default: the chain's schedule, here two seconds after the override.
    try expect_contains(text, "\"number\":\"0x3\"");
    try expect_contains(text, "\"timestamp\":\"0x1002\"");
    // Nothing was committed.
    try testing.expectEqual(head_root, try h.node.db.root());
    try testing.expectEqualStrings("\"result\":\"0x\"", try h.request("eth_getCode", "[" ++
        counter_at ++ ",\"latest\"]"));
}

test "eth: eth_simulateV1 limits and rejections" {
    const h = try Harness.create();
    defer h.destroy();
    const gas = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"gasLimit\":\"0x7530\"}," ++
        "\"calls\":[{\"to\":" ++ address_target ++ ",\"gas\":\"0xc350\"}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", gas), "{\"code\":-38015,\"message\":" ++
        "\"Block gas limit exceeded by the block's transactions\"}");
    // A call the EVM rejects fails the whole request.
    const no_gas = "[{\"blockStateCalls\":[{\"calls\":[{\"gas\":\"0x0\"}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", no_gas), "{\"code\":-38013,\"message\":" ++
        "\"intrinsic gas too low\"}");
    const backwards = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":\"0x0\"}}]}]";
    try expect_failure(h, "eth_simulateV1", backwards, "-38020", "block numbers must be in order");
    // At most 256 blocks past the base block, gap fillers included.
    const too_many = "{\"code\":-38026,\"message\":\"too many blocks\"}";
    const far = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":\"0x1000\"}}]}]";
    try expect_contains(try h.request("eth_simulateV1", far), too_many);
    const max = "\"0xffffffffffffffff\"";
    const last = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":" ++ max ++ "}}]}]";
    try expect_contains(try h.request("eth_simulateV1", last), too_many);
    const many = comptime blk: {
        var text: []const u8 = "[{\"blockStateCalls\":[";
        for (0..256) |_| text = text ++ "{},";
        break :blk text ++ "{}]}]";
    };
    try expect_contains(try h.request("eth_simulateV1", many), too_many);
    // Number gaps fill with empty blocks.
    const gap = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":\"0x3\"}}]}]";
    const filled = try h.request("eth_simulateV1", gap);
    try testing.expectEqual(@as(usize, 3), count_of(filled, "\"miner\""));
    // Before Denim a default timestamp after 2^64 - 1 overflows.
    const late = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"time\":" ++ max ++ "}},{}]}]";
    try expect_contains(try h.request("eth_simulateV1", late), "{\"code\":-38021,\"message\":" ++
        "\"block timestamps must be in order: 18446744073709551615 <= 18446744073709551615\"}");
    // Two blocks overriding the same time: Nethermind refuses the second.
    const same = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"time\":" ++ max ++ "}}," ++
        "{\"blockOverrides\":{\"time\":" ++ max ++ "}}]}]";
    try expect_contains(try h.request("eth_simulateV1", same), "{\"code\":-38021,\"message\":" ++
        "\"Block timestamp out of order 18446744073709551615 is <= than given base " ++
        "timestamp of 18446744073709551615!\"}");
    const validation = "[{\"blockStateCalls\":[],\"validation\":true}]";
    try expect_contains(try h.request("eth_simulateV1", validation), "{\"code\":-32602," ++
        "\"message\":\"calls are empty.\"}");
    // Base fee and blob base fee overrides apply (BASEFEE, BLOBBASEFEE).
    const fees = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"baseFeePerGas\":\"0x7\"," ++
        "\"blobBaseFee\":\"0x9\"},\"stateOverrides\":{" ++ override_target ++
        ":{\"code\":\"0x484a015f5260205ff3\"}},\"calls\":[{\"to\":" ++ override_target ++ "}]}]}]";
    const fee_text = try h.request("eth_simulateV1", fees);
    try expect_contains(fee_text, "\"baseFeePerGas\":\"0x7\"");
    try expect_contains(fee_text, "\"returnData\":\"0x" ++ zeros_62 ++ "10\"");
    // A base fee above 2^64 - 1 stays whole in the header and for BASEFEE, as Nethermind's
    // UInt256 (`Sealed` hashes it whole).
    const wide = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"baseFeePerGas\":" ++
        "\"0x9ed5eb1431d6880000\"},\"stateOverrides\":{" ++ override_target ++
        ":{\"code\":\"0x485f5260205ff3\"}},\"calls\":[{\"to\":" ++ override_target ++ "}]}]}]";
    const wide_text = try h.request("eth_simulateV1", wide);
    try expect_contains(wide_text, "\"baseFeePerGas\":\"0x9ed5eb1431d6880000\"");
    try expect_contains(wide_text, "\"returnData\":\"0x" ++ zeros_62[0..46] ++
        "9ed5eb1431d6880000\"");
    // The largest base fee plus a tip saturates; the effective price is the fee cap (it
    // overflowed and panicked before).
    const word_max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const huge = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"baseFeePerGas\":\"0x" ++
        word_max ++ "\"},\"calls\":[{\"to\":" ++ override_target ++
        ",\"maxFeePerGas\":\"0x" ++ word_max ++ "\",\"maxPriorityFeePerGas\":\"0x" ++
        word_max ++ "\"}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", huge), "\"status\":\"0x1\"");
    try expect_contains(try h.request("eth_simulateV1", "[{}]"), "invalid params");
    // A gas limit above the block's and the RPC gas cap is refused, not run (a looping call
    // without gas would otherwise spin for 2^64 gas).
    const unbounded = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"gasLimit\":" ++ max ++
        "},\"stateOverrides\":{" ++ override_target ++ ":{\"code\":\"0x5b5f56\"}}," ++
        "\"calls\":[{\"to\":" ++ override_target ++ "}]}]}]";
    try expect_failure(h, "eth_simulateV1", unbounded, "-38026", "Client adjustable limit reached");
    // Nethermind checks every block's overrides before it runs any call: a later block's gas
    // limit is refused before an earlier block's incomplete deposit.
    const later = "[{\"blockStateCalls\":[{\"calls\":[{\"type\":\"0x7e\"}]}," ++
        "{\"blockOverrides\":{\"gasLimit\":" ++ max ++ "}}]}]";
    try expect_failure(h, "eth_simulateV1", later, "-38026", "Client adjustable limit reached");
    const tip = "[{\"blockStateCalls\":[{\"calls\":[{\"type\":\"0x7e\"}]},{\"calls\":" ++
        "[{\"maxPriorityFeePerGas\":\"0x2\",\"maxFeePerGas\":\"0x1\"}]}]}]";
    try expect_failure(h, "eth_simulateV1", tip, "-32003", "max priority fee per gas higher");
    // A call for another chain in block 2 is refused before block 3's gas limit and state
    // conflict, and before block 1's out-of-order number (Nethermind).
    const chain = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":\"0x0\"}}," ++
        "{\"calls\":[{\"chainId\":\"0x32ff\"}]},{\"blockOverrides\":{\"gasLimit\":" ++
        max ++ "},\"stateOverrides\":{" ++ override_target ++
        ":{\"state\":{},\"stateDiff\":{}}}}]}]";
    try expect_failure(h, "eth_simulateV1", chain, "-32000", "invalid chain ID");
}

test "eth: eth_simulateV1 refuses an unknown override key" {
    const h = try Harness.create();
    defer h.destroy();
    // Nethermind reads override keys strictly and case-insensitively: an alias such as
    // `baseFee` names no field, in any block, before the block parameter is read.
    const prefix = "[{\"blockStateCalls\":[{},{\"blockOverrides\":";
    const tail = "}]},\"bad\"]";
    const unknown = prefix ++ "{\"baseFee\":\"0x8\"}" ++ tail;
    try expect_failure(h, "eth_simulateV1", unknown, "-32602", "invalid argument 0");
    const twice = prefix ++ "{\"gasLimit\":\"0x8\",\"GasLimit\":\"0x8\"}" ++ tail;
    try expect_failure(h, "eth_simulateV1", twice, "-32602", "invalid argument 0");
    const account = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ override_target ++
        ":{\"storage\":{}}}}]}]";
    try expect_failure(h, "eth_simulateV1", account, "-32602", "invalid argument 0");
    // Any case names the field, and the same spelling twice is one key.
    const cased = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"BASEFEEPERGAS\":\"0x7\"," ++
        "\"Time\":\"0x7fffffff\",\"Time\":\"0x7fffffff\"},\"stateOverrides\":{" ++
        override_target ++ ":{\"Code\":\"0x485f5260205ff3\"}},\"calls\":[{\"to\":" ++
        override_target ++ "}]}]}]";
    const text = try h.request("eth_simulateV1", cased);
    try expect_contains(text, "\"baseFeePerGas\":\"0x7\"");
    try expect_contains(text, "\"timestamp\":\"0x7fffffff\"");
    try expect_contains(text, "\"returnData\":\"0x" ++ zeros_62 ++ "07\"");
}

test "eth: eth_simulateV1 Denim default timestamps repeat at 2^64 - 1" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    const max = "\"0xffffffffffffffff\"";
    const late = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"time\":" ++ max ++ "}},{}]}]";
    const saturated = try h.request("eth_simulateV1", late);
    try testing.expectEqual(@as(usize, 2), count_of(saturated, "\"timestamp\":" ++ max));
    const stalled = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"time\":" ++ max ++ "}}," ++
        "{\"blockOverrides\":{\"time\":" ++ max ++ "}}]}]";
    // An overridden time must still pass the previous block's (Nethermind), Denim or not.
    try expect_failure(h, "eth_simulateV1", stalled, "-38021", "Block timestamp out of order");
}

test "eth: eth_simulateV1 call errors and validation" {
    const h = try Harness.create();
    defer h.destroy();
    const blocks = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ override_target ++
        ":{\"code\":\"" ++ revert_nope_code ++ "\"}},\"calls\":[";
    const reverted = try h.request("eth_simulateV1", blocks ++ "{\"to\":" ++ override_target ++
        "}]}]}]");
    try expect_contains(reverted, "\"returnData\":\"0x\"");
    const reverted_error = "\"error\":{\"code\":3,\"message\":\"execution reverted: nope\"," ++
        "\"data\":\"" ++ revert_nope_data ++ "\"}";
    try expect_contains(reverted, reverted_error);
    const loop = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ override_target ++
        ":{\"code\":\"0x5b5f56\"}},\"calls\":[{\"to\":" ++ override_target ++
        ",\"gas\":\"0x5300\"}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", loop), "\"error\":{\"code\":-32015," ++
        "\"message\":\"out of gas: gas required exceeds: 21248\"}");
    const poor = "[{\"blockStateCalls\":[{\"calls\":[{\"from\":" ++ poor_sender ++
        ",\"to\":" ++ address_target ++ ",\"value\":\"0x1\"}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", poor), "\"gasUsed\":\"0x5208\"," ++
        "\"maxUsedGas\":\"0x5208\",\"status\":\"0x0\",\"error\":{\"code\":-32015," ++
        "\"message\":\"EVM error: OutOfFunds\"}");
    // With validation the fee, nonce and balance checks apply.
    const validated = "[{\"validation\":true,\"blockStateCalls\":[{\"calls\":[{\"from\":" ++
        poor_sender ++ ",\"to\":" ++ address_target;
    const low_fee = "max fee per gas less than block base fee\"}";
    try expect_failure(h, "eth_simulateV1", validated ++ "}]}]}]", "-38012", low_fee);
    const priced = validated ++ ",\"maxFeePerGas\":\"0x10000000000\"";
    const nonce = priced ++ ",\"nonce\":\"0x5\"}]}]}]";
    const funds = "Insufficient funds to pay for gas fees and value for a transaction\"}";
    try expect_failure(h, "eth_simulateV1", priced ++ "}]}]}]", "-38014", funds);
    // As Nethermind, the balance is checked before the nonce.
    try expect_failure(h, "eth_simulateV1", nonce, "-38014", funds);
    const funded = "[{\"validation\":true,\"blockStateCalls\":[{\"stateOverrides\":{" ++
        poor_sender ++ ":{\"balance\":\"0xffffffffffffffffffff\"}},\"calls\":[{\"from\":" ++
        poor_sender ++ ",\"to\":" ++ address_target ++ ",\"maxFeePerGas\":\"0x10000000000\"";
    const funded_nonce = funded ++ ",\"nonce\":\"0x5\"}]}]}]";
    try expect_failure(h, "eth_simulateV1", funded_nonce, "-38011", "nonce too high\"}");
}

test "eth: eth_simulateV1 with validation charges the OP rollup fees" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    // The sender holds exactly gas * price; the operator fee constant (L1Block slot 8) is
    // charged over the call's encoding on top (Nethermind), so the funds fall short.
    const blocks = "[{\"validation\":true,\"blockStateCalls\":[{\"stateOverrides\":{" ++
        poor_sender ++ ":{\"balance\":\"0x52080000000000\"}";
    const operator_fee = ",\"0x4200000000000000000000000000000000000015\":{\"stateDiff\":{" ++
        "\"0x" ++ zeros_62 ++ "08\":\"0x" ++ zeros_62 ++ "ff\"}}";
    const calls = "},\"calls\":[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ address_target ++
        ",\"gas\":\"0x5208\",\"maxFeePerGas\":\"0x10000000000\"}]}]}]";
    const funds = "Insufficient funds to pay for gas fees and value for a transaction\"}";
    try expect_failure(h, "eth_simulateV1", blocks ++ operator_fee ++ calls, "-38014", funds);
    try expect_contains(try h.request("eth_simulateV1", blocks ++ calls), "\"status\":\"0x1\"");
}

test "eth: a sender at the maximum nonce" {
    const h = try Harness.create();
    defer h.destroy();
    const max_sender = "{" ++ poor_sender ++
        ":{\"nonce\":\"0xffffffffffffffff\",\"balance\":\"0xffffffffffffffffffff\"}}";
    // As Nethermind (and geth), an RPC call checks no nonce: the sender still runs.
    // A creation too: the nonce wraps to zero.
    const create = "[{\"from\":" ++ poor_sender ++ "},\"latest\"," ++ max_sender ++ "]";
    try expect_contains(try h.request("eth_call", create), "\"result\":\"0x\"");
    const sent = "[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ address_target ++ "},\"latest\",";
    const call = sent ++ max_sender ++ "]";
    try expect_contains(try h.request("eth_call", call), "\"result\":\"0x\"");
    try expect_contains(try h.request("eth_estimateGas", call), "\"result\":\"0x5208\"");
    try expect_contains(try h.request("eth_createAccessList", call), "\"gasUsed\":\"0x5208\"");
    const traced = sent ++ "{\"tracer\":\"callTracer\",\"stateOverrides\":" ++ max_sender ++ "}]";
    try expect_contains(try h.request("debug_traceCall", traced), "\"gasUsed\":\"0x5208\"");
    // eth_simulateV1 with validation reports a lower nonce before the maximum one.
    const blocks = "[{\"blockStateCalls\":[{\"stateOverrides\":" ++ max_sender ++
        ",\"calls\":[{\"from\":" ++ poor_sender ++ ",\"maxFeePerGas\":\"0x10000000000\"";
    const low = blocks ++ ",\"nonce\":\"0x28a\"}]}],\"validation\":true}]";
    try expect_failure(h, "eth_simulateV1", low, "-38010", "nonce too low");
    // Without validation, eth_simulateV1 refuses to bump the nonce (Nethermind).
    const plain = blocks ++ "}]}]}]";
    try expect_failure(h, "eth_simulateV1", plain, "-32603", "nonce has max value");
}

test "eth: eth_simulateV1 traceTransfers adds ERC-7528 transfer logs outside the bloom" {
    const h = try Harness.create();
    defer h.destroy();
    // The callee runs LOG0 (no data); the sender is funded by an override.
    const request = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ poor_sender ++
        ":{\"balance\":\"0x10\"}," ++ override_target ++ ":{\"code\":\"0x60006000a000\"}}," ++
        "\"calls\":[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ override_target ++
        ",\"value\":\"0x5\"}]}]";
    const plain = try h.request("eth_simulateV1", request ++ "}]");
    const bloom_at = std.mem.indexOf(u8, plain, "\"logsBloom\":").?;
    var bloom: [600]u8 = undefined;
    const plain_bloom = bloom[0..532];
    @memcpy(plain_bloom, plain[bloom_at..][0..532]);
    try testing.expectEqual(@as(usize, 1), count_of(plain, "\"logIndex\""));
    const traced = try h.request("eth_simulateV1", request ++ ",\"traceTransfers\":true}]");
    const transfer = "{\"address\":\"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"topics\":[" ++
        "\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"," ++
        "\"0x000000000000000000000000000000000000000000000000000000000000dead\"," ++
        "\"0x0000000000000000000000000000000000000000000000000000000000007777\"]," ++
        "\"data\":\"0x" ++ zeros_62 ++ "05\"";
    try expect_contains(traced, "\"logs\":[" ++ transfer);
    try expect_contains(traced, "\"logIndex\":\"0x0\"");
    try expect_contains(traced, "\"address\":" ++ override_target ++ ",\"topics\":[]");
    try expect_contains(traced, "\"logIndex\":\"0x1\"");
    // The block's bloom (and receipts) leave the synthetic log out.
    try expect_contains(traced, plain_bloom);
    // A reverted call logs no transfer.
    const reverting = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ poor_sender ++
        ":{\"balance\":\"0x10\"}," ++ override_target ++ ":{\"code\":\"0x5f5ffd\"}}," ++
        "\"calls\":[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ override_target ++
        ",\"value\":\"0x5\"}]}],\"traceTransfers\":true}]";
    try expect_contains(try h.request("eth_simulateV1", reverting), "\"logs\":[]");
    // A call to a precompile with value logs one transfer.
    const precompile = "[{\"blockStateCalls\":[{\"stateOverrides\":{" ++ poor_sender ++
        ":{\"balance\":\"0x10\"}},\"calls\":[{\"from\":" ++ poor_sender ++ ",\"to\":" ++
        "\"0x0000000000000000000000000000000000000004\",\"value\":\"0x7\"}]}]," ++
        "\"traceTransfers\":true}]";
    const identity = try h.request("eth_simulateV1", precompile);
    try testing.expectEqual(@as(usize, 1), count_of(identity, "\"logIndex\""));
    try expect_contains(identity, "\"data\":\"0x" ++ zeros_62 ++ "07\"");
    // The flags read as Nethermind's BooleanConverter: a string must start with true/false.
    const upper = request ++ ",\"traceTransfers\":\"TRUE\"}]";
    const string_flag = try h.request("eth_simulateV1", upper);
    try testing.expectEqual(@as(usize, 2), count_of(string_flag, "\"logIndex\""));
    const refused = [_][]const u8{ "\"latest\"", "null", "1", "{}" };
    const flags = [_][]const u8{ "traceTransfers", "validation", "returnFullTransactions" };
    var body: [1024]u8 = undefined;
    for (flags) |flag| for (refused) |value| {
        const format = request_prefix_format ++ "eth_simulateV1\",\"params\":{s},\"{s}\":{s}}}]}}";
        const text = try std.fmt.bufPrint(&body, format, .{ request, flag, value });
        try expect_contains(try h.request_runtime(text), "\"code\":-32602");
    };
}

/// Reverts with `Error("nope")`: CODECOPY the 100 bytes after the 10-byte prefix, REVERT.
const revert_nope_code = "0x6064600a5f39" ++ "60645ffd" ++ revert_nope_data[2..];
const revert_nope_data = "0x08c379a0" ++ zeros_62 ++ "20" ++ zeros_62 ++ "04" ++
    "6e6f7065" ++ "00000000000000000000000000000000000000000000000000000000";
const poor_sender = "\"0x000000000000000000000000000000000000dead\"";

fn simulate_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    const h = try Harness.create();
    defer h.destroy();
    const head_root = try h.node.db.root();
    var body: [4096]u8 = undefined;
    const pieces = [_][]const u8{
        "{\"calls\":[{\"to\":" ++ counter_at ++ "}]}",
        "{\"stateOverrides\":{" ++ counter_at ++ ":{\"code\":\"" ++ counter_hex ++ "\"}}}",
        "{\"blockOverrides\":{\"time\":\"0x5\"}}",
        "{\"blockOverrides\":{\"time\":\"0xffffffffffffffff\"}}",
        "{\"blockOverrides\":{\"number\":\"0xffffffffffffffff\"}}",
        "{\"blockOverrides\":{\"gasLimit\":\"0x0\"},\"calls\":[{}]}",
        "{\"stateOverrides\":{" ++ counter_at ++ ":{\"balance\":\"0x10\",\"state\":{}}}}",
        "{\"calls\":[{\"to\":" ++ counter_at ++ ",\"value\":\"0x1\"}]}",
        "{\"calls\":[{\"from\":" ++ address_one ++ ",\"to\":" ++ reverter_at ++ "}]}",
        "{\"bogus\":1}",
    };
    var w: std.Io.Writer = .fixed(&body);
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_simulateV1\",\"params\":[{");
    try w.writeAll("\"blockStateCalls\":[");
    const count = prng.below(6);
    for (0..count) |index| {
        if (index > 0) try w.writeAll(",");
        try w.writeAll(pieces[prng.below(pieces.len)]);
    }
    try w.writeAll("]}]}");
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, w.buffered(), &out);
    try json.validate(out.buffered());
    try testing.expectEqual(head_root, try h.node.db.root());
    try testing.expectEqual(@as(usize, 0), h.node.executor.state.accounts.count());
}

test "eth: seeded fuzz of eth_simulateV1 requests" {
    for (0..48) |seed| try simulate_scenario(seed + 0x5171);
}

fn fuzz_simulate(_: void, smith: *testing.Smith) anyerror!void {
    try simulate_scenario(smith.value(u64));
}

test "eth: fuzz eth_simulateV1" {
    try testing.fuzz({}, fuzz_simulate, .{});
}

test "eth: eth_simulateV1 blocks are base/base's sealed blocks" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    var head: [66]u8 = undefined;
    const latest = try h.request("eth_getBlockByNumber", "[\"latest\",false]");
    @memcpy(&head, value_after(latest, "hash", 0).?);
    // A counter call (one log), then slot 0 cleared from 1 (a refund), then an empty block.
    const clearer_at = "\"0x0000000000000000000000000000000000000057\"";
    const params = "[{\"returnFullTransactions\":true,\"blockStateCalls\":[" ++
        "{\"stateOverrides\":{" ++ counter_at ++
        ":{\"code\":\"" ++ counter_hex ++ "\"}},\"calls\":[{\"from\":" ++ address_one ++
        ",\"to\":" ++ counter_at ++ ",\"gasPrice\":\"0x0\"}]}," ++
        "{\"stateOverrides\":{" ++ clearer_at ++ ":{\"code\":\"0x5f5f5500\",\"state\":{\"0x" ++
        zeros_62 ++ "00\":\"0x" ++ zeros_62 ++ "01\"}}},\"calls\":[{\"to\":" ++ clearer_at ++
        "}]},{}]},\"latest\"]";
    const text = try h.request("eth_simulateV1", params);
    const result = text["\"result\":".len..];
    // Block hashes chain from the base block; the first block's log points at its block and
    // transaction. With full transactions, block and transaction hashes alternate.
    const first_hash = value_after(text, "hash", 0).?;
    const second_hash = value_after(text, "hash", 2).?;
    const tx_hash = value_after(text, "hash", 1).?;
    try testing.expectEqualStrings(&head, value_after(text, "parentHash", 0).?);
    try testing.expectEqualStrings(first_hash, value_after(text, "parentHash", 1).?);
    try testing.expectEqualStrings(second_hash, value_after(text, "parentHash", 2).?);
    try testing.expectEqualStrings(first_hash, value_after(text, "blockHash", 0).?);
    try testing.expectEqualStrings(tx_hash, value_after(text, "transactionHash", 0).?);
    try testing.expectEqualStrings(first_hash, value_after(text, "blockHash", 1).?);
    // Each `hash` is the hash of the header the block object shows.
    for (0..3) |index| {
        const object = element_of(result, index).?;
        const shown = try json.parse_fixed(32, value_after(object, "hash", 0).?);
        try testing.expectEqualSlices(u8, &shown, &(try header_of_block(object)).hash().bytes);
    }
    // A zero state and withdrawals root (no state provider), the transaction with its
    // `from` and a zero signature (a legacy one, gasPrice given, unsigned as geth builds it:
    // v zero, no EIP-155 v).
    const zero_hash = "\"0x" ++ zeros_62 ++ "00\"";
    try testing.expectEqual(@as(usize, 3), count_of(text, "\"stateRoot\":" ++ zero_hash));
    try testing.expectEqual(@as(usize, 3), count_of(text, "\"withdrawalsRoot\":" ++ zero_hash));
    try testing.expectEqual(@as(usize, 3), count_of(text, "\"withdrawals\":[]"));
    try expect_contains(text, "\"type\":\"0x0\",\"from\":" ++ address_one);
    try expect_contains(text, "\"type\":\"0x2\",\"from\":\"0x" ++ zeros_62[0..40] ++ "\"");
    try expect_contains(text, "\"r\":\"0x0\",\"s\":\"0x0\"");
    try expect_contains(text, "\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\"");
    try testing.expectEqual(@as(usize, 0), count_of(text, "\"v\":\"0x2"));
    try testing.expectEqual(@as(usize, 3), count_of(text, "\"difficulty\":\"0x0\""));
    // The empty block has the empty transactions and receipts roots.
    const empty = "\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"";
    try expect_contains(text, "\"transactionsRoot\":" ++ empty ++ ",\"receiptsRoot\":" ++ empty);
    // maxUsedGas is the gas before the refund: 21000 + 2 * 2 + 5000 = 26004, refunded 4800.
    try expect_contains(text, "\"gasUsed\":\"0x52d4\",\"maxUsedGas\":\"0x6594\"");
}

/// The value of the `nth` (from 0) string member `key` in `text`, without its quotes.
fn value_after(text: []const u8, key: []const u8, nth: usize) ?[]const u8 {
    var buffer: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&buffer, "\"{s}\":\"", .{key}) catch unreachable;
    var position: usize = 0;
    var found: usize = 0;
    while (std.mem.indexOfPos(u8, text, position, needle)) |at| : (found += 1) {
        const start = at + needle.len;
        const end = std.mem.indexOfScalarPos(u8, text, start, '"') orelse return null;
        if (found == nth) return text[start..end];
        position = end;
    }
    return null;
}

/// The raw text of element `index` of the JSON array `array`.
fn element_of(array: []const u8, index: usize) ?[]const u8 {
    var scanner = json.Scanner.init(array);
    const open = scanner.next() catch return null;
    if (open.tag != .array_begin) return null;
    var position: usize = 0;
    while (position <= index) : (position += 1) {
        const before = scanner.offset();
        const token = scanner.next() catch return null;
        if (token.tag == .array_end) return null;
        scanner.skip(token) catch return null;
        if (position == index) {
            const raw = scanner.input[before..scanner.offset()];
            return std.mem.trimStart(u8, raw, " \t\r\n,");
        }
    }
    return null;
}

/// Rebuilds the consensus header of an RPC block object from its fields.
fn header_of_block(object: []const u8) !consensus.Header {
    var header: consensus.Header = .{};
    header.parent_hash.bytes = try fixed_field(32, object, "parentHash");
    header.ommers_hash.bytes = try fixed_field(32, object, "sha3Uncles");
    header.beneficiary.bytes = try fixed_field(20, object, "miner");
    header.state_root.bytes = try fixed_field(32, object, "stateRoot");
    header.transactions_root.bytes = try fixed_field(32, object, "transactionsRoot");
    header.receipts_root.bytes = try fixed_field(32, object, "receiptsRoot");
    header.logs_bloom.bytes = try fixed_field(256, object, "logsBloom");
    header.difficulty = try quantity_field(u256, object, "difficulty");
    header.number = try quantity_field(u64, object, "number");
    header.gas_limit = try quantity_field(u64, object, "gasLimit");
    header.gas_used = try quantity_field(u64, object, "gasUsed");
    header.timestamp = try quantity_field(u64, object, "timestamp");
    header.mix_hash.bytes = try fixed_field(32, object, "mixHash");
    header.nonce.bytes = try fixed_field(8, object, "nonce");
    header.base_fee_per_gas = try quantity_field(u64, object, "baseFeePerGas");
    header.withdrawals_root = .{ .bytes = try fixed_field(32, object, "withdrawalsRoot") };
    header.blob_gas_used = try quantity_field(u64, object, "blobGasUsed");
    header.excess_blob_gas = try quantity_field(u64, object, "excessBlobGas");
    header.parent_beacon_block_root = .{
        .bytes = try fixed_field(32, object, "parentBeaconBlockRoot"),
    };
    header.requests_hash = .{ .bytes = try fixed_field(32, object, "requestsHash") };
    const extra = value_after(object, "extraData", 0) orelse return error.MissingField;
    try testing.expect(extra.len <= 2 + 2 * 32);
    header.extra_data = try json.parse_data(extra, &extra_data_buffer);
    return header;
}

var extra_data_buffer: [32]u8 = undefined;

fn fixed_field(comptime size: usize, object: []const u8, key: []const u8) ![size]u8 {
    return json.parse_fixed(size, value_after(object, key, 0) orelse return error.MissingField);
}

fn quantity_field(comptime T: type, object: []const u8, key: []const u8) !T {
    return json.parse_quantity(T, value_after(object, key, 0) orelse return error.MissingField);
}

test "eth: call and estimate gas" {
    const h = try Harness.create();
    defer h.destroy();
    const estimate = try h.request("eth_estimateGas", "[{\"to\":" ++ address_target ++ "}]");
    try testing.expectEqualStrings("\"result\":\"0x5208\"", estimate);
    const output = try h.request("eth_call", "[{\"to\":" ++ address_target ++ "},\"latest\"]");
    try testing.expectEqualStrings("\"result\":\"0x\"", output);
}

fn count_of(haystack: []const u8, needle: []const u8) usize {
    return std.mem.count(u8, haystack, needle);
}

test "eth: txpool content, contentFrom and inspect list pending and queued by sender" {
    const h = try Harness.create();
    defer h.destroy();
    try testing.expectEqualStrings(
        "\"result\":{\"pending\":{},\"queued\":{}}",
        try h.request("txpool_content", "[]"),
    );
    var buffer: [256]u8 = undefined;
    try fixture.submit(h.node, 1, 0, 1, &buffer);
    try fixture.submit(h.node, 1, 1, 2, &buffer);
    try fixture.submit(h.node, 1, 5, 3, &buffer); // Nonce gap: queued.
    try fixture.submit(h.node, 2, 0, 4, &buffer);
    const text = try h.request("txpool_content", "[]");
    try testing.expectEqual(@as(usize, 4), count_of(text, "\"from\""));
    const one = primitives.checksum(fixture.address_of(1), null);
    const two = primitives.checksum(fixture.address_of(2), null);
    const queued_at = std.mem.indexOf(u8, text, "\"queued\"").?;
    const one_at = std.mem.indexOf(u8, text, &one).?;
    const two_at = std.mem.indexOf(u8, text, &two).?;
    try testing.expect(one_at < queued_at and two_at < queued_at);
    const one_bytes = fixture.address_of(1).bytes;
    const two_bytes = fixture.address_of(2).bytes;
    const one_first = std.mem.order(u8, &one_bytes, &two_bytes) == .lt;
    try testing.expectEqual(one_first, one_at < two_at);
    try expect_contains(text[queued_at..], "\"5\":{");
    try expect_contains(text[0..queued_at], "\"1\":{");
    const lines = try h.request("txpool_inspect", "[]");
    const receiver = primitives.checksum(fixture.address_of(9), null);
    var expected: [128]u8 = undefined;
    const line_format = "\"{s}: 3 wei + 21000 gas \u{00d7} 10000000000 wei\"";
    const line = try std.fmt.bufPrint(&expected, line_format, .{&receiver});
    try expect_contains(lines, line);
    try testing.expectEqual(@as(usize, 4), count_of(lines, " wei + "));
    var body: [256]u8 = undefined;
    const from_format = request_prefix_format ++ "txpool_contentFrom\",\"params\":[\"{s}\"]}}";
    const from = try h.request_runtime(try std.fmt.bufPrint(&body, from_format, .{&two}));
    try expect_contains(from, "\"result\":{\"pending\":{\"0\":{");
    try expect_contains(from, "\"queued\":{}}");
    const unknown = "[\"0x00000000000000000000000000000000000000ff\"]";
    try testing.expectEqualStrings(
        "\"result\":{\"pending\":{},\"queued\":{}}",
        try h.request("txpool_contentFrom", unknown),
    );
}

test "eth: miner DA getter and gas limit target cap block building" {
    const h = try Harness.create();
    defer h.destroy();
    try testing.expectEqualStrings(
        "\"result\":[\"0x0\",\"0x0\"]",
        try h.request("miner_getMaxDASize", "[]"),
    );
    _ = try h.request("miner_setMaxDASize", "[\"0x100\",\"0x1000\"]");
    try testing.expectEqualStrings(
        "\"result\":[\"0x100\",\"0x1000\"]",
        try h.request("miner_getMaxDASize", "[]"),
    );
    // Room for two 21000-gas transfers: the third waits for the next block.
    const target = try h.request("miner_setGasLimit", "[\"0xa410\"]");
    try testing.expectEqualStrings("\"result\":true", target);
    var buffer: [256]u8 = undefined;
    for (0..3) |nonce| try fixture.submit(h.node, 1, nonce, 1, &buffer);
    const first = try h.mine(12);
    const header = h.node.chain.header(first.bytes).?;
    try testing.expectEqual(@as(u64, 42_000), header.gas_used);
    try testing.expectEqual(fixture.spec.gas_limit, header.gas_limit);
    _ = try h.request("miner_setGasLimit", "[\"0x0\"]");
}

test "eth: base_transactionStatus and admin drop methods" {
    const h = try Harness.create();
    defer h.destroy();
    var buffer: [256]u8 = undefined;
    try fixture.submit(h.node, 1, 0, 1, &buffer);
    try fixture.submit(h.node, 2, 0, 1, &buffer);
    try fixture.submit(h.node, 2, 1, 1, &buffer);
    const pool = &h.node.pool;
    var iterator = pool.sender_transactions(pool.sender_of(fixture.address_of(1)).?);
    const hash = iterator.next().?.tx.hash;
    var body: [256]u8 = undefined;
    const status_format =
        request_prefix_format ++ "base_transactionStatus\",\"params\":[\"0x{x}\"]}}";
    var status_buffer: [256]u8 = undefined;
    const status_body = try std.fmt.bufPrint(&status_buffer, status_format, .{&hash.bytes});
    try expect_contains(try h.request_runtime(status_body), "{\"status\":\"Known\"}");
    const drop_format = request_prefix_format ++ "admin_dropTransaction\",\"params\":[\"0x{x}\"]}}";
    const drop_body = try std.fmt.bufPrint(&body, drop_format, .{&hash.bytes});
    try expect_contains(try h.request_runtime(drop_body), "\"result\":true");
    try expect_contains(try h.request_runtime(drop_body), "\"result\":false");
    try expect_contains(try h.request_runtime(status_body), "{\"status\":\"Unknown\"}");
    const two = fixture.address_of(2);
    const sender_format =
        request_prefix_format ++ "admin_dropSenderTransactions\",\"params\":[\"0x{x}\"]}}";
    const sender_body = try std.fmt.bufPrint(&body, sender_format, .{&two.bytes});
    const dropped = try h.request_runtime(sender_body);
    try testing.expectEqual(@as(usize, 2), count_of(dropped, "\"0x"));
    try testing.expectEqual(@as(u32, 0), pool.count());
    try expect_contains(try h.request_runtime(sender_body), "\"result\":[]");
}

test "eth: eth_config on the dev L1 lists Prague with no next fork" {
    const h = try Harness.create();
    defer h.destroy();
    const text = try h.request("eth_config", "[]");
    try expect_contains(text, "\"current\":{\"activationTime\":0,");
    const schedule = "\"blobSchedule\":{\"baseFeeUpdateFraction\":5007716,\"max\":9,\"target\":6}";
    try expect_contains(text, schedule);
    try expect_contains(text, "\"chainId\":\"0x539\"");
    const pairing = "\"BLS12_PAIRING_CHECK\":\"0x000000000000000000000000000000000000000f\"";
    try expect_contains(text, pairing);
    try testing.expect(std.mem.indexOf(u8, text, "P256VERIFY") == null);
    try expect_contains(text, "\"WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS\"");
    const roots = "\"BEACON_ROOTS_ADDRESS\":\"0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02\"";
    try expect_contains(text, roots);
    try expect_contains(text, "\"next\":null,\"last\":null}");
    var expected: [32]u8 = undefined;
    const hash = std.hash.Crc32.hash(&h.node.chain.genesis_hash);
    const fork_id = try std.fmt.bufPrint(&expected, "\"forkId\":\"0x{x:0>8}\"", .{hash});
    try expect_contains(text, fork_id);
}

var l2_config_spec: chainspec.ChainSpec = chainspec.ChainSpec.presets.base_devnet;

test "eth: eth_config on L2 zeroes blobs, keeps Base system contracts, shows next fork" {
    l2_config_spec.upgrades[@backingInt(chainspec.Upgrade.beryl)] = 1_000_000;
    const h = try Harness.create_for(&l2_config_spec);
    defer h.destroy();
    const text = try h.request("eth_config", "[]");
    const zero = "\"blobSchedule\":{\"baseFeeUpdateFraction\":0,\"max\":0,\"target\":0}";
    try testing.expectEqual(@as(usize, 3), count_of(text, zero));
    try expect_contains(text, "\"P256VERIFY\":\"0x0000000000000000000000000000000000000100\"");
    try testing.expect(std.mem.indexOf(u8, text, "WITHDRAWAL_REQUEST") == null);
    try testing.expectEqual(@as(usize, 3), count_of(text, "\"HISTORY_STORAGE_ADDRESS\""));
    try expect_contains(text, "\"next\":{\"activationTime\":1000000,");
    try expect_contains(text, "\"last\":{\"activationTime\":1000000,");
    // The next fork's id folds the Beryl time into the current one.
    const forks = eth_config.fork_times(&l2_config_spec);
    const genesis = h.node.chain.genesis_hash;
    const now = eth_config.fork_hash(genesis, 0, forks.slice(), 0);
    const next = eth_config.fork_hash(genesis, 0, forks.slice(), 1_000_000);
    try testing.expect(now != next);
    var expected: [32]u8 = undefined;
    const next_id = try std.fmt.bufPrint(&expected, "\"forkId\":\"0x{x:0>8}\"", .{next});
    try expect_contains(text, next_id);
}

fn txpool_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    const h = try Harness.create();
    defer h.destroy();
    var buffer: [256]u8 = undefined;
    const count = prng.range(0, 24);
    for (0..count) |_| {
        const from: u8 = @intCast(1 + prng.below(fixture.senders));
        const nonce = prng.below(20);
        const value: u256 = prng.range(1, 1000);
        fixture.submit(h.node, from, nonce, value, &buffer) catch {}; // Rejections are fine.
    }
    const pool_count = h.node.pool.count();
    const content = try h.request("txpool_content", "[]");
    try testing.expectEqual(@as(usize, pool_count), count_of(content, "\"from\""));
    // `content` points into the harness output: check it before the next request.
    const pending = h.node.pool.pending_count;
    const queued_at = std.mem.indexOf(u8, content, "\"queued\"").?;
    try testing.expectEqual(@as(usize, pending), count_of(content[0..queued_at], "\"from\""));
    const lines = try h.request("txpool_inspect", "[]");
    try testing.expectEqual(@as(usize, pool_count), count_of(lines, " wei + "));
}

test "eth: txpool listings seeded fuzz" {
    for (0..12) |seed| try txpool_scenario(seed + 500);
}

fn fuzz_txpool(_: void, smith: *testing.Smith) anyerror!void {
    try txpool_scenario(smith.value(u64));
}

test "eth: txpool listings fuzz" {
    try testing.fuzz({}, fuzz_txpool, .{});
}

test "eth: fee history closes with the base fee after its newest block, not the head" {
    const h = try Harness.create_for(&chainspec.ChainSpec.presets.base_devnet);
    defer h.destroy();
    const first = try h.mine(2);
    const second = try h.mine(4);
    _ = try h.mine(6);
    const fee_first = h.node.chain.header(first.bytes).?.base_fee_per_gas.?;
    const fee_second = h.node.chain.header(second.bytes).?.base_fee_per_gas.?;
    // Empty blocks lower the base fee each block, so the head would imply a third value.
    try testing.expect(fee_second < fee_first);
    var expected: [128]u8 = undefined;
    const fees = try std.fmt.bufPrint(&expected, "\"baseFeePerGas\":[\"0x{x}\",\"0x{x}\"]", .{
        fee_first,
        fee_second,
    });
    const history = try h.request("eth_feeHistory", "[\"0x1\",\"0x1\",[]]");
    try expect_contains(history, fees);
    try expect_contains(history, "\"oldestBlock\":\"0x1\"");
    try expect_contains(history, "\"reward\":[]");
    try testing.expectEqualStrings(
        "\"result\":{\"gasUsedRatio\":[],\"oldestBlock\":\"0x0\"}",
        try h.request("eth_feeHistory", "[\"0x0\",\"latest\"]"),
    );
    // Counts past block 0 or above 1024 truncate, as in reth.
    const range = try h.request("eth_feeHistory", "[\"0x401\",\"0x1\"]");
    try expect_contains(range, "\"oldestBlock\":\"0x0\"");
    // The block size is the length of the block's RLP encoding.
    const raw = try h.request("debug_getRawBlock", "[\"0x1\"]");
    const raw_prefix = "\"result\":\"0x";
    try testing.expect(std.mem.startsWith(u8, raw, raw_prefix));
    const raw_length = (raw.len - raw_prefix.len - 1) / 2;
    const size = try std.fmt.bufPrint(&expected, "\"size\":\"0x{x}\"", .{raw_length});
    try expect_contains(try h.request("eth_getBlockByNumber", "[\"0x1\",false]"), size);
}

test "eth: fuzz_coverage exists only in a coverage build" {
    if (eth.fuzz_coverage.enabled) return error.SkipZigTest;
    const h = try Harness.create();
    defer h.destroy();
    try expect_contains(try h.request("fuzz_coverage", "[]"), "\"code\":-32601");
}

test "eth: block objects refuse unknown members instead of spinning" {
    const h = try Harness.create();
    defer h.destroy();
    const address = "\"0x833b738e23eb9ba1529e0d93ff98ba38dbb503bf\"";
    // An unknown member whose value is a container once left the member loop reading the
    // scanner's end token forever.
    for ([_][]const u8{ "{\"a\":[]}", "{\"accessList\":[]}", "{\"a\":1}", "{}" }) |block| {
        var body: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&body, request_prefix_format ++
            "eth_getBalance\",\"params\":[{s},{s}]}}", .{ address, block });
        try expect_contains(try h.request_runtime(text), "\"code\":-32602");
    }
    const by_number = try h.request("eth_getBalance", "[" ++ address ++
        ",{\"blockNumber\":\"0x0\"}]");
    try expect_contains(by_number, "\"result\":\"0x");
    const config = try h.request("debug_traceCall", "[{}, \"latest\"," ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"onlyTopCall\":[],\"x\":1}}]");
    try expect_contains(config, "invalid tracer config");
}

test "eth: getStorageAt reads a full-width slot key and defaults to latest" {
    const h = try Harness.create();
    defer h.destroy();
    const account = "\"0x4200000000000000000000000000000000000015\"";
    const wide = "\"0x0000000000000000000000000000000000000000000000000000000000000007\"";
    const short = try h.request("eth_getStorageAt", "[" ++ account ++ ",\"0x7\",\"latest\"]");
    try expect_contains(short, "\"result\":\"0x");
    try testing.expectEqualStrings(short, try h.request("eth_getStorageAt", "[" ++ account ++
        "," ++ wide ++ "]"));
    try testing.expectEqualStrings(short, try h.request("eth_getStorageAt", "[" ++ account ++
        ",\"0x007\"]"));
    // A bare 0x is slot zero (ruint reads no digits as zero), as base answers eth_getProof.
    const bare = try h.request("eth_getStorageAt", "[" ++ account ++ ",\"0x\"]");
    try expect_contains(bare, "\"result\":\"0x");
    for ([_][]const u8{ "\"7\"", "\"0x+7\"", "\"0x1_2\"" }) |slot| {
        var body: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&body, request_prefix_format ++
            "eth_getStorageAt\",\"params\":[{s},{s}]}}", .{ account, slot });
        try expect_contains(try h.request_runtime(text), "\"code\":-32602");
    }
}

test "eth: eth_call of a creation returns the deployed code" {
    const h = try Harness.create();
    defer h.destroy();
    // Init code storing 0x60ff at memory[30..32] and returning it as the runtime code.
    const created = try h.request("eth_call", "[{\"input\":\"0x6160ff6000526002601ef3\"}]");
    try testing.expectEqualStrings("\"result\":\"0x60ff\"", created);
}

test "eth: feeHistory takes a numeric block count and no percentiles" {
    const h = try Harness.create();
    defer h.destroy();
    const history = try h.request("eth_feeHistory", "[1,\"latest\"]");
    try expect_contains(history, "\"oldestBlock\":\"0x0\"");
    try testing.expect(std.mem.indexOf(u8, history, "reward") == null);
    try expect_contains(try h.request("eth_feeHistory", "[\"+1\",\"latest\"]"), "-32602");
    try expect_contains(try h.request("eth_feeHistory", "[1.5,\"latest\"]"), "-32602");
}

test "eth: a call request's access list is charged and warms its entries" {
    const h = try Harness.create();
    defer h.destroy();
    const to = "\"to\":\"0x00000000000000000000000000000000000000aa\"";
    try testing.expectEqualStrings(
        "\"result\":\"0x5208\"",
        try h.request("eth_estimateGas", "[{" ++ to ++ "}]"),
    );
    // 21000 + 2400 for the address + 1900 for each of two keys = 27200, before or after
    // `input`; reth's search (optimistic guess, then 1.5%) settles at 27545.
    const item_address = "\"address\":\"0x1111111111111111111111111111111111111111\"";
    const key_0 = "\"0x0000000000000000000000000000000000000000000000000000000000000000\"";
    const key_1 = "\"0x0000000000000000000000000000000000000000000000000000000000000001\"";
    const listed = "\"accessList\":[{" ++ item_address ++ ",\"storageKeys\":[" ++ key_0 ++
        "," ++ key_1 ++ "]}]";
    try testing.expectEqualStrings(
        "\"result\":\"0x6b99\"",
        try h.request("eth_estimateGas", "[{" ++ to ++ "," ++ listed ++ ",\"input\":\"0x\"}]"),
    );
    try testing.expectEqualStrings(
        "\"result\":\"0x6b99\"",
        try h.request("eth_estimateGas", "[{\"input\":\"0x\"," ++ listed ++ "," ++ to ++ "}]"),
    );
    // Nethermind requires an item's address, not its keys.
    const keyless = "[{\"accessList\":[{" ++ item_address ++ "}]}]";
    try expect_contains(try h.request("eth_estimateGas", keyless), "\"result\":\"0x");
    const addressless = "[{\"accessList\":[{\"storageKeys\":[]}]}]";
    try expect_contains(try h.request("eth_estimateGas", addressless), "-32602");
}

/// A call to code returning TIMESTAMP and NUMBER, the override installing it, and the
/// leading zeros of a 32-byte zero_word holding a one-byte value.
const clock_call = "{\"to\":\"0x00000000000000000000000000000000000c0ffe\"}";
const clock_code = "{\"0x00000000000000000000000000000000000c0ffe\":" ++
    "{\"code\":\"0x426000524360205260406000f3\"}}";
const zero_word = "00000000000000000000000000000000000000000000000000000000000000";

test "eth: a call at a block runs in that block's environment, pending in the next" {
    const h = try Harness.create();
    defer h.destroy();
    _ = try h.mine(2);
    _ = try h.mine(4);
    const code = clock_code;
    // The harness keeps only the head's state, so block 2 is named by number and by tag.
    const head = "\"result\":\"0x" ++ zero_word ++ "04" ++ zero_word ++ "02\"";
    try testing.expectEqualStrings(
        head,
        try h.request("eth_call", "[" ++ clock_call ++ ",\"0x2\"," ++ code ++ "]"),
    );
    try testing.expectEqualStrings(
        head,
        try h.request("eth_call", "[" ++ clock_call ++ ",\"latest\"," ++ code ++ "]"),
    );
    // base/base derives "pending" from the head: number + 1, timestamp + 12.
    try testing.expectEqualStrings(
        "\"result\":\"0x" ++ zero_word ++ "10" ++ zero_word ++ "03\"",
        try h.request("eth_call", "[" ++ clock_call ++ ",\"pending\"," ++ code ++ "]"),
    );
}

test "eth: a pending eth_call runs at the Denim schedule's next block, traceCall at + 12" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    // Block 1 is due 200 ms after genesis (time 0): second 0, millisecond part 200.
    try testing.expectEqualStrings(
        "\"result\":\"0x" ++ zero_word ++ "00" ++ zero_word ++ "01\"",
        try h.request("eth_call", "[" ++ clock_call ++ ",\"pending\"," ++ clock_code ++ "]"),
    );
    // BaseTime's packed slot 0 holds the forecast part beneath the caller's own override
    // (code returning slot 0); latest holds genesis's.
    const base_time = "\"0x4200000000000000000000000000000000000030\"";
    const millis = "[{\"to\":" ++ base_time ++ "}";
    const slot_reader = "{" ++ base_time ++ ":{\"code\":\"0x5f545f5260205ff3\"}}]";
    try testing.expectEqualStrings(
        "\"result\":\"0x" ++ zero_word ++ "c8\"",
        try h.request("eth_call", millis ++ ",\"pending\"," ++ slot_reader),
    );
    try testing.expectEqualStrings(
        "\"result\":\"0x" ++ zero_word ++ "00\"",
        try h.request("eth_call", millis ++ ",\"latest\"," ++ slot_reader),
    );
    // debug_traceCall keeps reth's pending env: head + 12 seconds.
    const traced = try h.request("debug_traceCall", "[" ++ clock_call ++ ",\"pending\"," ++
        "{\"tracer\":\"callTracer\",\"stateOverrides\":" ++ clock_code ++ "}]");
    try expect_contains(traced, "\"output\":\"0x" ++ zero_word ++ "0c" ++ zero_word ++ "01\"");
}

test "eth: a call request's authorizations are charged as a type-4 transaction" {
    const h = try Harness.create();
    defer h.destroy();
    // An authorization for another chain is skipped but still costs 25000 intrinsic gas.
    const authorization = "{\"address\":\"0x0000000000000000000000000000000000000004\"," ++
        "\"chainId\":\"0x2105\",\"nonce\":\"0x5\",\"r\":\"0x1\",\"s\":\"0x1\"," ++
        "\"yParity\":\"0x1\"}";
    const to = "\"to\":\"0x2a379f4bf2e4752dd19c04b3d8ac9f1d4ad44b89\"";
    const listed = try h.request("eth_createAccessList", "[{\"authorizationList\":[" ++
        authorization ++ "]," ++ to ++ "}]");
    try expect_contains(listed, "\"gasUsed\":\"0xb3b0\"");
    // Every field but r and s (zero when absent, as Nethermind) is required.
    const partial = "[{\"authorizationList\":[{\"address\":" ++
        "\"0x0000000000000000000000000000000000000004\"}]," ++ to ++ "}]";
    try expect_contains(try h.request("eth_createAccessList", partial), "-32602");
}

test "eth: request fields parse as base/base's serde types" {
    const h = try Harness.create();
    defer h.destroy();
    _ = try h.mine(2);
    // alloy's `Filter`: a block hash excludes a range; null bounds read as absent.
    const block = try h.request("eth_getBlockByNumber", "[\"latest\",false]");
    const at = std.mem.indexOf(u8, block, "\"hash\":\"").? + 8;
    var hash: [66]u8 = undefined;
    @memcpy(&hash, block[at..][0..66]);
    var body: [512]u8 = undefined;
    const both_format = request_prefix_format ++ "eth_getLogs\",\"params\":[{{" ++
        "\"blockHash\":\"{s}\",\"toBlock\":\"latest\"}}]}}";
    const both = try std.fmt.bufPrint(&body, both_format, .{&hash});
    try expect_contains(try h.request_runtime(both), "-32602");
    const open_end = "[{\"fromBlock\":\"latest\",\"toBlock\":null}]";
    try expect_contains(try h.request("eth_getLogs", open_end), "\"result\":[");
    // A block number parameter reads a hash as that block (Nethermind's BlockParameter).
    const by_hash_format = request_prefix_format ++
        "eth_getBlockByNumber\",\"params\":[\"{s}\",false]}}";
    const by_hash = try std.fmt.bufPrint(&body, by_hash_format, .{&hash});
    try expect_contains(try h.request_runtime(by_hash), "\"number\":\"0x1\"");
    // EIP-1898 objects as Nethermind's converter reads them: a null blockNumber is latest,
    // a null blockHash is absent, other members are ignored.
    const latest = try h.request("eth_getBlockReceipts", "[\"latest\"]");
    var latest_copy: [4096]u8 = undefined;
    const latest_text = latest_copy[0..latest.len];
    @memcpy(latest_text, latest);
    const null_number = "[{\"blockNumber\":null}]";
    try testing.expectEqualStrings(latest_text, try h.request("eth_getBlockReceipts", null_number));
    const numbered = "[{\"blockHash\":null,\"blockNumber\":\"0x1\",\"other\":1}]";
    try expect_contains(try h.request("eth_getBlockByNumber", numbered[0 .. numbered.len - 1] ++
        ",false]"), "\"number\":\"0x1\"");
    try expect_contains(try h.request("eth_getBlockReceipts", "[{\"blockHash\":null}]"), "-32602");
    const balance = "[\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\",{\"blockNumber\":null}]";
    try expect_contains(try h.request("eth_getBalance", balance), "\"result\":\"0x");
    // eth_getLogs bounds may be block hashes (Nethermind), mixed with tags or numbers.
    const hashes_format = request_prefix_format ++ "eth_getLogs\",\"params\":[{{" ++
        "\"fromBlock\":\"{s}\",\"toBlock\":\"{s}\"}}]}}";
    const hashes = try std.fmt.bufPrint(&body, hashes_format, .{ &hash, &hash });
    try expect_contains(try h.request_runtime(hashes), "\"result\":[");
    const mixed = try std.fmt.bufPrint(&body, hashes_format, .{ "0x0", &hash });
    try expect_contains(try h.request_runtime(mixed), "\"result\":[");
    const unknown = "0x" ++ @as([64]u8, @splat('e'));
    const missing = try std.fmt.bufPrint(&body, hashes_format, .{ unknown, unknown });
    try expect_contains(try h.request_runtime(missing), "block not found");
    // eth_call ignores movePrecompileToAddress (only eth_simulateV1 applies it).
    const moved = "[{},\"latest\",{\"0x0000000000000000000000000000000000000001\":" ++
        "{\"movePrecompileToAddress\":\"0x8fe1cc26a5cc6c3299bc42ffe394466911fc0dea\"}}]";
    try testing.expectEqualStrings("\"result\":\"0x\"", try h.request("eth_call", moved));
    // The chain id is checked; empty bytes read as empty; `type` must be a u8 quantity.
    try expect_failure(h, "eth_call", "[{\"chainId\":\"0x1\"}]", "-32000", "invalid chain ID");
    try testing.expectEqualStrings(
        "\"result\":\"0x\"",
        try h.request("eth_call", "[{\"input\":\"\"}]"),
    );
    try expect_contains(try h.request("eth_call", "[{\"type\":\"finalized\"}]"), "-32602");
    try expect_contains(try h.request("eth_call", "[{\"type\":-1}]"), "-32602");
    try expect_contains(try h.request("eth_call", "[{\"type\":\"0x2\"}]"), "\"result\"");
    const blob_hash = "\"0x02" ++ zero_word ++ "\"";
    const blob = "[{\"blobVersionedHashes\":[" ++ blob_hash ++ "]}]";
    try expect_failure(h, "eth_call", blob, "-32003", "blob hash version mismatch");
    // A call with blob hashes is a type-3 transaction: its blob fee cap is checked (revm
    // `validate_eip4844_tx`), while no fee is charged.
    const kzg_hash = "\"0x01" ++ zero_word ++ "\"";
    const blob_call = "[{\"blobVersionedHashes\":[" ++ kzg_hash ++ "],\"to\":" ++
        "\"0x4ac857f04be60f4f00ba2f2a6aa1f62b40459e53\",\"maxFeePerBlobGas\":";
    const blob_fee = "max fee per blob gas less than block blob gas fee";
    try expect_failure(h, "eth_call", blob_call ++ "\"0x0\"}]", "-32003", blob_fee);
    try expect_failure(h, "eth_estimateGas", blob_call ++ "\"0x0\"}]", "-32003", blob_fee);
    const traced = try h.request("debug_traceCall", blob_call ++ "\"0x0\"},\"latest\"," ++
        "{\"tracer\":\"callTracer\"}]");
    try expect_contains(traced, "{\"code\":-32003,\"message\":\"" ++ blob_fee);
    const paid = try h.request("eth_estimateGas", blob_call ++ "\"0x1\"}]");
    try testing.expectEqualStrings("\"result\":\"0x5208\"", paid);
    // `JsonStorageKey` reads a bare 0x as slot zero.
    const proof = "[\"0x4200000000000000000000000000000000000007\",[\"0x\"],\"latest\"]";
    try expect_contains(try h.request("eth_getProof", proof), "\"storageProof\":[{");
}

test "eth: block parameters and indexes read as Nethermind's converters" {
    const h = try Harness.create();
    defer h.destroy();
    var tx_buffer: [256]u8 = undefined;
    try fixture.submit(h.node, 1, 0, 5, &tx_buffer);
    const hash = try h.mine(12);
    var body: [512]u8 = undefined;
    // A hash names its block in a block-number parameter; "" and null read as latest.
    const count_format = request_prefix_format ++
        "eth_getBlockTransactionCountByNumber\",\"params\":[\"0x{x}\"]}}";
    const count = try std.fmt.bufPrint(&body, count_format, .{&hash.bytes});
    try expect_contains(try h.request_runtime(count), "\"result\":\"0x1\"}");
    const at_format = request_prefix_format ++
        "eth_getTransactionByBlockNumberAndIndex\",\"params\":[\"0x{x}\",\"0x0\"]}}";
    const at = try std.fmt.bufPrint(&body, at_format, .{&hash.bytes});
    try expect_contains(try h.request_runtime(at), "\"transactionIndex\":\"0x0\"");
    for ([_][]const u8{ "[\"\",false]", "[null,false]" }) |params| {
        const latest_format = request_prefix_format ++ "eth_getBlockByNumber\",\"params\":{s}}}";
        const latest = try std.fmt.bufPrint(&body, latest_format, .{params});
        try expect_contains(try h.request_runtime(latest), "\"number\":\"0x1\"");
    }
    // An index of 2^64 or more is past the end (Nethermind reads a `UInt256`).
    const wide = "\"0x10000000000000000\"";
    inline for (.{
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getRawTransactionByBlockNumberAndIndex",
        "eth_getUncleByBlockNumberAndIndex",
    }) |method| {
        const past = try h.request(method, "[\"latest\"," ++ wide ++ "]");
        try testing.expectEqualStrings("\"result\":null", past);
    }
    const by_hash_format = request_prefix_format ++
        "eth_getTransactionByBlockHashAndIndex\",\"params\":[\"0x{x}\"," ++ wide ++ "]}}";
    const by_hash = try std.fmt.bufPrint(&body, by_hash_format, .{&hash.bytes});
    try expect_contains(try h.request_runtime(by_hash), "\"result\":null}");
    // A capital 0X hash is refused.
    for ([_][]const u8{ "eth_getBlockByHash", "eth_getBlockByNumber" }) |method| {
        const capital_format = request_prefix_format ++ "{s}\",\"params\":[\"0X{x}\",false]}}";
        const capital = try std.fmt.bufPrint(&body, capital_format, .{ method, &hash.bytes });
        try expect_contains(try h.request_runtime(capital), "-32602");
    }
    // debug_traceBlockByNumber has no pending block.
    const pending = try h.request("debug_traceBlockByNumber", "[\"pending\"]");
    try expect_contains(pending, "{\"code\":-32000,\"message\":\"pending block is not available\"");
}

test "eth: debug_traceBlock of genesis follows Nethermind" {
    // Block 0 is not traceable.
    const zero = try Harness.create();
    defer zero.destroy();
    const refused = "{\"code\":-32000,\"message\":\"genesis is not traceable\"";
    try expect_contains(try zero.request("debug_traceBlockByNumber", "[\"earliest\"]"), refused);
    // A later genesis has no transactions, so it has no traces, whatever the tracer.
    const h = try Harness.create_numbered(fixture.spec, 30_008_523);
    defer h.destroy();
    _ = try h.mine(1);
    const empty = "\"result\":[]";
    const limited = "[\"earliest\",{\"limit\":512}]";
    try expect_contains(try h.request("debug_traceBlockByNumber", limited), empty);
    const call_tracer = "[\"earliest\",{\"tracer\":\"callTracer\"}]";
    try expect_contains(try h.request("debug_traceBlockByNumber", call_tracer), empty);
    const genesis = &h.node.chain.genesis_hash;
    const plain = "{\"tracer\":\"prestateTracer\"}";
    try expect_contains(try trace_request(h, "debug_traceBlockByHash", genesis, plain), empty);
    // Its RLP is refused.
    var buffer: [4096]u8 = undefined;
    const raw_genesis = try h.request("debug_getRawBlock", "[\"earliest\"]");
    const raw = try result_data(raw_genesis, &buffer);
    var body: [4096]u8 = undefined;
    const format = request_prefix_format ++ "debug_traceBlock\",\"params\":[\"0x{x}\"]}}";
    const traced_raw = try h.request_runtime(try std.fmt.bufPrint(&body, format, .{raw}));
    try expect_contains(traced_raw, refused);
}

test "eth: call requests read as Nethermind's transaction converters" {
    const h = try Harness.create();
    defer h.destroy();
    // Access list keys of any digit count, items without `storageKeys`.
    const listed = "[{\"to\":" ++ address_target ++ ",\"accessList\":[{\"address\":" ++
        address_target ++ ",\"storageKeys\":[\"0x1\",\"0xabc\"]},{\"address\":" ++
        address_one ++ "},{\"address\":" ++ address_one ++ ",\"storageKeys\":null}]}]";
    try testing.expectEqualStrings("\"result\":\"0x\"", try h.request("eth_call", listed));
    const bare_key = "[{\"to\":" ++ address_target ++ ",\"accessList\":[{\"address\":" ++
        address_target ++ ",\"storageKeys\":[\"0x\"]}]}]";
    try expect_contains(try h.request("eth_call", bare_key), "-32602");
    // An authorization without r and s has a zero signature (no authority).
    const unsigned = "[{\"to\":" ++ address_target ++ ",\"authorizationList\":[{" ++
        "\"chainId\":\"0x2105\",\"address\":" ++ address_one ++ ",\"nonce\":\"0x0\"," ++
        "\"yParity\":\"0x0\"}]}]";
    try testing.expectEqualStrings("\"result\":\"0x\"", try h.request("eth_call", unsigned));
    // Override slot keys are numbers; override code of an odd digit count has a leading
    // zero nibble (0x0 is STOP).
    const slot_reader = "[{\"to\":" ++ override_target ++ "},\"latest\",{" ++ override_target ++
        ":{\"code\":\"0x60015460005260206000f3\",\"stateDiff\":{\"0x1\":\"0x" ++ zero_word ++
        "ff\"}}}]";
    try expect_contains(try h.request("eth_call", slot_reader), "ff\"");
    const odd_code = "[{\"to\":" ++ override_target ++ "},\"latest\",{" ++ override_target ++
        ":{\"code\":\"0x0\"}}]";
    try testing.expectEqualStrings("\"result\":\"0x\"", try h.request("eth_call", odd_code));
    // Call data stays strict: an odd digit count is refused, as Nethermind's input.
    const odd_input = "[{\"to\":" ++ address_target ++ ",\"input\":\"0x123\"}]";
    try expect_contains(try h.request("eth_call", odd_input), "-32602");
    // A deposit is no signable request; debug_traceCall takes a complete one only.
    const deposit = "[{\"to\":" ++ address_target ++ ",\"type\":\"0x7e\"}]";
    const refused = "{\"code\":-32602,\"message\":\"invalid argument 0\"";
    try expect_contains(try h.request("eth_call", deposit), refused);
    try expect_contains(try h.request("eth_estimateGas", deposit), refused);
    try expect_contains(try h.request("eth_createAccessList", deposit), refused);
    const tracer = "},\"latest\",{\"tracer\":\"callTracer\"}]";
    const no_source = "{\"code\":-32602,\"message\":\"Value cannot be null. " ++
        "(Parameter 'SourceHash')\"";
    try expect_contains(try h.request("debug_traceCall", deposit[0 .. deposit.len - 2] ++
        tracer), no_source);
    const sourced = "[{\"to\":" ++ address_target ++ ",\"type\":\"0x7e\",\"sourceHash\":\"0x" ++
        zeros_62 ++ "01\",\"from\":" ++ poor_sender;
    const no_value = "\"message\":\"Value cannot be null. (Parameter 'Value')\"";
    try expect_contains(try h.request("debug_traceCall", sourced ++ tracer), no_value);
    const complete = sourced ++ ",\"value\":\"0x0\",\"input\":\"0x\"";
    const traced = try h.request("debug_traceCall", complete ++ tracer);
    try expect_contains(traced, "\"result\":{\"type\":\"CALL\"");
    // eth_simulateV1 converts its calls the same way.
    const blocks = "[{\"blockStateCalls\":[{\"calls\":";
    const simulated = blocks ++ deposit ++ "}]}]";
    try expect_contains(try h.request("eth_simulateV1", simulated), no_source);
    const whole = blocks ++ complete ++ "}]}]}]";
    try expect_contains(try h.request("eth_simulateV1", whole), "\"status\":\"0x1\"");
    // A priced transfer from an unfunded sender exceeds its allowance (no 21000 shortcut).
    const unfunded = "[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ address_target;
    const exceeds = "{\"code\":-32000,\"message\":\"gas required exceeds allowance (0)\"";
    inline for (.{ "gasPrice", "maxFeePerGas" }) |field| {
        const priced = unfunded ++ ",\"" ++ field ++ "\":\"0x10000000000\"}]";
        try expect_contains(try h.request("eth_estimateGas", priced), exceeds);
    }
    const free = try h.request("eth_estimateGas", unfunded ++ "}]");
    try testing.expectEqualStrings("\"result\":\"0x5208\"", free);
}

fn fuzz_body(h: *Harness, body: []const u8) !void {
    var out: std.Io.Writer = .fixed(&h.out);
    const outcome = eth.Router.handle(&h.api, body, &out);
    if (outcome == .response) try json.validate(out.buffered());
}

const method_names = [_][]const u8{
    "eth_getBalance",
    "eth_getBlockByNumber",
    "eth_getLogs",
    "eth_call",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_getStorageAt",
    "eth_getTransactionReceipt",
    "eth_sendRawTransaction",
    "eth_sendRawTransactionSync",
    "eth_getBlockByHash",
    "eth_getProof",
    "miner_setMaxDASize",
    "debug_getRawHeader",
    "debug_getRawBlock",
    "debug_getRawReceipts",
    "debug_getRawTransaction",
    "eth_getBlockTransactionCountByNumber",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getUncleByBlockHashAndIndex",
    "web3_sha3",
    "txpool_status",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_uninstallFilter",
    "txpool_content",
    "txpool_contentFrom",
    "txpool_inspect",
    "miner_getMaxDASize",
    "miner_setGasLimit",
    "base_transactionStatus",
    "admin_dropTransaction",
    "admin_dropSenderTransactions",
    "eth_config",
    "debug_executePayload",
    "debug_proofsSyncStatus",
    "eth_createAccessList",
    "eth_simulateV1",
};
const param_pieces = [_][]const u8{
    "\"latest\"",
    "\"0x0\"",
    "\"0x1\"",
    "true",
    "null",
    "{}",
    "{\"to\":" ++ address_target ++ "}",
    address_one,
    "{\"blockHash\":\"0x00\"}",
    "[]",
    "\"pending\"",
    "{\"fromBlock\":\"earliest\",\"topics\":[null]}",
    "\"0x02\"",
    "1",
};

fn random_requests(h: *Harness, prng: *Prng) !void {
    var body: [1024]u8 = undefined;
    for (0..32) |_| {
        var writer: std.Io.Writer = .fixed(&body);
        const method = method_names[prng.below(method_names.len)];
        try writer.print(request_prefix_format ++ "{s}\",\"params\":[", .{method});
        const count = prng.below(4);
        for (0..count) |i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll(param_pieces[prng.below(param_pieces.len)]);
        }
        try writer.writeAll("]}");
        try fuzz_body(h, writer.buffered());
    }
}

test "eth: seeded fuzz of request shapes" {
    const h = try Harness.create();
    defer h.destroy();
    var prng = Prng.init(0xe7);
    try random_requests(h, &prng);
}

fn fuzz_eth(h: *Harness, smith: *testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    const len = smith.slice(&bytes);
    try fuzz_body(h, bytes[0..len]);
    var prng = Prng.init(smith.value(u64));
    try random_requests(h, &prng);
}

test "eth: fuzz" {
    const h = try Harness.create();
    defer h.destroy();
    try testing.fuzz(h, fuzz_eth, .{});
}

const denim_rpc_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    for (0..@backingInt(chainspec.Upgrade.denim) + 1) |index| result.upgrades[index] = 0;
    break :blk result;
};

test "eth: Denim blocks, transactions and logs report millisecond timestamps" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    // Block 1 is 200 ms after genesis (time 0): the BaseTime deposit at index 1.
    var calldata = [2][consensus.base_time.calldata_length]u8{
        consensus.base_time.encode_calldata(0),
        consensus.base_time.encode_calldata(200),
    };
    var info = consensus.base_time.deposit(1, &calldata[0]);
    info.source_hash = .{ .bytes = @splat(0x11) };
    info.to = .{ .call = .{ .bytes = @splat(0x11) } };
    const deposits = [2]consensus.Envelope{
        .{ .deposit = info },
        .{ .deposit = consensus.base_time.deposit(1, &calldata[1]) },
    };
    var encoded: [2][256]u8 = undefined;
    const forced = [2][]const u8{
        deposits[0].encode_to(&encoded[0]),
        deposits[1].encode_to(&encoded[1]),
    };
    var attrs = fixture.attributes_l2(0, 0xfe);
    attrs.transactions = &forced;
    const node = h.node;
    const genesis: primitives.B256 = .{ .bytes = node.chain.genesis_hash };
    const version = engine_types.forkchoice_version(&denim_rpc_spec, 0);
    const choice = fixture.forkchoice(genesis);
    const updated = try node.engine.forkchoice_updated(version, choice, &attrs);
    const get_version = engine_types.get_payload_version(&denim_rpc_spec, 0);
    const built = try node.engine.get_payload(get_version, updated.payload_id.?);
    _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(built.block_hash), null);
    const block = try h.request("eth_getBlockByNumber", "[\"0x1\",true]");
    try expect_contains(block, "\"timestamp\":\"0x0\"");
    try expect_contains(block, "\"timestampMs\":\"0xc8\"");
    try expect_contains(block, "\"blockTimestampMs\":\"0xc8\"");
    const tx_hash = primitives.keccak256(forced[1]).bytes;
    var body: [256]u8 = undefined;
    const format = request_prefix_format ++ "eth_getTransactionByHash\",\"params\":[\"0x{x}\"]}}";
    const tx = try h.request_runtime(try std.fmt.bufPrint(&body, format, .{&tx_hash}));
    try expect_contains(tx, "\"blockTimestampMs\":\"0xc8\"");
    // Genesis has no BaseTime deposit: no millisecond fields.
    const genesis_block = try h.request("eth_getBlockByNumber", "[\"0x0\",false]");
    try testing.expect(std.mem.indexOf(u8, genesis_block, "timestampMs") == null);
}

/// Mines a block holding `deposit` alone on the harness head (timestamp 4, coinbase 0xfe..),
/// then six more; returns the deposit's block hash.
fn mine_deposit(h: *Harness, deposit: consensus.Envelope, raw: *[256]u8) !primitives.B256 {
    const forced = [1][]const u8{deposit.encode_to(raw)};
    var attrs = fixture.attributes_l2(4, 0xfe);
    attrs.transactions = &forced;
    const node = h.node;
    const head: primitives.B256 = .{ .bytes = node.chain.head_hash() };
    const version = engine_types.forkchoice_version(node.spec, 4);
    const updated = try node.engine.forkchoice_updated(version, fixture.forkchoice(head), &attrs);
    const get_version = engine_types.get_payload_version(node.spec, 4);
    const built = try node.engine.get_payload(get_version, updated.payload_id.?);
    _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(built.block_hash), null);
    _ = try h.mine(6);
    return built.block_hash;
}

fn deposit_to(to: [20]u8, gas_limit: u64) consensus.Envelope {
    return .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(0x22) },
        .from = .{ .bytes = @splat(0xd0) },
        .to = .{ .call = .{ .bytes = to } },
        .mint = 0,
        .value = 0,
        .gas_limit = gas_limit,
        .is_system_transaction = false,
        .input = &.{},
    } };
}

/// A harness on Denim with history for tracing; 0x55.. (nonce 60) is delegated to 0x33..,
/// which CALLs 0x44.. (nonce 1, no code) and then loops until out of gas.
fn failing_deposit_harness(store: *history_module.Store) !*Harness {
    const h = try Harness.create_for(&denim_rpc_spec);
    errdefer h.destroy();
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(store);
    const callee_code = [_]u8{ 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73 } ++
        @as([20]u8, @splat(0x44)) ++ [_]u8{ 0x61, 0xff, 0xff, 0xf1, 0x50, 0x5b, 0x60, 0x24, 0x56 };
    try h.node.db.put_account(@splat(0x33), 0, 1, &callee_code);
    try h.node.db.put_account(@splat(0x44), 0, 1, &.{});
    const delegation = [_]u8{ 0xef, 0x01, 0x00 } ++ @as([20]u8, @splat(0x33));
    try h.node.db.put_account(@splat(0x55), 0, 60, &delegation);
    _ = try h.mine(2);
    return h;
}

/// Mines `deposit`, checks it failed with its whole gas limit and returns its prestate.
fn failed_deposit_prestate(h: *Harness, deposit: consensus.Envelope) ![]const u8 {
    return failed_deposit_trace(h, deposit, "{\"tracer\":\"prestateTracer\"}");
}

/// Mines `deposit`, checks it failed with its whole gas limit and traces it with `config`.
fn failed_deposit_trace(
    h: *Harness,
    deposit: consensus.Envelope,
    config: []const u8,
) ![]const u8 {
    var raw: [256]u8 = undefined;
    _ = try mine_deposit(h, deposit, &raw);
    const hash = primitives.keccak256(deposit.encode_to(&raw)).bytes;
    const receipt_format = request_prefix_format ++
        "eth_getTransactionReceipt\",\"params\":[\"0x{x}\"]}}";
    var body: [256]u8 = undefined;
    const receipt = try h.request_runtime(try std.fmt.bufPrint(&body, receipt_format, .{&hash}));
    try expect_contains(receipt, "\"status\":\"0x0\"");
    var gas_used: [32]u8 = undefined;
    const gas_limit = deposit.deposit.gas_limit;
    const gas_used_text = "\"gasUsed\":\"0x{x}\"";
    try expect_contains(receipt, try std.fmt.bufPrint(&gas_used, gas_used_text, .{gas_limit}));
    return trace_request(h, "debug_traceTransaction", &hash, config);
}

test "eth: prestateTracer lists the beneficiary for a deposit" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    // The beneficiary is not empty; a deposit pays it nothing, yet Nethermind looks it up.
    try h.node.db.put_account(@splat(0xfe), 1, 0, &.{});
    _ = try h.mine(2);
    var raw: [256]u8 = undefined;
    const block_hash = try mine_deposit(h, deposit_to(@splat(0x33), 100_000), &raw);
    const coinbase = "\"0xfefefefefefefefefefefefefefefefefefefefe\":{\"balance\":\"0x1\"}";
    const plain = "{\"tracer\":\"prestateTracer\"}";
    const traced = try trace_request(h, "debug_traceBlockByHash", &block_hash.bytes, plain);
    try testing.expectEqual(@as(usize, 1), count_of(traced, "\"txHash\""));
    try expect_contains(traced, coinbase);
    const hash = primitives.keccak256(deposit_to(@splat(0x33), 100_000).encode_to(&raw)).bytes;
    try expect_contains(try trace_request(h, "debug_traceTransaction", &hash, plain), coinbase);
    // Unchanged, it is not in a diff.
    const diff = "{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}";
    const changes = try trace_request(h, "debug_traceTransaction", &hash, diff);
    try testing.expect(std.mem.indexOf(u8, changes, "0xfefefefe") == null);
}

const callee_pre = "\"0x5555555555555555555555555555555555555555\":{" ++
    "\"balance\":\"0x0\",\"nonce\":60,";
const delegate_pre = "\"0x3333333333333333333333333333333333333333\":{\"balance\"";
const inner_pre = "\"0x4444444444444444444444444444444444444444\":{" ++
    "\"balance\":\"0x0\",\"nonce\":1}";

test "eth: prestateTracer keeps what a deposit loaded before running out of gas" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    const traced = try failed_deposit_prestate(h, deposit_to(@splat(0x55), 100_000));
    try expect_contains(traced, callee_pre);
    try expect_contains(traced, delegate_pre);
    try expect_contains(traced, inner_pre);
}

test "eth: prestateTracer lists the callee of a deposit that cannot pay its value" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    var deposit = deposit_to(@splat(0x55), 100_000);
    deposit.deposit.mint = 1;
    deposit.deposit.value = 2;
    const traced = try failed_deposit_prestate(h, deposit);
    try expect_contains(traced, callee_pre);
    try expect_contains(traced, delegate_pre);
}

test "eth: callTracer gives a failed deposit revm-inspectors' top frame" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    // The first frame starts and fails its transfer (geth's top frame, as base gives it):
    // gas and gasUsed are the gas limit, the receipt's.
    var deposit = deposit_to(@splat(0x55), 100_000);
    deposit.deposit.mint = 1;
    deposit.deposit.value = 2;
    deposit.deposit.input = &.{ 0x82, 0x4b, 0xb8, 0x45, 0x01, 0x02 };
    const call_tracer = "{\"tracer\":\"callTracer\"}";
    const unfunded = try failed_deposit_trace(h, deposit, call_tracer);
    try expect_contains(unfunded, "\"result\":{\"type\":\"CALL\",\"from\":\"0x" ++
        "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0\",\"to\":\"0x" ++
        "5555555555555555555555555555555555555555\",\"value\":\"0x2\",\"gas\":\"0x186a0\"," ++
        "\"gasUsed\":\"0x186a0\",\"input\":\"0x824bb8450102\",\"error\":" ++
        "\"insufficient balance for transfer\"}");
    var raw: [256]u8 = undefined;
    const hash = primitives.keccak256(deposit.encode_to(&raw)).bytes;
    const four_byte = "{\"tracer\":\"4byteTracer\"}";
    const selectors = try trace_request(h, "debug_traceTransaction", &hash, four_byte);
    try expect_contains(selectors, "\"result\":{\"0x824bb845-2\":1}");
}

test "eth: callTracer gives a call that cannot pay its value its top frame" {
    const h = try Harness.create();
    defer h.destroy();
    // geth's EVM.Call enters the frame before its balance check, and revm's first frame
    // fails the transfer: the tracers see the frame; gasUsed is the calldata floor here.
    const call = "[{\"to\":\"0x00000000000000000000000000000000000000aa\",\"value\":\"0xef\"," ++
        "\"gas\":\"0x186a0\",\"input\":\"0x12345678\"},\"latest\",";
    const traced = try h.request("debug_traceCall", call ++ "{\"tracer\":\"callTracer\"}]");
    try expect_contains(traced, "\"result\":{\"type\":\"CALL\",\"from\":\"0x" ++
        "0000000000000000000000000000000000000000\",\"to\":\"0x" ++
        "00000000000000000000000000000000000000aa\"," ++
        "\"value\":\"0xef\",\"gas\":\"0x186a0\",\"gasUsed\":\"0x52a8\",\"input\":" ++
        "\"0x12345678\",\"error\":\"insufficient balance for transfer\"}");
    const selectors = try h.request("debug_traceCall", call ++ "{\"tracer\":\"4byteTracer\"}]");
    try expect_contains(selectors, "\"result\":{\"0x12345678-0\":1}");
    const flat = try h.request("debug_traceCall", call ++ "{\"tracer\":\"flatCallTracer\"}]");
    try expect_contains(flat, "\"error\":\"Insufficient balance for transfer\"");
    try testing.expectEqual(@as(usize, 1), count_of(flat, "\"traceAddress\""));
}

test "eth: callTracer gives a creation that cannot pay its value a frame without to" {
    const h = try Harness.create();
    defer h.destroy();
    // geth's `processOutput` (and revm-inspectors) clear a failed CREATE's `to`; gasUsed is
    // the intrinsic gas: 53000 plus the initcode word cost.
    const call = "[{\"value\":\"0xef\",\"gas\":\"0x186a0\",\"input\":\"0x6001600055\"}," ++
        "\"latest\",";
    const traced = try h.request("debug_traceCall", call ++ "{\"tracer\":\"callTracer\"}]");
    try expect_contains(traced, "\"result\":{\"type\":\"CREATE\",\"from\":\"0x" ++
        "0000000000000000000000000000000000000000\",\"value\":\"0xef\",\"gas\":\"0x186a0\"," ++
        "\"gasUsed\":\"0xcf4e\",\"input\":\"0x6001600055\",\"error\":" ++
        "\"insufficient balance for transfer\"}");
    const selectors = try h.request("debug_traceCall", call ++ "{\"tracer\":\"4byteTracer\"}]");
    try expect_contains(selectors, "\"result\":{}");
    const flat = try h.request("debug_traceCall", call ++ "{\"tracer\":\"flatCallTracer\"}]");
    try expect_contains(flat, "\"error\":\"Insufficient balance for transfer\"");
    try expect_contains(flat, "\"creationMethod\":\"create\"");
    try testing.expect(std.mem.indexOf(u8, flat, "\"address\"") == null);
}

test "eth: callTracer gives a deposit rejected before any frame a frame from the tx" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    // A system deposit after Regolith enters no frame: geth's (and Nethermind's) frame is
    // built from the transaction, and no selector is counted.
    var deposit = deposit_to(@splat(0x55), 100_000);
    deposit.deposit.is_system_transaction = true;
    deposit.deposit.input = &.{ 0x82, 0x4b, 0xb8, 0x45, 0x01, 0x02 };
    const call_tracer = "{\"tracer\":\"callTracer\"}";
    const system = try failed_deposit_trace(h, deposit, call_tracer);
    try expect_contains(system, "\"result\":{\"type\":\"CALL\",\"from\":\"0x" ++
        "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0\",\"to\":\"0x" ++
        "5555555555555555555555555555555555555555\",\"value\":\"0x0\",\"gas\":\"0x186a0\"," ++
        "\"gasUsed\":\"0x186a0\",\"input\":\"0x824bb8450102\",\"error\":" ++
        "\"failed deposit: system deposit after Regolith\"}");
    var raw: [256]u8 = undefined;
    const hash = primitives.keccak256(deposit.encode_to(&raw)).bytes;
    const four_byte = "{\"tracer\":\"4byteTracer\"}";
    const selectors = try trace_request(h, "debug_traceTransaction", &hash, four_byte);
    try expect_contains(selectors, "\"result\":{}");
    const flat = "{\"tracer\":\"flatCallTracer\"}";
    const flat_traces = try trace_request(h, "debug_traceTransaction", &hash, flat);
    try expect_contains(flat_traces, "\"error\":\"failed deposit: system deposit after Regolith\"");
    try testing.expectEqual(@as(usize, 1), count_of(flat_traces, "\"traceAddress\""));
}

test "eth: callTracer gives a deposit below its intrinsic gas a frame from the tx" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    const call_tracer = "{\"tracer\":\"callTracer\"}";
    const low = try failed_deposit_trace(h, deposit_to(@splat(0x55), 20_000), call_tracer);
    try expect_contains(low, "\"result\":{\"type\":\"CALL\",\"from\":\"0x" ++
        "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0\",\"to\":\"0x" ++
        "5555555555555555555555555555555555555555\",\"value\":\"0x0\",\"gas\":\"0x4e20\"," ++
        "\"gasUsed\":\"0x4e20\",\"input\":\"0x\",\"error\":" ++
        "\"failed deposit: intrinsic gas too low\"}");
}

test "eth: prestateTracer lists the callee of a deposit below its intrinsic gas" {
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    const h = try failing_deposit_harness(&store);
    defer h.destroy();
    // Nethermind looks up the callee and its delegate before any check; nothing runs.
    const traced = try failed_deposit_prestate(h, deposit_to(@splat(0x55), 20_000));
    try expect_contains(traced, callee_pre);
    try expect_contains(traced, delegate_pre);
    try testing.expect(std.mem.indexOf(u8, traced, "0x44444444") == null);
}

test "eth: pre-Denim blocks carry no millisecond timestamps" {
    const h = try Harness.create();
    defer h.destroy();
    _ = try h.mine(12);
    const block = try h.request("eth_getBlockByNumber", "[\"0x1\",true]");
    try testing.expect(std.mem.indexOf(u8, block, "timestampMs") == null);
}

fn transfer_raw(buffer: []u8, nonce: u64) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = fixture.spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 21_000,
        .to = .{ .call = fixture.address_of(9) },
        .value = 77,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    return envelope.encode_to(buffer);
}

fn send_sync_raw(h: *Harness, raw: []const u8, timeout: []const u8) ![]const u8 {
    var body: [1024]u8 = undefined;
    const format = request_prefix_format ++
        "eth_sendRawTransactionSync\",\"params\":[\"0x{x}\"{s}]}}";
    const request = try std.fmt.bufPrint(&body, format, .{ raw, timeout });
    var out: std.Io.Writer = .fixed(&h.out);
    _ = eth.Router.handle(&h.api, request, &out);
    try json.validate(out.buffered());
    return out.buffered();
}

test "eth: sendRawTransactionSync hands a single call's transaction to the transport" {
    const h = try Harness.create();
    defer h.destroy();
    var raw_buffer: [256]u8 = undefined;
    const raw = try transfer_raw(&raw_buffer, 0);
    // No transport support: the method is unavailable and nothing is submitted.
    try expect_contains(try send_sync_raw(h, raw, ""), "unavailable");
    try testing.expectEqual(@as(u32, 0), h.node.pool.count());
    var request: send_sync.Request = .{ .timeout_ms_max = 25_000 };
    h.api.sync = &request;
    // A batch (or no free slot) is refused before submission.
    request.prepare(false, true);
    try expect_contains(try send_sync_raw(h, raw, ""), "in a batch");
    request.prepare(true, false);
    try expect_contains(try send_sync_raw(h, raw, ""), "too many pending");
    try testing.expectEqual(@as(u32, 0), h.node.pool.count());
    try testing.expect(request.hash == null);
    // A shorter requested timeout applies; the hash is the fallback result.
    request.prepare(true, true);
    try expect_contains(try send_sync_raw(h, raw, ",500"), "\"result\":\"0x");
    try testing.expectEqual(@as(u32, 1), h.node.pool.count());
    try testing.expectEqualSlices(u8, &primitives.keccak256(raw).bytes, &request.hash.?);
    try testing.expectEqual(@as(u64, 500), request.timeout_ms);
    // A longer one is capped; the second (nonce 1) transaction also enters the pool.
    const next = try transfer_raw(&raw_buffer, 1);
    request.prepare(true, true);
    try expect_contains(try send_sync_raw(h, next, ",\"0xf4240\""), "\"result\":\"0x");
    try testing.expectEqual(@as(u64, 25_000), request.timeout_ms);
    // Invalid transactions fail like eth_sendRawTransaction and are not parked.
    request.prepare(true, true);
    try expect_contains(try send_sync_raw(h, next, ""), "\"error\"");
    try testing.expect(request.hash == null);
    // Once mined, the receipt the transport answers with is the canonical one.
    _ = try h.mine(12);
    var out: std.Io.Writer = .fixed(&h.out);
    const hash = primitives.keccak256(raw).bytes;
    try testing.expect(send_sync.write_included(&h.api, &out, "7", hash));
    try json.validate(out.buffered());
    try expect_contains(out.buffered(), "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{");
    try expect_contains(out.buffered(), "\"status\":\"0x1\"");
}

test "eth: calls without gas default under the Osaka per-transaction cap" {
    // Every Base upgrade active: Osaka (EIP-7825) applies; the block limit is 30M > 2^24.
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    const to = "\"to\":\"0x00000000000000000000000000000000deadbeef\"";
    const call_result = try h.request("eth_call", "[{" ++ to ++ "},\"latest\"]");
    try expect_contains(call_result, "\"result\":\"0x\"");
    const estimate = try h.request("eth_estimateGas", "[{" ++ to ++ "}]");
    try expect_contains(estimate, "\"result\":\"0x5208\"");
    // An explicit gas above the cap runs: reth lifts the cap for calls.
    const over = try h.request("eth_call", "[{" ++ to ++ ",\"gas\":\"0x1c9c380\"},\"latest\"]");
    try expect_contains(over, "\"result\":\"0x\"");
    const head = h.node.chain.header(h.node.chain.head_hash()).?;
    const env = chain_module.env_of(&head);
    try testing.expect(head.gas_limit > 1 << 24);
    try testing.expectEqual(@as(u64, 1 << 24), h.node.chain.executor.default_call_gas(&env));
}

test "eth: pre-Osaka calls without gas default to the block gas limit" {
    const h = try Harness.create();
    defer h.destroy();
    const head = h.node.chain.header(h.node.chain.head_hash()).?;
    const env = chain_module.env_of(&head);
    try testing.expectEqual(head.gas_limit, h.node.chain.executor.default_call_gas(&env));
}

test "eth: getTransactionCount reads EIP-8130 channel nonces by nonce key" {
    const h = try Harness.create();
    defer h.destroy();
    const native = @import("../evm/native.zig");
    const owner = fixture.address_of(1).bytes;
    const slot = native.nonce_slot(owner, 5);
    try h.node.db.put_account(native.nonce_manager_address, 0, 0, &.{0x00});
    try h.node.db.put_storage(native.nonce_manager_address, slot, 7);
    const prefix = "[\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\",\"latest\"";
    try testing.expectEqualStrings("\"result\":\"0x7\"", try h.request(
        "eth_getTransactionCount",
        prefix ++ ",\"0x5\"]",
    ));
    // Key zero (or none) is the protocol nonce; an unused channel is zero.
    try testing.expectEqualStrings("\"result\":\"0x0\"", try h.request(
        "eth_getTransactionCount",
        prefix ++ ",\"0x0\"]",
    ));
    try testing.expectEqualStrings("\"result\":\"0x0\"", try h.request(
        "eth_getTransactionCount",
        prefix ++ ",\"0x6\"]",
    ));
    const max_key = ",\"0x" ++ @as([64]u8, @splat('f')) ++ "\"]";
    try expect_contains(try h.request("eth_getTransactionCount", prefix ++ max_key), "-32602");
}

test "eth: EIP-8130 eth_call and eth_estimateGas simulate 0x79 requests" {
    everest_spec.upgrades = @splat(0);
    const h = try Harness.create_for(&everest_spec);
    defer h.destroy();
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    const reverter = primitives.hex.decode_array(20, reverter_at[3..43]) catch unreachable;
    try h.node.db.put_account(reverter, 0, 0, &.{ 0x5f, 0x5f, 0xfd });
    const from = "\"from\":" ++ address_one;
    const phases = ",\"calls\":[[{\"to\":" ++ counter_at ++ ",\"data\":\"0x\"}]]";
    const one = "\"0x0000000000000000000000000000000000000000000000000000000000000001\"";
    try expect_contains(try h.request("eth_call", "[{" ++ from ++ phases ++ "},\"latest\"]"), one);
    // A single call from `to`, made EIP-8130 by `nonceKey`.
    const single = "[{" ++ from ++ ",\"to\":" ++ counter_at ++ ",\"nonceKey\":\"0x7\"}]";
    try expect_contains(try h.request("eth_call", single), one);
    const estimate = try h.request("eth_estimateGas", "[{" ++ from ++ phases ++ "}]");
    try expect_contains(estimate, "\"result\":\"0x");
    const reverts = "[{" ++ from ++ ",\"type\":\"0x79\",\"to\":" ++ reverter_at ++ "}]";
    try expect_contains(try h.request("eth_call", reverts), "execution reverted");
    try expect_contains(try h.request("eth_estimateGas", reverts), "execution reverted");
    // Invalid requests.
    const both = "[{" ++ from ++ ",\"to\":" ++ counter_at ++ phases ++ "}]";
    try expect_contains(try h.request("eth_call", both), "CallsAndSingleCall");
    const no_sender = "[{\"nonceKey\":\"0x1\",\"to\":" ++ counter_at ++ "}]";
    try expect_contains(try h.request("eth_call", no_sender), "MissingSender");
    const mismatch = "[{" ++ from ++ ",\"sender\":" ++ counter_at ++ phases ++ "}]";
    try expect_contains(try h.request("eth_call", mismatch), "SenderFromMismatch");
    // A plain request still takes the plain path.
    try expect_contains(try h.request("eth_call", "[{\"to\":" ++ counter_at ++ "}]"), one);
}

test "eth: EIP-8130 requests are refused before Everest" {
    const h = try Harness.create();
    defer h.destroy();
    const request = "[{\"from\":" ++ address_one ++ ",\"type\":\"0x79\",\"to\":" ++
        address_target ++ "}]";
    try expect_contains(try h.request("eth_call", request), "not active before Everest");
}

/// Advances one microsecond per read.
const StepClock = struct {
    now_ns: u64 = 0,

    fn read(context: *anyopaque) u64 {
        const clock: *StepClock = @ptrCast(@alignCast(context));
        clock.now_ns += std.time.ns_per_us;
        return clock.now_ns;
    }
};

fn meter_scenario(h: *Harness, transfers: u64, timestamp: u64, nonce: *u64) !void {
    var buffers: [8][256]u8 = undefined;
    for (0..transfers) |index| {
        const raw = try transfer_raw(&buffers[index], nonce.*);
        nonce.* += 1;
        try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    }
    const hash = try h.mine(timestamp);
    const by_number = try h.request("base_meterBlockByNumber", "[\"latest\"]");
    try expect_contains(by_number, "\"signerRecoveryTimeUs\":");
    try expect_contains(by_number, "\"stateRootTimeUs\":0");
    try testing.expectEqual(@as(usize, transfers), count_of(by_number, "\"gasUsed\":21000"));
    var body: [256]u8 = undefined;
    const format = request_prefix_format ++ "base_meterBlockByHash\",\"params\":[\"0x{x}\"]}}";
    const request = try std.fmt.bufPrint(&body, format, .{&hash.bytes});
    const by_hash = try h.request_runtime(request);
    try testing.expectEqual(@as(usize, transfers), count_of(by_hash, "\"gasUsed\":21000"));
}

fn meter_history() !history_module.Store {
    return history_module.Store.init(testing.allocator, .{
        .window_blocks = 8,
        .paths_max = 1 << 12,
        .small_versions_max = 1 << 12,
        .large_versions_max = 1 << 10,
        .prune_per_commit = 256,
    });
}

test "eth: base_meterBlock re-executes a block and times its transactions" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    _ = try h.mine(12); // History starts here: block 2's parent is in it.
    var clock: StepClock = .{};
    h.api.clock = .{ .context = &clock, .now_ns = StepClock.read };
    var nonce: u64 = 0;
    try meter_scenario(h, 2, 24, &nonce);
    // Each transfer's execution reads the clock twice: one microsecond each.
    const latest = try h.request("base_meterBlockByNumber", "[\"latest\"]");
    try testing.expectEqual(@as(usize, 2), count_of(latest, "\"executionTimeUs\":1}"));
    try expect_contains(latest, "\"blockNumber\":2,");
    // The state is untouched: the head still serves reads, and the next block builds.
    try meter_scenario(h, 1, 36, &nonce);
    // Genesis has no parent; an unknown block is not found.
    try expect_contains(try h.request("base_meterBlockByNumber", "[\"0x0\"]"), "genesis");
    const unknown = "[\"0x" ++ @as([64]u8, @splat('a')) ++ "\"]";
    try expect_contains(try h.request("base_meterBlockByHash", unknown), "block not found");
}

test "eth: seeded fuzz of base_meterBlock over random blocks" {
    var prng = Prng.init(0x6d65);
    for (0..4) |_| {
        const h = try Harness.create();
        defer h.destroy();
        var store = try meter_history();
        defer store.deinit(testing.allocator);
        try h.node.db.trie().track_changes(testing.allocator);
        try h.node.chain.attach_history(&store);
        _ = try h.mine(12);
        var nonce: u64 = 0;
        var timestamp: u64 = 24;
        for (0..prng.range(1, 3)) |_| {
            try meter_scenario(h, prng.below(4), timestamp, &nonce);
            timestamp += 12;
        }
    }
}

fn meter_bundle_request(h: *Harness, raws: []const []const u8) ![]const u8 {
    var body: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&body);
    try writer.writeAll(request_prefix ++ "base_meterBundle\",\"params\":[{\"txs\":[");
    for (raws, 0..) |raw, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("\"0x{x}\"", .{raw});
    }
    try writer.writeAll("]}]}");
    return h.request_runtime(writer.buffered());
}

test "eth: base_meterBundle meters a bundle ahead of the sender's nonce" {
    const h = try Harness.create();
    defer h.destroy();
    var buffers: [2][256]u8 = undefined;
    const raws = [_][]const u8{
        try transfer_raw(&buffers[0], 5),
        try transfer_raw(&buffers[1], 6),
    };
    const text = try meter_bundle_request(h, &raws);
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"gasUsed\":21000"));
    try expect_contains(text, "\"totalGasUsed\":42000");
    try expect_contains(text, "\"stateBlockNumber\":0");
    // gasUsed * maxFeePerGas (10 gwei).
    try expect_contains(text, "\"gasFees\":\"0x17dfcdece4000\"");
    try expect_contains(text, "\"bundleGasPrice\":\"0x2540be400\"");
    var hashes: [64]u8 = undefined;
    hashes[0..32].* = primitives.keccak256(raws[0]).bytes;
    hashes[32..64].* = primitives.keccak256(raws[1]).bytes;
    var expected: [96]u8 = undefined;
    const bundle_hash = try std.fmt.bufPrint(&expected, "\"bundleHash\":\"0x{x}\"", .{
        &primitives.keccak256(&hashes).bytes,
    });
    try expect_contains(text, bundle_hash);
    // Nothing committed: the sender's nonce is unchanged.
    const count = "[" ++ "\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\",\"latest\"]";
    try testing.expectEqualStrings("\"result\":\"0x0\"", try h.request(
        "eth_getTransactionCount",
        count,
    ));
    // Too far ahead of the sender's nonce.
    const far = [_][]const u8{try transfer_raw(&buffers[0], 20_000)};
    try expect_contains(try meter_bundle_request(h, &far), "InvalidTransaction");
    // An empty bundle meters nothing; malformed bundles are invalid params.
    try expect_contains(try meter_bundle_request(h, &.{}), "\"totalGasUsed\":0");
    try expect_contains(try h.request("base_meterBundle", "[{}]"), "-32602");
    try expect_contains(try h.request("base_meterBundle", "[{\"txs\":[\"0x7e\"]}]"), "-32602");
    try expect_contains(try h.request("base_meterBundle", "[{\"txs\":1}]"), "-32602");
    // base/base decodes every transaction before metering (`ParsedBundle::try_from`).
    const undecodable = try h.request("base_meterBundle", "[{\"txs\":[\"0xc20180\"]}]");
    try expect_contains(undecodable, "-32602");
    try expect_contains(undecodable, "Failed to decode transaction");
    // serde refuses null for the `full` flag; leaving it out reads as false.
    const null_full = try h.request("eth_getBlockByNumber", "[\"latest\",null]");
    try expect_contains(null_full, "-32602");
    try expect_contains(try h.request("eth_getBlockByNumber", "[\"latest\"]"), "\"result\":{");
}

test "eth: seeded fuzz of base_meterBundle nonces" {
    var prng = Prng.init(0x6275);
    const h = try Harness.create();
    defer h.destroy();
    for (0..16) |_| {
        var buffers: [4][256]u8 = undefined;
        var raws: [4][]const u8 = undefined;
        const count = prng.range(1, 4);
        const start = prng.below(12_000);
        for (raws[0..count], 0..) |*raw, index| {
            // Mostly consecutive; sometimes a gap, which fails at execution.
            const gap: u64 = if (prng.chance(1, 8)) 1 else 0;
            raw.* = try transfer_raw(&buffers[index], start + index + gap);
        }
        const text = try meter_bundle_request(h, raws[0..count]);
        const ok = std.mem.indexOf(u8, text, "\"result\"") != null;
        if (start > 10_000) try testing.expect(!ok);
        if (ok) try testing.expectEqual(count, count_of(text, "\"gasUsed\":21000"));
    }
}

fn contract_call_raw(buffer: []u8, nonce: u64, to: [20]u8) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = fixture.spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 200_000,
        .to = .{ .call = .{ .bytes = to } },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    return envelope.encode_to(buffer);
}

fn trace_request(
    h: *Harness,
    method: []const u8,
    hash: []const u8,
    config: []const u8,
) ![]const u8 {
    var body: [512]u8 = undefined;
    const format = request_prefix_format ++ "{s}\",\"params\":[\"0x{x}\",{s}]}}";
    return h.request_runtime(try std.fmt.bufPrint(&body, format, .{ method, hash, config }));
}

test "eth: debug_trace callTracer reports nested calls, logs and reverts" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    const reverter = primitives.hex.decode_array(20, reverter_at[3..43]) catch unreachable;
    try h.node.db.put_account(reverter, 0, 0, &.{ 0x5f, 0x5f, 0xfd });
    // CALL(gas, counter, 0, 0, 0, 0, 0); STOP.
    const caller: [20]u8 = @splat(0x57);
    const caller_code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73 } ++ counter ++
        [_]u8{ 0x5a, 0xf1, 0x00 };
    try h.node.db.put_account(caller, 0, 0, &caller_code);
    _ = try h.mine(12);
    var buffers: [2][256]u8 = undefined;
    const nested = try contract_call_raw(&buffers[0], 0, caller);
    const reverting = try contract_call_raw(&buffers[1], 1, reverter);
    try expect_contains(try send_raw(h, nested), "\"result\":\"0x");
    try expect_contains(try send_raw(h, reverting), "\"result\":\"0x");
    const block = try h.mine(24);
    const call_tracer = "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"withLog\":true}}";
    const nested_hash = primitives.keccak256(nested).bytes;
    const text = try trace_request(h, "debug_traceTransaction", &nested_hash, call_tracer);
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"type\":\"CALL\""));
    // A CALL reports its value even when zero.
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"value\":\"0x0\""));
    try expect_contains(text, "\"calls\":[{");
    try expect_contains(text, "\"gas\":\"0x30d40\""); // The transaction's gas limit.
    try expect_contains(text, "\"logs\":[{");
    try expect_contains(text, "\"position\":\"0x0\"");
    const top_only = "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"onlyTopCall\":true}}";
    const top = try trace_request(h, "debug_traceTransaction", &nested_hash, top_only);
    try testing.expect(std.mem.indexOf(u8, top, "calls") == null);
    const reverting_hash = primitives.keccak256(reverting).bytes;
    const reverted = try trace_request(h, "debug_traceTransaction", &reverting_hash, call_tracer);
    try expect_contains(reverted, "\"error\":\"execution reverted\"");
    const by_hash = try trace_request(h, "debug_traceBlockByHash", &block.bytes, call_tracer);
    try testing.expectEqual(@as(usize, 2), count_of(by_hash, "\"txHash\""));
    const by_number = try h.request(
        "debug_traceBlockByNumber",
        "[\"latest\",{\"tracer\":\"callTracer\"}]",
    );
    try testing.expectEqual(@as(usize, 2), count_of(by_number, "\"txHash\""));
    // No tracer: geth's struct logger, one frame per transaction.
    const default = try h.request("debug_traceBlockByNumber", "[\"latest\"]");
    try testing.expectEqual(@as(usize, 2), count_of(default, "\"structLogs\":[{"));
    try testing.expectEqual(@as(usize, 2), count_of(default, "\"txHash\""));
    // The most common call: a transaction with no options. The CALL forwards all but 1/64
    // of the gas left after its 2600 (cold account); the counter runs at depth 2.
    const logs = try trace_request(h, "debug_traceTransaction", &nested_hash, "{}");
    try expect_contains(logs, "{\"failed\":false,\"gas\":46377,\"returnValue\":\"0x\",");
    try expect_contains(logs, "{\"pc\":27,\"op\":\"CALL\",\"gas\":178985," ++
        "\"gasCost\":176229,\"depth\":1,");
    try expect_contains(logs, "{\"pc\":0,\"op\":\"PUSH0\",\"gas\":173629,\"gasCost\":2," ++
        "\"depth\":2,\"stack\":[],\"refund\":0}");
    try expect_contains(logs, "{\"pc\":28,\"op\":\"STOP\",\"gas\":153623,\"gasCost\":0," ++
        "\"depth\":1,\"stack\":[\"0x1\"],\"refund\":0}]}");
    // flatCallTracer locates each trace in the block.
    const flat = "{\"tracer\":\"flatCallTracer\"}";
    const flat_text = try trace_request(h, "debug_traceTransaction", &reverting_hash, flat);
    var block_hash: [2 + 64]u8 = undefined;
    _ = try std.fmt.bufPrint(&block_hash, "0x{x}", .{&block.bytes});
    try expect_contains(flat_text, "\"blockHash\":\"");
    try expect_contains(flat_text, &block_hash);
    try expect_contains(flat_text, "\"error\":\"Reverted\",\"result\":{\"gasUsed\":\"0x4\"," ++
        "\"output\":\"0x\"},\"subtraces\":0,\"traceAddress\":[],\"transactionHash\":\"");
    try expect_contains(flat_text, "\"transactionPosition\":1,\"type\":\"call\"}]");
}

test "eth: debug_trace replays BLOCKHASH of a block the head's ring has dropped" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    // SSTORE(0, BLOCKHASH(NUMBER - 255)); STOP.
    const target: [20]u8 = @splat(0x5b);
    try h.node.db.put_account(target, 0, 0, &.{ 0x60, 0xff, 0x43, 0x03, 0x40, 0x5f, 0x55, 0x00 });
    var timestamp: u64 = 0;
    for (0..256) |_| {
        timestamp += 12;
        _ = try h.mine(timestamp);
    }
    var buffer: [256]u8 = undefined;
    const raw = try contract_call_raw(&buffer, 0, target);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    timestamp += 12;
    _ = try h.mine(timestamp);
    // The next block takes the ring slot of BLOCKHASH(2): only the replay reads it there.
    timestamp += 12;
    _ = try h.mine(timestamp);
    const tx_hash = primitives.keccak256(raw).bytes;
    // 21000 + 30 for the opcodes + 22100 for a cold SSTORE of a non-zero hash.
    const gas_used = "\"gasUsed\":\"0xa87a\"";
    var body: [200]u8 = undefined;
    const receipt_format = request_prefix_format ++
        "eth_getTransactionReceipt\",\"params\":[\"0x{x}\"]}}";
    const receipt = try std.fmt.bufPrint(&body, receipt_format, .{&tx_hash});
    try expect_contains(try h.request_runtime(receipt), gas_used);
    const call_tracer = "{\"tracer\":\"callTracer\"}";
    try expect_contains(
        try trace_request(h, "debug_traceTransaction", &tx_hash, call_tracer),
        gas_used,
    );
    try expect_contains(try trace_request(h, "debug_traceTransaction", &tx_hash, "{}"), "43130");
}

test "eth: debug_traceCall traces a call against the head state" {
    const h = try Harness.create();
    defer h.destroy();
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    const reverter = primitives.hex.decode_array(20, reverter_at[3..43]) catch unreachable;
    try h.node.db.put_account(reverter, 0, 0, &.{ 0x5f, 0x5f, 0xfd });
    const caller_code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73 } ++ counter ++
        [_]u8{ 0x5a, 0xf1, 0x00 };
    try h.node.db.put_account(@splat(0x57), 0, 0, &caller_code);
    const caller_at = "\"0x5757575757575757575757575757575757575757\"";
    const tracer = "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"withLog\":true}}";
    const nested = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ ",\"gas\":\"0x30d40\"},\"latest\"," ++ tracer ++ "]",
    );
    try testing.expectEqual(@as(usize, 2), count_of(nested, "\"type\":\"CALL\""));
    try expect_contains(nested, "\"gas\":\"0x30d40\"");
    try expect_contains(nested, "\"logs\":[{");
    const top = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ "},\"latest\",{\"tracer\":\"callTracer\"," ++
            "\"tracerConfig\":{\"onlyTopCall\":true}}]",
    );
    try testing.expectEqual(@as(usize, 1), count_of(top, "\"type\":\"CALL\""));
    const reverted = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ reverter_at ++ "},\"latest\",{\"tracer\":\"callTracer\"}]",
    );
    try expect_contains(reverted, "\"error\":\"execution reverted\"");
    try expect_contains(try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ "},\"latest\"]",
    ), "\"structLogs\":[{");
    // The executor's tracer is detached afterwards: a plain call still runs.
    try expect_contains(try h.request("eth_call", "[{\"to\":" ++ caller_at ++ "}]"), "result");
    try testing.expect(h.node.chain.executor.machine.tracer == null);
}

/// One struct log as revm-inspectors writes it (no error, refund counter 0).
fn struct_step(
    comptime pc: u32,
    comptime name: []const u8,
    comptime gas: u64,
    comptime cost: u64,
    comptime stack: []const u8,
    comptime storage: []const u8,
) []const u8 {
    const format = "{{\"pc\":{d},\"op\":\"{s}\",\"gas\":{d},\"gasCost\":{d},\"depth\":1," ++
        "\"stack\":[{s}]{s},\"refund\":0}}";
    return std.fmt.comptimePrint(format, .{ pc, name, gas, cost, stack, storage });
}

const invalid_at = "\"0x0000000000000000000000000000000000000058\"";

/// The counter, the reverter, an INVALID contract and a caller of the counter.
fn put_trace_contracts(h: *Harness) !void {
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    const reverter = primitives.hex.decode_array(20, reverter_at[3..43]) catch unreachable;
    try h.node.db.put_account(reverter, 0, 0, &.{ 0x5f, 0x5f, 0xfd });
    const invalid = primitives.hex.decode_array(20, invalid_at[3..43]) catch unreachable;
    try h.node.db.put_account(invalid, 0, 0, &.{0xfe});
    const caller_code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73 } ++ counter ++
        [_]u8{ 0x5a, 0xf1, 0x00 };
    try h.node.db.put_account(@splat(0x57), 0, 0, &caller_code);
}

/// The counter called with 200000 gas, by hand: 179000 after the 21000 intrinsic. The cold
/// SLOAD costs 2100, setting the (now warm) slot from 0 to 1 costs 20000, the MSTORE 3 plus
/// one word of memory, the LOG0 375 plus 8 per byte of its 32; 22762 in all.
const slot_zero = ",\"storage\":{" ++ word_zero ++ ":" ++ word_zero ++ "}";
const slot_one = ",\"storage\":{" ++ word_zero ++ ":" ++ word_one ++ "}";
const counter_struct_logs = "{\"failed\":false,\"gas\":43762,\"returnValue\":" ++ word_one ++
    ",\"structLogs\":[" ++
    struct_step(0, "PUSH0", 179000, 2, "", "") ++ "," ++
    struct_step(1, "SLOAD", 178998, 2100, "\"0x0\"", slot_zero) ++ "," ++
    struct_step(2, "PUSH1", 176898, 3, "\"0x0\"", "") ++ "," ++
    struct_step(4, "ADD", 176895, 3, "\"0x0\",\"0x1\"", "") ++ "," ++
    struct_step(5, "DUP1", 176892, 3, "\"0x1\"", "") ++ "," ++
    struct_step(6, "PUSH0", 176889, 2, "\"0x1\",\"0x1\"", "") ++ "," ++
    struct_step(7, "SSTORE", 176887, 20000, "\"0x1\",\"0x1\",\"0x0\"", slot_one) ++ "," ++
    struct_step(8, "PUSH0", 156887, 2, "\"0x1\"", "") ++ "," ++
    struct_step(9, "MSTORE", 156885, 6, "\"0x1\",\"0x0\"", "") ++ "," ++
    struct_step(10, "PUSH1", 156879, 3, "", "") ++ "," ++
    struct_step(12, "PUSH0", 156876, 2, "\"0x20\"", "") ++ "," ++
    struct_step(13, "LOG0", 156874, 631, "\"0x20\",\"0x0\"", "") ++ "," ++
    struct_step(14, "PUSH1", 156243, 3, "", "") ++ "," ++
    struct_step(16, "PUSH0", 156240, 2, "\"0x20\"", "") ++ "," ++
    struct_step(17, "RETURN", 156238, 0, "\"0x20\",\"0x0\"", "") ++ "]}";
const reverter_struct_logs = "\"result\":{\"failed\":true,\"gas\":21004," ++
    "\"returnValue\":\"0x\",\"structLogs\":[" ++
    struct_step(0, "PUSH0", 179000, 2, "", "") ++ "," ++
    struct_step(1, "PUSH0", 178998, 2, "\"0x0\"", "") ++ "," ++
    struct_step(2, "REVERT", 178996, 0, "\"0x0\",\"0x0\"", "") ++ "]}";

test "eth: debug_trace struct logger writes geth's default frame" {
    const h = try Harness.create();
    defer h.destroy();
    try put_trace_contracts(h);
    const gas = "\"gas\":\"0x30d40\"},\"latest\"";
    try testing.expectEqualStrings("\"result\":" ++ counter_struct_logs, try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "," ++ gas ++ "]",
    ));
    // An empty tracer name is the struct logger too.
    try testing.expectEqualStrings("\"result\":" ++ counter_struct_logs, try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "," ++ gas ++ ",{\"tracer\":\"\"}]",
    ));
    // REVERT is no step error; the frame failed and returned nothing.
    try testing.expectEqualStrings(reverter_struct_logs, try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ reverter_at ++ "," ++ gas ++ "]",
    ));
    // INVALID halts with revm's error text, and the halt spends all the gas.
    try testing.expectEqualStrings("\"result\":{\"failed\":true,\"gas\":200000," ++
        "\"returnValue\":\"0x\",\"structLogs\":[{\"pc\":0,\"op\":\"INVALID\",\"gas\":179000," ++
        "\"gasCost\":0,\"depth\":1,\"error\":\"Some(InvalidFEOpcode)\",\"stack\":[]," ++
        "\"refund\":0}]}", try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ invalid_at ++ "," ++ gas ++ "]",
    ));
}

test "eth: debug_trace struct logger honours its config" {
    const h = try Harness.create();
    defer h.destroy();
    try put_trace_contracts(h);
    const gas = "\"gas\":\"0x30d40\"},\"latest\"";
    // Memory (after the MSTORE of 1 at 0) and return data on; stack and storage off; ten
    // steps at most.
    const config = "{\"disableStack\":true,\"disableStorage\":true,\"enableMemory\":true," ++
        "\"enableReturnData\":true,\"limit\":10}";
    const text = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "," ++ gas ++ "," ++ config ++ "]",
    );
    try testing.expectEqual(@as(usize, 10), count_of(text, "\"pc\":"));
    try testing.expect(std.mem.indexOf(u8, text, "\"stack\"") == null);
    try testing.expect(std.mem.indexOf(u8, text, "\"storage\"") == null);
    try expect_contains(text, "{\"pc\":1,\"op\":\"SLOAD\",\"gas\":178998,\"gasCost\":2100," ++
        "\"depth\":1,\"returnData\":\"0x\",\"memory\":[],\"refund\":0}");
    try expect_contains(text, "{\"pc\":10,\"op\":\"PUSH1\",\"gas\":156879,\"gasCost\":3," ++
        "\"depth\":1,\"returnData\":\"0x\",\"memory\":[" ++ word_one ++ "],\"refund\":0}]}");
    // After the counter returns, the caller's STOP sees its output as return data.
    const caller_at = "\"0x5757575757575757575757575757575757575757\"";
    const nested = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ "," ++ gas ++ ",{\"enableReturnData\":true}]",
    );
    try expect_contains(nested, "\"depth\":2,");
    try expect_contains(nested, "{\"pc\":28,\"op\":\"STOP\",\"gas\":153623,\"gasCost\":0," ++
        "\"depth\":1,\"stack\":[\"0x1\"],\"returnData\":" ++ word_one ++ ",\"refund\":0}]}");
    // Tracers reth serves only as JavaScript, or that needlefish lacks, are internal errors.
    const js = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "},\"latest\",{\"tracer\":\"{result: 1}\"}]",
    );
    try expect_contains(js, "-32603");
    try expect_contains(js, "JS Tracer is not enabled");
    try expect_contains(try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "},\"latest\",{\"tracer\":\"muxTracer\"}]",
    ), "unsupported tracer");
    // The block parameter fails first; the tracer is refused once the block is found.
    const latests = "{\"tracer\":\"latests\"}]";
    const by_tag = try h.request("debug_traceBlockByNumber", "[\"latests\"," ++ latests);
    try expect_contains(by_tag, "-32602");
    const by_number = try h.request("debug_traceBlockByNumber", "[\"0x7777\"," ++ latests);
    try expect_contains(by_number, "block not found");
    const found = try h.request("debug_traceBlockByNumber", "[\"latest\"," ++ latests);
    try expect_contains(found, "JS Tracer is not enabled");
    try testing.expect(h.node.chain.executor.machine.tracer == null);
}

test "eth: debug_trace callTracer values follow revm-inspectors" {
    const h = try Harness.create();
    defer h.destroy();
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    // DELEGATECALL(gas, counter, 0, 0, 0, 0); POP; STATICCALL(gas, counter, 0, 0, 0, 0); STOP.
    const call_counter = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x73 } ++ counter ++ [_]u8{0x5a};
    const code = call_counter ++ [_]u8{ 0xf4, 0x50 } ++ call_counter ++ [_]u8{ 0xfa, 0x00 };
    try h.node.db.put_account(@splat(0x59), 0, 0, &code);
    const text = try h.request(
        "debug_traceCall",
        "[{\"from\":\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\"," ++
            "\"to\":\"0x5959595959595959595959595959595959595959\",\"value\":\"0x7\"}," ++
            "\"latest\",{\"tracer\":\"callTracer\"}]",
    );
    try expect_contains(text, "\"type\":\"DELEGATECALL\"");
    try expect_contains(text, "\"type\":\"STATICCALL\"");
    // The DELEGATECALL reports its parent's value; only the STATICCALL has none.
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"value\":\"0x7\""));
    try testing.expectEqual(@as(usize, 2), count_of(text, "\"value\""));
}

test "eth: debug_trace tracerConfig fields are typed as alloy's config structs" {
    const h = try Harness.create();
    defer h.destroy();
    try put_trace_contracts(h);
    const head = "[{\"to\":" ++ counter_at ++ "},\"latest\",";
    const invalid = "-32602";
    const config = "invalid tracer config";
    const prestate = "{\"tracer\":\"prestateTracer\",\"tracerConfig\":";
    try expect_failure(h, "debug_traceCall", head ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"onlyTopCall\":[]}}]", invalid, config);
    try expect_failure(h, "debug_traceCall", head ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"withLog\":1}}]", invalid, config);
    const yes = prestate ++ "{\"diffMode\":\"yes\"}}]";
    try expect_failure(h, "debug_traceCall", head ++ yes, invalid, config);
    const object = prestate ++ "{\"diffMode\":{}}}]";
    try expect_failure(h, "debug_traceCall", head ++ object, invalid, config);
    const finalized = prestate ++ "{\"disableCode\":\"finalized\"}}]";
    try expect_failure(h, "debug_traceCall", head ++ finalized, invalid, config);
    const zero = prestate ++ "{\"disableStorage\":0}}]";
    try expect_failure(h, "debug_traceCall", head ++ zero, invalid, config);
    try expect_failure(h, "debug_traceCall", head ++ "{\"tracer\":\"flatCallTracer\"," ++
        "\"tracerConfig\":{\"convertParityErrors\":\"no\"}}]", invalid, config);
    try expect_failure(h, "debug_traceCall", head ++ "{\"tracer\":\"flatCallTracer\"," ++
        "\"tracerConfig\":{\"includePrecompiles\":[true]}}]", invalid, config);
    // A config that is no object (or an array longer than the struct) does not deserialize.
    try expect_failure(h, "debug_traceCall", head ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":5}]", invalid, config);
    try expect_failure(h, "debug_traceCall", head ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":[true,true,true]}]", invalid, config);
    // Null reads as absent, unknown fields and other tracers' fields are ignored, an array
    // fills the fields by position, and tracers without a config never read it.
    const top = try h.request("debug_traceCall", head ++ "{\"tracer\":\"callTracer\"," ++
        "\"tracerConfig\":{\"onlyTopCall\":null,\"diffMode\":\"yes\",\"other\":[]}}]");
    try expect_contains(top, "\"type\":\"CALL\"");
    const positional = try h.request("debug_traceCall", head ++
        "{\"tracer\":\"callTracer\",\"tracerConfig\":[null,true]}]");
    try expect_contains(positional, "\"logs\":[{");
    try expect_contains(try h.request("debug_traceCall", head ++
        "{\"tracer\":\"4byteTracer\",\"tracerConfig\":5}]"), "\"result\":{}");
    // The struct logger's flags fail the params, as serde reads the whole options object.
    try expect_failure(h, "debug_traceCall", head ++ "{\"debug\":\"x\"}]", invalid, "invalid");
    try expect_failure(h, "debug_traceCall", head ++ "{\"timeout\":5}]", invalid, "invalid");
    try expect_failure(h, "debug_traceCall", head ++ "{\"limit\":\"5\"}]", invalid, "invalid");
    // A bad config is refused once the transaction is found, as reth builds its tracer.
    const missing = "[\"0x" ++ zeros_62 ++ "01\",{\"tracer\":\"callTracer\",\"tracerConfig\":1}]";
    try expect_failure(h, "debug_traceTransaction", missing, "-32000", "transaction not found");
}

test "eth: debug_traceCall without gas runs with the RPC gas cap" {
    const h = try Harness.create();
    defer h.destroy();
    try put_trace_contracts(h);
    // reth's `prepare_call_env`: the 50M cap, not the block's gas limit.
    const tracer = "{\"tracer\":\"callTracer\"}]";
    const bare = try h.request("debug_traceCall", "[{},\"latest\"," ++ tracer);
    try expect_contains(bare, "\"gas\":\"0x2faf080\"");
    const call = try h.request("debug_traceCall", "[{\"to\":" ++ counter_at ++ "}," ++
        "\"latest\"," ++ tracer);
    try expect_contains(call, "\"gas\":\"0x2faf080\"");
    // A priced call without gas runs with what the caller can afford: 100000 wei at 1 wei.
    const priced = try h.request("debug_traceCall", "[{\"from\":" ++ poor_sender ++
        ",\"to\":" ++ counter_at ++ ",\"gasPrice\":\"0x1\"},\"latest\",{\"tracer\":" ++
        "\"callTracer\",\"stateOverrides\":{" ++ poor_sender ++ ":{\"balance\":\"0x186a0\"}}}]");
    try expect_contains(priced, "\"gas\":\"0x186a0\"");
    // A given gas is kept.
    const given = try h.request("debug_traceCall", "[{\"to\":" ++ counter_at ++
        ",\"gas\":\"0x30d40\"},\"latest\"," ++ tracer);
    try expect_contains(given, "\"gas\":\"0x30d40\"");
}

/// Routes `body` into a response that grows on demand, as an HTTP response moves into a
/// large send buffer; returns the response (caller frees).
fn request_growing(h: *Harness, body: []const u8) ![]u8 {
    var allocating: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer allocating.deinit();
    _ = eth.Router.handle(&h.api, body, &allocating.writer);
    return allocating.toOwnedSlice();
}

test "eth: debug_trace struct logs stream past the scratch into the response" {
    const h = try Harness.create();
    defer h.destroy();
    // JUMPDEST; PUSH0; JUMP: 11 gas a turn. 79000 gas after the intrinsic is 7181 turns
    // and a JUMP that runs out with 6 left: 21546 steps, megabytes of logs where the
    // scratch holds 256 KiB.
    const looper: [20]u8 = @splat(0x5a);
    try h.node.db.put_account(looper, 0, 0, &.{ 0x5b, 0x5f, 0x56 });
    const body = request_prefix ++ "debug_traceCall\",\"params\":[{\"to\":" ++
        "\"0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\",\"gas\":\"0x186a0\"},\"latest\"]}";
    const text = try request_growing(h, body);
    defer testing.allocator.free(text);
    try json.validate(text);
    try testing.expect(text.len > h.scratch.len);
    try testing.expect(std.mem.startsWith(u8, text, "{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"result\":{\"failed\":true,\"gas\":100000,\"returnValue\":\"0x\",\"structLogs\":[{"));
    try testing.expectEqual(@as(usize, 21546), count_of(text, "\"pc\":"));
    try expect_contains(text, "{\"pc\":2,\"op\":\"JUMP\",\"gas\":6,\"gasCost\":6,\"depth\":1," ++
        "\"error\":\"Some(OutOfGas)\",\"stack\":[\"0x0\"],\"refund\":0}]}}");
    // A response that cannot grow past its buffer fails cleanly, as jsonrpsee's.
    const too_large = try h.request_runtime(body);
    try expect_contains(too_large, oversized);
    try testing.expect(h.node.chain.executor.machine.tracer == null);
}

/// jsonrpsee's error for a response past reth's 160 MiB bound.
const oversized = "\"error\":{\"code\":-32008,\"message\":\"Response is too big\"," ++
    "\"data\":\"Exceeded max limit of 167772160\"}}";

const http = @import("../../utilities/http/root.zig");

/// A response as the node's HTTP server builds it: a 64 KiB send buffer whose body moves
/// into `large` once a write needs more room (`http.ResponseBuilder`).
const HttpResponse = struct {
    small: [1 << 16]u8 = undefined,
    large: []u8,
    builder: http.ResponseBuilder = undefined,

    fn acquire(context: *anyopaque, size_bytes: usize) ?[]u8 {
        const response: *HttpResponse = @ptrCast(@alignCast(context));
        return if (size_bytes <= response.large.len) response.large else null;
    }

    fn request(response: *HttpResponse, h: *Harness, body: []const u8) ![]const u8 {
        response.builder = .init(&response.small);
        response.builder.grow = .{ .context = response, .acquire = acquire };
        _ = eth.Router.handle(&h.api, body, response.builder.writer());
        const text = response.builder.writer().buffered();
        try json.validate(text);
        return text;
    }
};

/// Reads `fan_out_count` storage slots (counter down to 1) and makes as many CALLs to 128
/// fresh accounts (0x10000 + counter % 128): a transaction whose call tree and prestate
/// run past a 64 KiB send buffer, within the fixture executor's state bounds.
const fan_out_count = 900;
const fan_out_code = [_]u8{
    0x61, fan_out_count >> 8, fan_out_count & 0xff, // PUSH2 count
    0x5b, 0x80, 0x15, 0x60, 0x24, 0x57, // loop (3): JUMPDEST DUP1 ISZERO PUSH1 end JUMPI
    0x80, 0x54, 0x50, // SLOAD(counter) POP
    0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x85, 0x60, 0x7f, 0x16, // the CALL's zeros, counter % 128
    0x62, 0x01, 0x00, 0x00, 0x01, 0x5a, 0xf1, 0x50, // + 0x10000; GAS CALL POP
    0x60, 0x01, 0x90, 0x03, 0x60, 0x03, 0x56, // counter - 1; PUSH1 loop JUMP
    0x5b, 0x00, // end (0x24): JUMPDEST STOP
};
comptime {
    std.debug.assert(fan_out_code[0x24] == 0x5b and fan_out_code[3] == 0x5b);
}
const fan_out_at = "\"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b\"";

fn fan_out_raw(buffer: []u8) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = fixture.spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 3_000_000,
        .to = .{ .call = .{ .bytes = @splat(0x5b) } },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    return envelope.encode_to(buffer);
}

test "eth: debug_trace tracers stream a heavy transaction into a growing response" {
    const h = try Harness.create();
    defer h.destroy();
    const scratch = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(scratch);
    h.api.scratch = scratch;
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    try h.node.db.put_account(@splat(0x5b), 0, 0, &fan_out_code);
    _ = try h.mine(12);
    var buffer: [256]u8 = undefined;
    const raw = try fan_out_raw(&buffer);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    _ = try h.mine(24);
    const large = try testing.allocator.alloc(u8, 4 << 20);
    defer testing.allocator.free(large);
    const response = try testing.allocator.create(HttpResponse);
    defer testing.allocator.destroy(response);
    response.* = .{ .large = large };
    const block = request_prefix ++ "debug_traceBlockByNumber\",\"params\":[\"latest\",";
    // Each slot read reports its zero value.
    const zero_slot = "\":\"0x" ++ zeros_62 ++ "00\"";
    const pre = try response.request(h, block ++ "{\"tracer\":\"prestateTracer\"}]}");
    try testing.expect(pre.len > response.small.len);
    try testing.expect(count_of(pre, zero_slot) >= fan_out_count);
    const diff = try response.request(h, block ++ "{\"tracer\":\"prestateTracer\"," ++
        "\"tracerConfig\":{\"diffMode\":true}}]}");
    try expect_contains(diff, "\"post\":{");
    const calls = try response.request(h, block ++ "{\"tracer\":\"callTracer\"}]}");
    try testing.expectEqual(@as(usize, fan_out_count + 1), count_of(calls, "\"type\":\"CALL\""));
    const flat = try response.request(h, block ++ "{\"tracer\":\"flatCallTracer\"}]}");
    try testing.expectEqual(@as(usize, fan_out_count + 1), count_of(flat, "\"callType\""));
    const four = try response.request(h, block ++ "{\"tracer\":\"4byteTracer\"}]}");
    try expect_contains(four, "\"result\":{}");
    // debug_traceCall's prestate and call paths hold the same call.
    const call = request_prefix ++ "debug_traceCall\",\"params\":[{\"to\":" ++ fan_out_at ++
        "},\"latest\",";
    const call_pre = try response.request(h, call ++ "{\"tracer\":\"prestateTracer\"}]}");
    try testing.expect(count_of(call_pre, zero_slot) >= fan_out_count);
    const call_tree = try response.request(h, call ++ "{\"tracer\":\"callTracer\"}]}");
    try testing.expectEqual(@as(usize, fan_out_count + 1), count_of(call_tree, "\"to\""));
    // Past the large buffer: jsonrpsee's oversized response, not a torn result.
    response.large = large[0 .. 64 << 10];
    const call_tracer = "{\"tracer\":\"callTracer\"}]}";
    try expect_contains(try response.request(h, block ++ call_tracer), oversized);
    try testing.expect(h.node.chain.executor.machine.tracer == null);
}

test "eth: debug_trace 4byteTracer, noopTracer and flatCallTracer" {
    const h = try Harness.create();
    defer h.destroy();
    try put_trace_contracts(h);
    const four = "{\"tracer\":\"4byteTracer\"}";
    try testing.expectEqualStrings("\"result\":{\"0x12345678-2\":1}", try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ ",\"input\":\"0x12345678aabb\"},\"latest\"," ++ four ++ "]",
    ));
    // The caller's CALL passes no input: nothing to count.
    const caller_at = "\"0x5757575757575757575757575757575757575757\"";
    try testing.expectEqualStrings("\"result\":{}", try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ "},\"latest\"," ++ four ++ "]",
    ));
    try testing.expectEqualStrings("\"result\":{}", try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ "},\"latest\",{\"tracer\":\"noopTracer\"}]",
    ));
    // By hand: the caller spends 15 on pushes and GAS, 2600 on the cold CALL and the 22762
    // the counter uses (0x6321); the counter gets all but 1/64 of the 176385 left (0x2a63d).
    const flat = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ caller_at ++ ",\"gas\":\"0x30d40\"},\"latest\"," ++
            "{\"tracer\":\"flatCallTracer\"}]",
    );
    try expect_contains(flat, "\"result\":[{\"action\":{\"from\":");
    try expect_contains(flat, "\"callType\":\"call\",\"gas\":\"0x30d40\",\"input\":\"0x\"," ++
        "\"to\":" ++ caller_at ++ ",\"value\":\"0x0\"},\"blockNumber\":");
    try expect_contains(flat, "\"result\":{\"gasUsed\":\"0x6321\",\"output\":\"0x\"}," ++
        "\"subtraces\":1,\"traceAddress\":[],\"transactionHash\":null," ++
        "\"transactionPosition\":null,\"type\":\"call\"},{\"action\":{\"from\":" ++ caller_at ++
        ",\"callType\":\"call\",\"gas\":\"0x2a63d\",\"input\":\"0x\",\"to\":" ++ counter_at ++
        ",\"value\":\"0x0\"},\"blockNumber\":");
    try expect_contains(flat, "\"result\":{\"gasUsed\":\"0x58ea\",\"output\":" ++ word_one ++
        "},\"subtraces\":0,\"traceAddress\":[0],\"transactionHash\":null," ++
        "\"transactionPosition\":null,\"type\":\"call\"}]");
    try testing.expect(std.mem.indexOf(u8, flat, "blockHash") == null);
    // A halt other than a revert has a parity error and no result.
    try expect_contains(try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ invalid_at ++ "},\"latest\",{\"tracer\":\"flatCallTracer\"}]",
    ), "\"error\":\"Bad instruction\",\"result\":null,\"subtraces\":0");
}

const zeros_62 = "00000000000000000000000000000000000000000000000000000000000000";
const word_zero = "\"0x" ++ zeros_62 ++ "00\"";
const word_one = "\"0x" ++ zeros_62 ++ "01\"";

test "eth: debug_trace prestateTracer reports pre-transaction state and diffs" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    _ = try h.mine(12);
    var buffers: [2][256]u8 = undefined;
    const first = try contract_call_raw(&buffers[0], 0, counter);
    const second = try contract_call_raw(&buffers[1], 1, counter);
    try expect_contains(try send_raw(h, first), "\"result\":\"0x");
    try expect_contains(try send_raw(h, second), "\"result\":\"0x");
    const block = try h.mine(24);
    const sender = "\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\":{";
    const plain = "{\"tracer\":\"prestateTracer\"}";
    const second_hash = primitives.keccak256(second).bytes;
    // The second transaction sees the first one's effects as its pre-state.
    const pre = try trace_request(h, "debug_traceTransaction", &second_hash, plain);
    try expect_contains(pre, sender);
    try expect_contains(pre, "\"nonce\":1");
    try expect_contains(pre, "\"storage\":{\"0x" ++ zeros_62 ++ "00\":" ++ word_one);
    const diff = "{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}";
    const first_hash = primitives.keccak256(first).bytes;
    const changes = try trace_request(h, "debug_traceTransaction", &first_hash, diff);
    const post = changes[std.mem.indexOf(u8, changes, "\"post\"").?..];
    // The counter's slot was zero: a diff leaves zero values out (revm-inspectors).
    const pre_side = changes[0 .. changes.len - post.len];
    try testing.expect(std.mem.indexOf(u8, pre_side, "storage") == null);
    try expect_contains(post, word_one);
    try expect_contains(post, "\"nonce\":1");
    const by_hash = try trace_request(h, "debug_traceBlockByHash", &block.bytes, plain);
    try testing.expectEqual(@as(usize, 2), count_of(by_hash, "\"txHash\""));
    // debug_traceCall runs on the head state, where slot 0 is now 2.
    const call = try h.request(
        "debug_traceCall",
        "[{\"to\":" ++ counter_at ++ "},\"latest\",{\"tracer\":\"prestateTracer\"," ++
            "\"tracerConfig\":{\"diffMode\":true}}]",
    );
    try expect_contains(call, "\"0x" ++ zeros_62 ++ "02\"");
    try expect_contains(call, "\"0x" ++ zeros_62 ++ "03\"");
}

const ValiditySinkRecorder = struct {
    count: u32 = 0,
    predicates: u32 = 0,

    fn submit(
        context: *anyopaque,
        _: *const txpool.Tx,
        predicates: []const txpool.validity.Predicate,
    ) anyerror!void {
        const recorder: *ValiditySinkRecorder = @ptrCast(@alignCast(context));
        recorder.count += 1;
        recorder.predicates = @intCast(predicates.len);
    }
};

fn validity_request(h: *Harness, raw: []const u8, predicates: []const u8) ![]const u8 {
    var body: [2048]u8 = undefined;
    const format = request_prefix_format ++ "base_sendRawTransactionValidity\"," ++
        "\"params\":[\"0x{x}\",{{\"validity\":{s}}}]}}";
    return h.request_runtime(try std.fmt.bufPrint(&body, format, .{ raw, predicates }));
}

test "eth: base_sendRawTransactionValidity validates and hands off to the sink" {
    const h = try Harness.create();
    defer h.destroy();
    var buffer: [256]u8 = undefined;
    const raw = try transfer_raw(&buffer, 0);
    const expiry = "{\"type\":\"block_number\",\"params\":{\"op\":\"<=\",\"value\":\"0x10\"}}";
    const balance = "{\"type\":\"balance\",\"params\":{\"address\":" ++
        "\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\",\"op\":\">\",\"value\":0}}";
    const valid = "[" ++ expiry ++ "," ++ balance ++ "]";
    // Without a sink the transaction is rejected after validation.
    try expect_contains(try validity_request(h, raw, valid), "no pool enforces");
    var recorder: ValiditySinkRecorder = .{};
    h.api.validity_sink = .{ .context = &recorder, .submit = ValiditySinkRecorder.submit };
    var expected: [80]u8 = undefined;
    const hash = try std.fmt.bufPrint(&expected, "\"result\":\"0x{x}\"", .{
        &primitives.keccak256(raw).bytes,
    });
    try expect_contains(try validity_request(h, raw, valid), hash);
    try testing.expectEqual(@as(u32, 1), recorder.count);
    try testing.expectEqual(@as(u32, 2), recorder.predicates);
    // Denim builds 200 ms blocks: flashblock predicates are rejected (accepted before).
    const flash = "[" ++ expiry ++ ",{\"type\":\"flashblock_index\",\"params\":" ++
        "{\"op\":\">\",\"value\":1}}]";
    const flash_text = try validity_request(h, raw, flash);
    if (h.api.spec.is_upgrade_active(.denim, 2)) {
        try expect_contains(flash_text, "not supported after Denim");
    } else {
        try expect_contains(flash_text, hash);
        recorder.count -= 1;
    }
    try expect_contains(try validity_request(h, raw, "[" ++ balance ++ "]"), "upper bound");
    try expect_contains(try validity_request(h, raw, "[]"), "must not be empty");
    // 60 s of blocks from block 1 ends by block 301 (200 ms) or 31 (2 s).
    const far = "[{\"type\":\"block_number\",\"params\":{\"op\":\"=\",\"value\":302}}]";
    try expect_contains(try validity_request(h, raw, far), "too far in the future");
    try expect_contains(try validity_request(h, &.{ 0x02, 0x01 }, valid), "-32602");
    try testing.expectEqual(@as(u32, 1), recorder.count);
}

test "eth: prestateTracer keeps accounts and slots touched by reverted frames" {
    const h = try Harness.create();
    defer h.destroy();
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    // CALL(gas, counter, 0, 0, 0, 0, 0); REVERT(0, 0): the counter's warmth is reverted.
    const caller_code = [_]u8{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73 } ++ counter ++
        [_]u8{ 0x5a, 0xf1, 0x5f, 0x5f, 0xfd };
    try h.node.db.put_account(@splat(0x58), 0, 0, &caller_code);
    const text = try h.request(
        "debug_traceCall",
        "[{\"to\":\"0x5858585858585858585858585858585858585858\"},\"latest\"," ++
            "{\"tracer\":\"prestateTracer\"}]",
    );
    try expect_contains(text, counter_at ++ ":{");
    try expect_contains(text, "\"storage\":{\"0x" ++ zeros_62 ++ "00\":" ++ word_zero);
}

fn tip_free_call_raw(buffer: []u8, chain_id: u64, to: [20]u8) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 200_000,
        .to = .{ .call = .{ .bytes = to } },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    return envelope.encode_to(buffer);
}

test "eth: prestateTracer reports revm's loaded accounts as revm-inspectors does" {
    const h = try Harness.create_for(&denim_rpc_spec);
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    const vaults = [_][]const u8{ "19", "1a", "1b" };
    for (vaults) |last| {
        var address: [20]u8 = @splat(0);
        address[0] = 0x42;
        address[19] = std.fmt.parseInt(u8, last, 16) catch unreachable;
        try h.node.db.put_account(address, 1, 0, &.{0x00});
    }
    // The coinbase, and the L1Block contract the L1 fee parameters are read from.
    try h.node.db.put_account(@splat(0xfe), 1, 0, &.{});
    var l1_block: [20]u8 = @splat(0);
    l1_block[0] = 0x42;
    l1_block[19] = 0x15;
    try h.node.db.put_account(l1_block, 1, 0, &.{0x00});
    _ = try h.mine(2);
    var buffer: [256]u8 = undefined;
    const raw = try tip_free_call_raw(&buffer, h.node.spec.chain_id, l1_block);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    _ = try h.mine(4);
    const hash = primitives.keccak256(raw).bytes;
    const plain = "{\"tracer\":\"prestateTracer\"}";
    const traced = try trace_request(h, "debug_traceTransaction", &hash, plain);
    // A transaction without a tip still pays the coinbase (nothing), which revm loads.
    try expect_contains(traced, "\"0xfefefefefefefefefefefefefefefefefefefefe\":{\"balance\"");
    // The L1 fee parameters are read outside the EVM: no L1Block slot is listed.
    // Nethermind lists an account's code hash next to its code.
    try expect_contains(traced, "\"0x4200000000000000000000000000000000000015\":{" ++
        "\"balance\":\"0x1\",\"code\":\"0x00\",\"codeHash\":" ++ code_hash_00 ++ "}");
    // A call charges no fee and credits no fee vault; as Nethermind, the coinbase is
    // listed (credited nothing) and empty accounts are left out.
    const call = try h.request("debug_traceCall", "[{\"from\":" ++
        "\"0x7dc6c0165f09500b75146b66eec05a39dbbc40d2\",\"to\":" ++
        "\"0x00000000000000000000000000000000000000aa\"},\"latest\",{\"tracer\":" ++
        "\"prestateTracer\",\"tracerConfig\":{\"disableCode\":true}}]");
    try testing.expect(std.mem.startsWith(u8, call, "\"result\":{" ++
        "\"0xfefefefefefefefefefefefefefefefefefefefe\":{\"balance\":\"0x"));
    try testing.expect(std.mem.endsWith(u8, call, "\"}}"));
    try testing.expectEqual(@as(usize, 1), count_of(call, "balance"));
    // An overridden account the call never loads is not reported; the sender, empty
    // before, is left out of a diff's pre (Nethermind), and both it and the account it
    // creates are in post.
    const created = try h.request("debug_traceCall", "[{\"from\":" ++
        "\"0x7dc6c0165f09500b75146b66eec05a39dbbc40d2\"},\"latest\",{\"stateOverrides\":" ++
        "{\"0x5b76c950a887b42e74fdde348bf928517f41cf70\":{\"code\":\"0x\"}},\"tracer\":" ++
        "\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}]");
    try testing.expectEqualStrings("\"result\":{\"pre\":{},\"post\":{" ++
        "\"0x5c7d5a7b707d05be9a3f8f28eb3099ed20e22f9f\":{\"nonce\":1}," ++
        "\"0x7dc6c0165f09500b75146b66eec05a39dbbc40d2\":{\"nonce\":1}}}", created);
}

test "eth: a call object member of the wrong type is refused" {
    const h = try Harness.create();
    defer h.destroy();
    // Nethermind types every `TransactionForRpc` member: a block tag is no nonce.
    const tagged = "[{\"nonce\":\"finalized\",\"to\":" ++ address_target ++ "},\"latest\"]";
    try expect_contains(try h.request("eth_estimateGas", tagged), "{\"code\":-32602");
    try expect_contains(try h.request("eth_call", tagged), "{\"code\":-32602");
    const bad_hash = "[{\"blockHash\":\"0x12\",\"to\":" ++ address_target ++ "},\"latest\"]";
    try expect_contains(try h.request("eth_call", bad_hash), "{\"code\":-32602");
    // A padded hex nonce or a decimal one reads as Nethermind's `ULongConverter` reads it.
    const padded = "[{\"nonce\":\"0x01\",\"v\":\"27\",\"to\":" ++ address_target ++
        "},\"latest\"]";
    try expect_contains(try h.request("eth_call", padded), "\"result\":\"0x\"");
}

test "eth: prestateTracer diff leaves out an account destroyed in a reverted frame" {
    const h = try Harness.create();
    defer h.destroy();
    // 0x..c0de creates a child whose init code self-destructs (CALLER SELFDESTRUCT), then
    // reverts everything (INVALID). As Nethermind and geth, the destroyed account stays out
    // of post although the revert undid the destruction; an account created without
    // destroying itself is listed missing (a zero code hash).
    const request = "[{\"from\":\"0x7dc6c0165f09500b75146b66eec05a39dbbc40d2\",\"to\":" ++
        "\"0x000000000000000000000000000000000000c0de\"},\"latest\",{\"stateOverrides\":{" ++
        "\"0x000000000000000000000000000000000000c0de\":{\"code\":\"0x61";
    const config = "6000526002601e6000f0fe\"}},\"tracer\":\"prestateTracer\"," ++
        "\"tracerConfig\":{\"diffMode\":true}}]";
    // The child, at nonce 0 of 0x..c0de.
    const child = "\"0x8bbc3514477d75ec797bbe4e19d7961660bb849c\":";
    const destroyed = try h.request("debug_traceCall", request ++ "33ff" ++ config);
    try testing.expect(std.mem.indexOf(u8, destroyed, child) == null);
    const kept = try h.request("debug_traceCall", request ++ "0000" ++ config);
    try expect_contains(kept, child ++ "{\"codeHash\":\"0x" ++ zeros_62 ++ "00\"}");
}

test "eth: prestateTracer diff lists a create that fails before it runs" {
    const h = try Harness.create();
    defer h.destroy();
    // 0x..c0de (no balance) creates with one wei: the create pays its gas, then cannot
    // transfer the value, so the account never exists. As geth and Nethermind (the address
    // is looked up once the instruction's gas is paid, and counted created), post lists it
    // missing (a zero code hash) and pre leaves it out.
    const request = "[{\"from\":\"0x7dc6c0165f09500b75146b66eec05a39dbbc40d2\",\"to\":" ++
        "\"0x000000000000000000000000000000000000c0de\"},\"latest\",{\"stateOverrides\":{" ++
        "\"0x000000000000000000000000000000000000c0de\":{\"code\":\"0x600060006001f000\"}}," ++
        "\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}]";
    const child = "\"0x8bbc3514477d75ec797bbe4e19d7961660bb849c\":";
    const diff = try h.request("debug_traceCall", request);
    const post = diff[std.mem.indexOf(u8, diff, "\"post\"").?..];
    try testing.expect(std.mem.indexOf(u8, diff[0 .. diff.len - post.len], child) == null);
    try expect_contains(post, child ++ "{\"codeHash\":\"0x" ++ zeros_62 ++ "00\"}");
}

test "eth: prestateTracer diff of a creation call that cannot pay its value" {
    const h = try Harness.create();
    defer h.destroy();
    // As Nethermind: the address the creation makes is looked up and counted created, so
    // post lists it missing; the missing sender, which Nethermind creates for an unpriced
    // call and whose nonce the failed creation leaves alone, is no diff.
    const request = "[{\"from\":\"0x00000000000000000000000000000000000000aa\",\"input\":" ++
        "\"0x6001600055\",\"value\":\"0xffffffffffffffffffffffffffff\"},\"latest\"," ++
        "{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}]";
    const diff = try h.request("debug_traceCall", request);
    try testing.expect(std.mem.startsWith(u8, diff, "\"result\":{\"pre\":{},\"post\":{"));
    try expect_contains(diff, "\"0x45eb6484d76cfe3f45708b91f5af8ce495134fac\":{\"codeHash\":" ++
        "\"0x" ++ zeros_62 ++ "00\"}");
    try testing.expect(std.mem.indexOf(u8, diff, "00000000000000000000aa") == null);
}

test "eth: prestateTracer diff lists a looked-up missing account with a zero code hash" {
    const h = try Harness.create();
    defer h.destroy();
    // The identity precompile has no account. Nethermind (as geth) reads a zero code hash
    // for an account missing after the transaction, which differs from the empty-code
    // hash it assumes before: the diff's post lists it, its pre does not.
    const call = "[{\"from\":\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\",\"to\":" ++
        "\"0x0000000000000000000000000000000000000004\"},\"latest\",{\"tracer\":" ++
        "\"prestateTracer\"";
    const diff_config = ",\"tracerConfig\":{\"diffMode\":true}}]";
    const diff = try h.request("debug_traceCall", call ++ diff_config);
    const post = diff[std.mem.indexOf(u8, diff, "\"post\"").?..];
    const identity = "\"0x0000000000000000000000000000000000000004\":";
    try expect_contains(post, identity ++ "{\"codeHash\":\"0x" ++ zeros_62 ++ "00\"}");
    try testing.expectEqual(@as(usize, 1), count_of(diff, identity));
    const plain = try h.request("debug_traceCall", call ++ "}]");
    try testing.expect(std.mem.indexOf(u8, plain, identity) == null);
}

/// keccak256(0x00), the code hash of the one-byte code `0x00`.
const code_hash_00 = "\"0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a\"";

test "eth: prestateTracer lists an authority whose authorization is invalid" {
    const h = try Harness.create();
    defer h.destroy();
    // Key 1's account (funded by the fixture) signs for chain 1: the authorization is
    // skipped, yet Nethermind's tracer still looks the authority up.
    var authorization: consensus.tx_fields.Authorization = .{
        .chain_id = 1,
        .address = .{ .bytes = @splat(0xcc) },
        .nonce = 0,
        .y_parity = 0,
        .r = 0,
        .s = 0,
    };
    const signature = try consensus.signature.sign(fixture.key(1), authorization.signing_hash());
    authorization.y_parity = @intFromBool(signature.y_parity);
    authorization.r = signature.r;
    authorization.s = signature.s;
    var body: [1024]u8 = undefined;
    const format = request_prefix_format ++ "debug_traceCall\",\"params\":[{{\"to\":" ++
        "\"0x00000000000000000000000000000000000000aa\",\"authorizationList\":[{{" ++
        "\"chainId\":\"0x1\",\"address\":\"0x{x}\",\"nonce\":\"0x0\",\"yParity\":\"0x{x}\"," ++
        "\"r\":\"0x{x}\",\"s\":\"0x{x}\"}}]}},\"latest\",{{\"tracer\":\"prestateTracer\"}}]}}";
    const request = try std.fmt.bufPrint(&body, format, .{
        &authorization.address.bytes,
        authorization.y_parity,
        authorization.r,
        authorization.s,
    });
    const traced = try h.request_runtime(request);
    try expect_contains(traced, "\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\":{\"balance\"");
}

test "eth: prestateTracer lists the callee's delegate from before the authorizations" {
    const h = try Harness.create();
    defer h.destroy();
    // Key 1's account is delegated to 0xd0.. and re-delegates to 0xd1.. in the call it
    // receives. Nethermind's tracer looks up the delegate before the authorization applies;
    // the call then runs 0xd1..'s (empty) code without listing it.
    var authorization: consensus.tx_fields.Authorization = .{
        .chain_id = 0,
        .address = .{ .bytes = @splat(0xd1) },
        .nonce = 0,
        .y_parity = 0,
        .r = 0,
        .s = 0,
    };
    const signature = try consensus.signature.sign(fixture.key(1), authorization.signing_hash());
    authorization.y_parity = @intFromBool(signature.y_parity);
    authorization.r = signature.r;
    authorization.s = signature.s;
    const authority = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const old = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
    const new = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    var body: [1536]u8 = undefined;
    const format = request_prefix_format ++ "debug_traceCall\",\"params\":[{{\"to\":\"" ++
        authority ++ "\",\"authorizationList\":[{{\"chainId\":\"0x0\",\"address\":" ++
        "\"0x{x}\",\"nonce\":\"0x0\",\"yParity\":\"0x{x}\",\"r\":\"0x{x}\",\"s\":\"0x{x}\"}}]}}," ++
        "\"latest\",{{\"tracer\":\"prestateTracer\",\"stateOverrides\":{{\"" ++ authority ++
        "\":{{\"code\":\"0xef0100" ++ old ++ "\"}},\"0x" ++ old ++ "\":{{\"balance\":\"0x1\"}}," ++
        "\"0x" ++ new ++ "\":{{\"balance\":\"0x1\"}}}}}}]}}";
    const request = try std.fmt.bufPrint(&body, format, .{
        &authorization.address.bytes,
        authorization.y_parity,
        authorization.r,
        authorization.s,
    });
    const traced = try h.request_runtime(request);
    try expect_contains(traced, "\"" ++ authority ++ "\":{\"balance\"");
    try expect_contains(traced, "\"0x" ++ old ++ "\":{\"balance\":\"0x1\"}");
    try testing.expect(std.mem.indexOf(u8, traced, new) == null);
}

test "eth: prestateTracer lists an authority whose authorization nonce mismatches" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    // Key 2's account, delegated already at nonce 74, signs for nonce 93 on this chain.
    const designator = [_]u8{ 0xef, 0x01, 0x00 } ++ @as([19]u8, @splat(0)) ++ [_]u8{0x06};
    try h.node.db.put_account(fixture.address_of(2).bytes, 1, 74, &designator);
    _ = try h.mine(2);
    var authorization: consensus.tx_fields.Authorization = .{
        .chain_id = h.node.spec.chain_id,
        .address = .{ .bytes = @as([19]u8, @splat(0)) ++ [_]u8{0x0c} },
        .nonce = 93,
        .y_parity = 0,
        .r = 0,
        .s = 0,
    };
    const signature = try consensus.signature.sign(fixture.key(2), authorization.signing_hash());
    authorization.y_parity = @intFromBool(signature.y_parity);
    authorization.r = signature.r;
    authorization.s = signature.s;
    var list_bytes: [256]u8 = undefined;
    var encoder = rlp.Encoder.init(&list_bytes);
    rlp.encode(&encoder, authorization);
    const tx: consensus.Eip7702 = .{
        .chain_id = h.node.spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 200_000,
        .to = .{ .bytes = @as([19]u8, @splat(0)) ++ [_]u8{0xaa} },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
        .authorization_list = .{ .payload = encoder.written(), .count = 1 },
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(1));
    var buffer: [512]u8 = undefined;
    const raw = envelope.encode_to(&buffer);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    _ = try h.mine(4);
    const hash = primitives.keccak256(raw).bytes;
    const plain = "{\"tracer\":\"prestateTracer\"}";
    const traced = try trace_request(h, "debug_traceTransaction", &hash, plain);
    var expected: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&expected, "\"0x{x}\":{{\"balance\"", .{
        &fixture.address_of(2).bytes,
    });
    try expect_contains(traced, key);
}

test "eth: prestateTracer leaves out an account an instruction cannot pay to run" {
    const h = try Harness.create();
    defer h.destroy();
    // 0x..be (one wei) and 0x..d1e (delegated to it) are named by the code below.
    const other = "00000000000000000000000000000000000000be";
    const delegated = "0000000000000000000000000000000000000d1e";
    const listed = "\"0x" ++ other ++ "\":{\"balance\"";
    const other_key = "\"0x" ++ other ++ "\":";
    const delegated_key = "\"0x" ++ delegated ++ "\":{\"balance\"";
    const request = "[{\"to\":" ++ override_target ++ ",\"gas\":\"";
    const tracer = "\"},\"latest\",{\"tracer\":\"prestateTracer\",\"stateOverrides\":{" ++
        "\"0x" ++ other ++ "\":{\"balance\":\"0x1\"},\"0x" ++ delegated ++
        "\":{\"code\":\"0xef0100" ++ other ++ "\"}," ++ override_target ++ ":{\"code\":\"";
    // As geth's tracer (the failed opcode reported with its error), nothing is looked up.
    // BALANCE of a cold account without gas for the cold access: never read.
    const balance_code = "0x73" ++ other ++ "3100";
    const balance = try h.request("debug_traceCall", request ++ "0x5400" ++ tracer ++
        balance_code ++ "\"}}}]");
    try testing.expect(std.mem.indexOf(u8, balance, other_key) == null);
    // EXTCODECOPY of 64 KiB: the account is read, then the memory is unaffordable.
    const copy_code = "0x61ffff60006000" ++ "73" ++ other ++ "3c00";
    const copied = try h.request("debug_traceCall", request ++ "0x7918" ++ tracer ++
        copy_code ++ "\"}}}]");
    try testing.expect(std.mem.indexOf(u8, copied, other_key) == null);
    // A CALL the frame cannot pay for: neither the target nor its delegate.
    const call_code = "0x60006000600060006000" ++ "73" ++ delegated ++ "61fffff100";
    const called = try h.request("debug_traceCall", request ++ "0x5400" ++ tracer ++
        call_code ++ "\"}}}]");
    try testing.expect(std.mem.indexOf(u8, called, delegated_key) == null);
    try testing.expect(std.mem.indexOf(u8, called, other_key) == null);
    // The same with gas to spare lists both, and so does a CALL that runs but cannot
    // transfer its value (the caller has none).
    const paid = try h.request("debug_traceCall", request ++ "0x30000" ++ tracer ++
        call_code ++ "\"}}}]");
    try expect_contains(paid, delegated_key);
    try expect_contains(paid, listed);
    const value_code = "0x60006000600060006001" ++ "73" ++ other ++ "61fffff100";
    const valued = try h.request("debug_traceCall", request ++ "0x30000" ++ tracer ++
        value_code ++ "\"}}}]");
    try expect_contains(valued, listed);
}

test "eth: prestateTracer leaves out a slot whose SSTORE runs out of gas" {
    const h = try Harness.create();
    defer h.destroy();
    // SLOAD 0xbc, then SSTORE 1 to the cold slot 0xbb: the frame can load 0xbb but not pay
    // the 22100 for the write. The failed instruction's slot is not listed.
    const request = "[{\"to\":" ++ override_target ++ ",\"gas\":\"0x7530\"},\"latest\"," ++
        "{\"tracer\":\"prestateTracer\",\"stateOverrides\":{" ++ override_target ++
        ":{\"code\":\"0x60";
    const store_code = "5450600160bb5500\"}}}]";
    const slot_bc = "\"0x" ++ zeros_62 ++ "bc\":\"0x" ++ zeros_62 ++ "00\"";
    const slot_bb = "\"0x" ++ zeros_62 ++ "bb\":\"0x" ++ zeros_62 ++ "00\"";
    const failed = try h.request("debug_traceCall", request ++ "bc" ++ store_code);
    try expect_contains(failed, "\"storage\":{" ++ slot_bc ++ "}");
    try testing.expect(std.mem.indexOf(u8, failed, slot_bb) == null);
    // A slot read before the failing SSTORE stays listed.
    const read_first = try h.request("debug_traceCall", request ++ "bb" ++ store_code);
    try expect_contains(read_first, "\"storage\":{" ++ slot_bb ++ "}");
}

test "eth: a call naming a tip but no fee cap fails as in geth and Nethermind" {
    const h = try Harness.create();
    defer h.destroy();
    // The missing fee cap stays zero (geth `CallDefaults`), below the tip.
    const inner = "max priority fee per gas higher than max fee per gas: address " ++
        "0x0000000000000000000000000000000000000000, maxPriorityFeePerGas: 1, maxFeePerGas: 0";
    const tip_call = "{\"to\":" ++ override_target ++ ",\"maxPriorityFeePerGas\":\"0x1\"}";
    const called = try h.request("eth_call", "[" ++ tip_call ++ ",\"latest\"]");
    try testing.expectEqualStrings("\"error\":{\"code\":-32000,\"message\":\"err: " ++ inner ++
        " (supplied gas 50000000)\"}", called);
    const traced = try h.request("debug_traceCall", "[" ++ tip_call ++ ",\"latest\",{}]");
    try testing.expectEqualStrings("\"error\":{\"code\":-32000,\"message\":\"tracing failed: " ++
        inner ++ "\"}", traced);
    const gas_given = "{\"gas\":\"0x7530\",\"maxPriorityFeePerGas\":\"0x1\"}";
    const estimated = try h.request("eth_estimateGas", "[" ++ gas_given ++ "]");
    const failed_with = "\"error\":{\"code\":-32000,\"message\":\"failed with 30000 gas: ";
    try testing.expectEqualStrings(failed_with ++ inner ++ "\"}", estimated);
    // A zero tip is not above the zero cap.
    const zero_tip = "[{\"to\":" ++ override_target ++ ",\"maxPriorityFeePerGas\":\"0x0\"}]";
    const unrefused = try h.request("eth_call", zero_tip);
    try testing.expect(std.mem.indexOf(u8, unrefused, "maxPriorityFeePerGas") == null);
}

const override_target = "\"0x0000000000000000000000000000000000007777\"";

test "eth: eth_call, eth_estimateGas and debug_traceCall apply state and block overrides" {
    const h = try Harness.create();
    defer h.destroy();
    const call = "[{\"to\":" ++ override_target ++ "},\"latest\",";
    // PUSH1 42, return it as a word.
    const code_42 = "{" ++ override_target ++ ":{\"code\":\"0x602a5f5260205ff3\"}}";
    const word_42 = "\"result\":\"0x" ++ zeros_62 ++ "2a\"";
    try expect_contains(try h.request("eth_call", call ++ code_42 ++ "]"), word_42);
    // Not persisted: the address has no code afterwards.
    try expect_contains(try h.request("eth_call", call ++ "null]"), "\"result\":\"0x\"");
    // SLOAD(0) with a stateDiff slot.
    const slot = "{" ++ override_target ++ ":{\"code\":\"0x5f545f5260205ff3\",\"stateDiff\":" ++
        "{\"0x" ++ zeros_62 ++ "00\":\"0x" ++ zeros_62 ++ "07\"}}}";
    const word_7 = "\"result\":\"0x" ++ zeros_62 ++ "07\"";
    try expect_contains(try h.request("eth_call", call ++ slot ++ "]"), word_7);
    // NUMBER under a block override.
    const number = "{" ++ override_target ++ ":{\"code\":\"0x435f5260205ff3\"}}";
    const word_99 = "\"result\":\"0x" ++ zeros_62 ++ "99\"";
    const block = ",{\"number\":\"0x99\"}]";
    try expect_contains(try h.request("eth_call", call ++ number ++ block), word_99);
    // eth_estimateGas runs the overridden code on every step.
    const estimate = try h.request("eth_estimateGas", call ++ code_42 ++ "]");
    try testing.expect(std.mem.indexOf(u8, estimate, "\"result\":\"0x5208\"") == null);
    try expect_contains(estimate, "\"result\":\"0x5");
    // debug_traceCall reads the overrides from its config.
    const traced = try h.request(
        "debug_traceCall",
        call ++ "{\"tracer\":\"callTracer\",\"stateOverrides\":" ++ code_42 ++ "}]",
    );
    try expect_contains(traced, "\"output\":\"0x" ++ zeros_62 ++ "2a\"");
    // Malformed overrides are invalid params.
    const bad = "{" ++ override_target ++ ":{\"colour\":\"0x01\"}}]";
    try expect_contains(try h.request("eth_call", call ++ bad), "-32602");
    // Unknown block override members are ignored, as serde ignores them.
    try expect_contains(try h.request("eth_call", call ++ "null,{\"bogus\":1}]"), "\"result\"");
    const both = "{" ++ override_target ++ ":{\"state\":{},\"stateDiff\":{}}}]";
    try expect_contains(try h.request("eth_call", call ++ both), "{\"code\":-32602,\"message\":" ++
        "\"account 0x0000000000000000000000000000000000007777 has both 'state' and 'stateDiff'\"}");
}

test "eth: any state override of a precompile's address makes it an ordinary account" {
    const h = try Harness.create();
    defer h.destroy();
    // geth's override `Apply` (and Nethermind's): the identity precompile echoes its input
    // until an override names its address, then the account's code runs.
    const identity = "\"0x0000000000000000000000000000000000000004\"";
    const call = "[{\"to\":" ++ identity ++ ",\"input\":\"0x" ++ zeros_62 ++ "07\"},\"latest\"";
    const word_7 = "\"result\":\"0x" ++ zeros_62 ++ "07\"";
    const word_42 = "\"result\":\"0x" ++ zeros_62 ++ "2a\"";
    try expect_contains(try h.request("eth_call", call ++ "]"), word_7);
    const code_42 = "{" ++ identity ++ ":{\"code\":\"0x602a5f5260205ff3\"}}";
    try expect_contains(try h.request("eth_call", call ++ "," ++ code_42 ++ "]"), word_42);
    // Without code too: the account has none, so the call returns nothing.
    const balance = "{" ++ identity ++ ":{\"balance\":\"0x1\"}}";
    const none = try h.request("eth_call", call ++ "," ++ balance ++ "]");
    try expect_contains(none, "\"result\":\"0x\"");
    // A delegation designator as override code is followed.
    const delegated = "{" ++ identity ++ ":{\"code\":\"0xef0100" ++
        "0000000000000000000000000000000000007777\"}," ++ override_target ++
        ":{\"code\":\"0x602a5f5260205ff3\"}}";
    try expect_contains(try h.request("eth_call", call ++ "," ++ delegated ++ "]"), word_42);
    const traced = try h.request("debug_traceCall", call ++
        ",{\"tracer\":\"callTracer\",\"stateOverrides\":" ++ code_42 ++ "}]");
    try expect_contains(traced, "\"output\":\"0x" ++ zeros_62 ++ "2a\"");
    // Not carried into the next call.
    try expect_contains(try h.request("eth_call", call ++ "]"), word_7);
    // eth_simulateV1: only for the overriding block.
    const simulated = "[{\"blockStateCalls\":[{\"stateOverrides\":" ++ code_42 ++
        ",\"calls\":[{\"to\":" ++ identity ++ ",\"input\":\"0x" ++ zeros_62 ++ "07\"}]}," ++
        "{\"calls\":[{\"to\":" ++ identity ++ ",\"input\":\"0x" ++ zeros_62 ++ "07\"}]}]}]";
    const blocks = try h.request("eth_simulateV1", simulated);
    const first = std.mem.indexOf(u8, blocks, "\"returnData\":\"0x" ++ zeros_62 ++ "2a\"").?;
    const second = std.mem.indexOf(u8, blocks, "\"returnData\":\"0x" ++ zeros_62 ++ "07\"").?;
    try testing.expect(first < second);
}

test "eth: eth_call, eth_estimateGas and eth_createAccessList report reth's call errors" {
    const h = try Harness.create();
    defer h.destroy();
    const call = "[{\"to\":" ++ override_target;
    const nope = "\"latest\",{" ++ override_target ++ ":{\"code\":\"" ++ revert_nope_code ++
        "\"}}]";
    const reverted = "{\"code\":3,\"message\":\"execution reverted: nope\",\"data\":\"" ++
        revert_nope_data ++ "\"}";
    try expect_contains(try h.request("eth_call", call ++ "}," ++ nope), reverted);
    try expect_contains(try h.request("eth_estimateGas", call ++ "}," ++ nope), reverted);
    const limited = call ++ ",\"gas\":\"0x7530\"}," ++ nope;
    try expect_contains(try h.request("eth_estimateGas", limited), reverted);
    const listed = try h.request("eth_createAccessList", call ++ "}," ++ nope);
    try expect_contains(listed, "\"error\":\"execution reverted: nope\"}");
    // Halts are -32003 with reth's text.
    const fe = "\"latest\",{" ++ override_target ++ ":{\"code\":\"0xfe\"}}]";
    try expect_contains(try h.request("eth_call", call ++ "}," ++ fe), "{\"code\":-32003," ++
        "\"message\":\"EVM error: InvalidFEOpcode\"}");
    const loop = "\"latest\",{" ++ override_target ++ ":{\"code\":\"0x5b5f56\"}}]";
    const out_of_gas = "out of gas: gas required exceeds: 21248\"}";
    const looping = call ++ ",\"gas\":\"0x5300\"}," ++ loop;
    try expect_failure(h, "eth_call", looping, "-32003", out_of_gas);
    // Fee fields: the base fee check, conflicts, and the caller's allowance.
    const low_fee = "max fee per gas less than block base fee\"}";
    try expect_failure(h, "eth_call", call ++ ",\"maxFeePerGas\":\"0x1\"}]", "-32000", low_fee);
    try expect_contains(try h.request("eth_call", call ++ ",\"gasPrice\":\"0x1\"," ++
        "\"maxFeePerGas\":\"0x1\"}]"), "{\"code\":-32602,\"message\":\"both gasPrice and " ++
        "(maxFeePerGas or maxPriorityFeePerGas) specified\"}");
    const poor = "[{\"from\":" ++ poor_sender ++ ",\"to\":" ++ override_target;
    const priced = poor ++ ",\"gasPrice\":\"0x1\"}]";
    // As Nethermind (and geth), the 21000 transfer shortcut needs the sender to fund it.
    const allowance = "gas required exceeds allowance (0)\"}";
    try expect_failure(h, "eth_estimateGas", priced, "-32000", allowance);
    const priced_create = "[{\"from\":" ++ poor_sender ++ ",\"gasPrice\":\"0x1\"}]";
    try expect_failure(h, "eth_estimateGas", priced_create, "-32000", allowance);
    try expect_contains(try h.request("eth_call", poor ++ ",\"gasPrice\":\"0x1\"," ++
        "\"value\":\"0x1\"}]"), "{\"code\":-32003,\"message\":\"insufficient funds for gas * " ++
        "price + value: have 0 want 1\"}");
    try expect_failure(h, "eth_createAccessList", priced, "-32000", "intrinsic gas too low\"}");
    const short = poor ++ ",\"value\":\"0x1\"}]";
    try expect_failure(h, "eth_call", short, "-32003", "EVM error: OutOfFunds\"}");
    // The RPC gas cap (50M) is the default gas and bounds a larger one (GAS returns the
    // cap less 21000 and the GAS opcode's 2).
    const gas_left = "\"latest\",{" ++ override_target ++ ":{\"code\":\"0x5a5f5260205ff3\"}}]";
    const capped = "\"result\":\"0x" ++ zeros_62[0..57] ++ "2fa9e76\"";
    try expect_contains(try h.request("eth_call", call ++ "}," ++ gas_left), capped);
    const above = call ++ ",\"gas\":\"0x5f5e100\"}," ++ gas_left;
    try expect_contains(try h.request("eth_call", above), capped);
    // reth's estimate stops within 1.5%: a bare create needs 53000 and reports 53793.
    const create = try h.request("eth_estimateGas", "[{\"from\":" ++ poor_sender ++ "}]");
    try expect_contains(create, "\"result\":\"0xd221\"");
}

test "eth: seeded fuzz of eth_call storage overrides" {
    var prng = Prng.init(0x6f76);
    const h = try Harness.create();
    defer h.destroy();
    for (0..32) |_| {
        const value = prng.int(u64);
        const slot_index = prng.below(4);
        var body: [1024]u8 = undefined;
        const format = request_prefix_format ++ "eth_call\",\"params\":[{{\"to\":" ++
            override_target ++ ",\"data\":\"0x{x:0>64}\"}},\"latest\",{{" ++ override_target ++
            ":{{\"code\":\"0x5f35545f5260205ff3\",\"stateDiff\":{{\"0x{x:0>64}\":" ++
            "\"0x{x:0>64}\"}}}}}}]}}";
        // CALLDATALOAD(0) is the slot read; only the overridden slot holds `value`.
        const read = if (prng.chance(1, 2)) slot_index else slot_index + 1;
        const text = try h.request_runtime(
            try std.fmt.bufPrint(&body, format, .{ read, slot_index, value }),
        );
        var expected: [96]u8 = undefined;
        const want: u64 = if (read == slot_index) value else 0;
        try expect_contains(text, try std.fmt.bufPrint(&expected, "\"result\":\"0x{x:0>64}\"", .{
            want,
        }));
    }
}

const sender_at = "\"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\"";
const empty_storage_root =
    "\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"";

test "eth: eth_getAccount, eth_getAccountInfo and eth_getHeaderBy* read accounts and headers" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    const before = try h.mine(12);
    var buffer: [256]u8 = undefined;
    try expect_contains(try send_raw(h, try transfer_raw(&buffer, 0)), "\"result\":\"0x");
    const after = try h.mine(24);
    const account = try h.request("eth_getAccount", "[" ++ sender_at ++ ",\"latest\"]");
    try expect_contains(account, "\"nonce\":\"0x1\"");
    try expect_contains(account, "\"storageRoot\":" ++ empty_storage_root);
    // The block before the transfer, from the history window.
    var body: [256]u8 = undefined;
    const old = try h.request_runtime(try std.fmt.bufPrint(
        &body,
        request_prefix_format ++ "eth_getAccount\",\"params\":[" ++ sender_at ++
            ",\"0x{x}\"]}}",
        .{&before.bytes},
    ));
    try expect_contains(old, "\"nonce\":\"0x0\"");
    const code_hash = primitives.keccak256(&counter_code).bytes;
    var expected: [96]u8 = undefined;
    const contract = try h.request("eth_getAccount", "[" ++ counter_at ++ ",\"latest\"]");
    try expect_contains(contract, try std.fmt.bufPrint(&expected, "\"codeHash\":\"0x{x}\"", .{
        &code_hash,
    }));
    const absent = "[\"0x00000000000000000000000000000000000000aa\",\"latest\"]";
    try expect_contains(try h.request("eth_getAccount", absent), "\"result\":null");
    const info = try h.request("eth_getAccountInfo", "[" ++ counter_at ++ ",\"latest\"]");
    try expect_contains(info, "\"code\":\"" ++ counter_hex ++ "\"");
    try expect_contains(
        try h.request("eth_getAccountInfo", absent),
        "{\"balance\":\"0x0\",\"nonce\":\"0x0\",\"code\":\"0x\"}",
    );
    // Headers: the block's header fields without a body.
    const header = try h.request("eth_getHeaderByNumber", "[\"latest\"]");
    const hash_field = try std.fmt.bufPrint(&expected, "\"hash\":\"0x{x}\"", .{&after.bytes});
    try expect_contains(header, hash_field);
    try testing.expect(std.mem.indexOf(u8, header, "transactions\"") == null);
    const by_hash = try h.request_runtime(try std.fmt.bufPrint(
        &body,
        request_prefix_format ++ "eth_getHeaderByHash\",\"params\":[\"0x{x}\"]}}",
        .{&after.bytes},
    ));
    try expect_contains(by_hash, hash_field);
    try expect_contains(try h.request("eth_getHeaderByNumber", "[\"0x99\"]"), "\"result\":null");
}

test "eth: seeded fuzz of eth_getAccount against eth_getBalance" {
    var prng = Prng.init(0x6163);
    const h = try Harness.create();
    defer h.destroy();
    for (0..32) |_| {
        // Mostly low addresses (dev accounts and precompiles live there), sometimes random.
        var address: [20]u8 = @splat(0);
        if (prng.chance(1, 2)) prng.fill(&address) else address[19] = @intCast(prng.below(16));
        var body: [256]u8 = undefined;
        // Responses share the harness buffer: keep a copy before the next request.
        var account_copy: [1024]u8 = undefined;
        const account_text = try h.request_runtime(try std.fmt.bufPrint(
            &body,
            request_prefix_format ++ "eth_getAccount\",\"params\":[\"0x{x}\"]}}",
            .{&address},
        ));
        @memcpy(account_copy[0..account_text.len], account_text);
        const account = account_copy[0..account_text.len];
        const balance = try h.request_runtime(try std.fmt.bufPrint(
            &body,
            request_prefix_format ++ "eth_getBalance\",\"params\":[\"0x{x}\"]}}",
            .{&address},
        ));
        const value_start = std.mem.indexOf(u8, balance, "\"result\":").? + 9;
        const value = balance[value_start .. balance.len - 1];
        if (std.mem.indexOf(u8, account, "\"result\":null") == null) {
            var expected: [96]u8 = undefined;
            const field = try std.fmt.bufPrint(&expected, "\"balance\":{s}", .{value});
            try expect_contains(account, field);
        } else try testing.expectEqualStrings("\"0x0\"", value);
    }
}

const call_config = "{\"tracer\":\"callTracer\"}";

fn trace_block_request(h: *Harness, block: []const u8, config: []const u8) ![]const u8 {
    var body: [8192]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&body);
    const format = request_prefix_format ++ "debug_traceBlock\",\"params\":[\"0x{x}\",{s}]}}";
    try stream.print(format, .{ block, config });
    return h.request_runtime(stream.buffered());
}

/// Mines (on a history-backed harness) a block calling the counter; returns its RLP.
fn traced_block(h: *Harness, out: []u8) ![]u8 {
    const counter = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    const counter_code = primitives.hex.decode_array(18, counter_hex[2..]) catch unreachable;
    try h.node.db.put_account(counter, 0, 0, &counter_code);
    _ = try h.mine(12);
    var buffer: [256]u8 = undefined;
    const raw = try contract_call_raw(&buffer, 0, counter);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    _ = try h.mine(24);
    return result_data(try h.request("debug_getRawBlock", "[\"latest\"]"), out);
}

test "eth: debug_traceBlock traces an RLP block like debug_traceBlockByNumber" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    var block_buffer: [4096]u8 = undefined;
    const block = try traced_block(h, &block_buffer);
    const configs = [_][]const u8{
        "{\"tracer\":\"callTracer\"}",
        "{\"tracer\":\"prestateTracer\"}",
        "{\"tracer\":\"4byteTracer\"}",
        "{\"tracer\":\"noopTracer\"}",
        "{\"tracer\":\"flatCallTracer\"}",
        "{\"disableStack\":true}",
    };
    for (configs) |config| {
        var copy: [8192]u8 = undefined;
        var body: [256]u8 = undefined;
        const stored = try h.request_runtime(try std.fmt.bufPrint(
            &body,
            request_prefix_format ++ "debug_traceBlockByNumber\",\"params\":[\"latest\",{s}]}}",
            .{config},
        ));
        @memcpy(copy[0..stored.len], stored);
        try expect_contains(stored, "\"result\":[{");
        const raw = try trace_block_request(h, block, config);
        try testing.expectEqualStrings(copy[0..stored.len], raw);
    }
    try expect_contains(try trace_block_request(h, block[1..], call_config), "invalid block RLP");
    // A block whose parent is unknown cannot be traced.
    var decoded = try consensus.block.Block.decode(block);
    decoded.header.parent_hash = .{ .bytes = @splat(0x77) };
    var orphan: [4096]u8 = undefined;
    const orphan_bytes = decoded.encode_to(&orphan);
    const orphan_text = try trace_block_request(h, orphan_bytes, call_config);
    try expect_contains(orphan_text, "parent block not found");
}

test "eth: seeded fuzz of debug_traceBlock with corrupted blocks" {
    var prng = Prng.init(0x7462);
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    var block_buffer: [4096]u8 = undefined;
    const block = try traced_block(h, &block_buffer);
    var corrupted: [4096]u8 = undefined;
    for (0..64) |_| {
        const bytes = corrupted[0..block.len];
        @memcpy(bytes, block);
        for (0..prng.range(1, 4)) |_| bytes[prng.below(block.len)] = prng.int(u8);
        const length = if (prng.chance(1, 4)) prng.range(1, block.len) else block.len;
        // Always an answer, never a crash: a trace, or an error.
        const text = try trace_block_request(h, bytes[0..length], call_config);
        try testing.expect(std.mem.indexOf(u8, text, "\"result\"") != null or
            std.mem.indexOf(u8, text, "\"error\"") != null);
    }
}

fn fuzz_trace_block(_: void, smith: *testing.Smith) anyerror!void {
    const h = try Harness.create();
    defer h.destroy();
    const bytes = smith.value([96]u8);
    const length = smith.value(u8) % bytes.len;
    const text = try trace_block_request(h, bytes[0..length], call_config);
    try testing.expect(std.mem.indexOf(u8, text, "\"error\"") != null);
}

test "eth: fuzz debug_traceBlock input" {
    try testing.fuzz({}, fuzz_trace_block, .{});
}

const StorageRangeFake = struct {
    hash: [32]u8 = @splat(0),
    number: u64 = 0,
    address_hash: [32]u8 = @splat(0),
    start: [32]u8 = @splat(0),
    max: u32 = 0,

    fn range(
        context: *anyopaque,
        hash: [32]u8,
        number: u64,
        address_hash: [32]u8,
        start: [32]u8,
        max: u32,
        out: []rpc_storage_range.Leaf,
    ) anyerror!rpc_storage_range.Range {
        const fake: *StorageRangeFake = @ptrCast(@alignCast(context));
        fake.* = .{
            .hash = hash,
            .number = number,
            .address_hash = address_hash,
            .start = start,
            .max = max,
        };
        const leaves = [_]rpc_storage_range.Leaf{
            .{ .key_hash = @splat(0x11), .value = 5 },
            .{ .key_hash = @splat(0x22), .value = 0x100 },
        };
        const count = @min(out.len, leaves.len);
        @memcpy(out[0..count], leaves[0..count]);
        return .{ .count = @intCast(count), .next = if (max > 2) null else @splat(0x33) };
    }
};
const rpc_storage_range = @import("storage_range.zig");
const hex_11 = "1111111111111111111111111111111111111111111111111111111111111111";
const hex_22 = "2222222222222222222222222222222222222222222222222222222222222222";
const hex_33 = "3333333333333333333333333333333333333333333333333333333333333333";
const hex_00 = "0000000000000000000000000000000000000000000000000000000000000000";

fn storage_range_request(
    h: *Harness,
    hash: primitives.B256,
    index: u64,
    start: []const u8,
    max: u32,
) ![]const u8 {
    var body: [512]u8 = undefined;
    const format = request_prefix_format ++ "debug_storageRangeAt\",\"params\":[\"0x{x}\"," ++
        "\"0x{x}\",\"0x0000000000000000000000000000000000000055\",\"0x{s}\",{d}]}}";
    return h.request_runtime(try std.fmt.bufPrint(&body, format, .{
        &hash.bytes, index, start, max,
    }));
}

test "eth: debug_storageRangeAt reads block-boundary states through the source" {
    const h = try Harness.create();
    defer h.destroy();
    _ = try h.mine(12);
    var buffer: [256]u8 = undefined;
    try expect_contains(try send_raw(h, try transfer_raw(&buffer, 0)), "\"result\":\"0x");
    const hash = try h.mine(24);
    const unavailable = try storage_range_request(h, hash, 0, "", 2);
    try expect_contains(unavailable, "storage ranges are unavailable");
    var fake: StorageRangeFake = .{};
    h.api.storage_range = .{ .context = &fake, .range = StorageRangeFake.range };
    // txIndex 0: the parent's state; the start key is left-padded to 32 bytes.
    const text = try storage_range_request(h, hash, 0, "abcd", 2);
    try testing.expectEqual(@as(u64, 1), fake.number);
    try testing.expectEqual(@as(u32, 2), fake.max);
    try testing.expectEqual(@as(u16, 0xabcd), std.mem.readInt(u16, fake.start[30..32], .big));
    const address = primitives.hex.decode_array(20, counter_at[3..43]) catch unreachable;
    try testing.expectEqualSlices(u8, &primitives.keccak256(&address).bytes, &fake.address_hash);
    try expect_contains(text, "\"0x" ++ hex_11 ++ "\":{\"key\":null" ++
        ",\"value\":\"0x" ++ zeros_62 ++ "05\"}");
    try expect_contains(text, "\"0x" ++ hex_22 ++ "\":{\"key\":null");
    try expect_contains(text, "\"nextKey\":\"0x" ++ hex_33 ++ "\"");
    // Past the last transaction: the block's own state; the range ends.
    try expect_contains(try storage_range_request(h, hash, 1, "", 5), "\"nextKey\":null");
    try testing.expectEqual(@as(u64, 2), fake.number);
    const middle = try storage_range_request(h, try h.mine(36), 0, "", 1);
    try expect_contains(middle, "\"result\"");
    try testing.expectEqual(@as(u64, 3), fake.number); // An empty block's states coincide.
    const too_long = try storage_range_request(h, hash, 0, "00" ++ hex_00, 1);
    try expect_contains(too_long, "keyStart is at most 32 bytes");
    const unknown = try storage_range_request(h, .{ .bytes = @splat(9) }, 0, "", 1);
    try expect_contains(unknown, "block not found");
}

test "eth: seeded fuzz of debug_storageRangeAt start keys and limits" {
    var prng = Prng.init(0x7372);
    for (0..64) |_| {
        var bytes: [40]u8 = undefined;
        prng.fill(&bytes);
        const length = prng.below(bytes.len + 1);
        const key = rpc_storage_range.start_key(bytes[0..length]);
        const max = prng.int(u32);
        var text: [16]u8 = undefined;
        const decimal = try std.fmt.bufPrint(&text, "{d}", .{max});
        try testing.expectEqual(@as(?u64, max), rpc_storage_range.max_result_of(decimal));
        const hex = try std.fmt.bufPrint(&text, "\"0x{x}\"", .{max});
        try testing.expectEqual(@as(?u64, max), rpc_storage_range.max_result_of(hex));
        try testing.expect(rpc_storage_range.max_result_of(text[1..hex.len]) == null);
        if (length > 32) {
            try testing.expect(key == null);
        } else {
            try testing.expectEqualSlices(u8, bytes[0..length], key.?[32 - length ..]);
            for (key.?[0 .. 32 - length]) |byte| try testing.expectEqual(@as(u8, 0), byte);
        }
    }
}

fn fuzz_start_key(_: void, smith: *testing.Smith) anyerror!void {
    const bytes = smith.value([40]u8);
    const length = smith.value(u8) % (bytes.len + 1);
    const key = rpc_storage_range.start_key(bytes[0..length]);
    try testing.expectEqual(length > 32, key == null);
    _ = rpc_storage_range.max_result_of(bytes[0..length]);
}

test "eth: fuzz debug_storageRangeAt start keys" {
    try testing.fuzz({}, fuzz_start_key, .{});
}

test "eth: debug_storageRangeAt reads the head trie and the history window" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    try h.node.db.trie().track_changes(testing.allocator);
    try h.node.chain.attach_history(&store);
    h.api.storage_range = .of_chain(h.api.chain);
    var block_buffer: [4096]u8 = undefined;
    _ = try traced_block(h, &block_buffer); // Block 2 calls the counter: slot 0 becomes 1.
    const record_hash = h.api.chain.state_hash;
    const before = try storage_range_request(h, .{ .bytes = record_hash }, 0, "", 8);
    try expect_contains(before, "{\"storage\":{},\"nextKey\":null}");
    const after = try storage_range_request(h, .{ .bytes = record_hash }, 1, "", 8);
    const slot_hash = primitives.keccak256(&@as([32]u8, @splat(0))).bytes;
    var expected: [256]u8 = undefined;
    try expect_contains(after, try std.fmt.bufPrint(
        &expected,
        "{{\"storage\":{{\"0x{x}\":{{\"key\":null,\"value\":\"0x{s}01\"}}}},\"nextKey\":null}}",
        .{ &slot_hash, zeros_62 },
    ));
    // Past the only slot: an empty range.
    var start: [64]u8 = undefined;
    var past = slot_hash;
    past[31] +%= 1;
    const tail = try std.fmt.bufPrint(&start, "{x}", .{&past});
    const empty = try storage_range_request(h, .{ .bytes = record_hash }, 1, tail, 8);
    try expect_contains(empty, "\"storage\":{}");
}

fn validated_entry(out: []u8, sender: []const u8, raw: []const u8) ![]const u8 {
    return std.fmt.bufPrint(out, "{{\"sender\":{s},\"raw\":\"0x{x}\"}}", .{ sender, raw });
}

fn insert_request(h: *Harness, method: []const u8, params: []const u8) ![]const u8 {
    var body: [4096]u8 = undefined;
    const format = request_prefix_format ++ "{s}\",\"params\":[{s}]}}";
    return h.request_runtime(try std.fmt.bufPrint(&body, format, .{ method, params }));
}

test "eth: base_insertValidatedTransaction pools forwarded transactions by their sender" {
    const h = try Harness.create();
    defer h.destroy();
    var buffer: [256]u8 = undefined;
    const raw = try transfer_raw(&buffer, 0);
    var entry: [512]u8 = undefined;
    const one = "base_insertValidatedTransaction";
    const text = try validated_entry(&entry, sender_at, raw);
    try expect_contains(try insert_request(h, one, text), "\"result\":null");
    const hash = primitives.keccak256(raw);
    try testing.expect(h.api.pool.?.get(hash) != null);
    const again = try insert_request(h, one, text);
    try expect_contains(again, "-32603");
    try expect_contains(again, "pool rejected transaction: already imported");
    // The sender is trusted: an unfunded one is refused by the pool's balance check.
    const unfunded = "\"0x00000000000000000000000000000000000000aa\"";
    var raw_buffer: [256]u8 = undefined;
    const other = try validated_entry(&entry, unfunded, try transfer_raw(&raw_buffer, 1));
    try expect_contains(try insert_request(h, one, other), "InsufficientFunds");
    const extension = "{\"sender\":" ++ sender_at ++ ",\"raw\":\"0x01\",\"extra\":1}";
    const refused = try insert_request(h, one, extension);
    try expect_contains(refused, "transaction extensions are disabled");
    try expect_contains(try insert_request(h, one, "{\"raw\":\"0x01\"}"), "-32602");
}

test "eth: base_insertValidatedTransactions answers each entry and parses all first" {
    const h = try Harness.create();
    defer h.destroy();
    var buffers: [2][256]u8 = undefined;
    const first = try transfer_raw(&buffers[0], 0);
    const second = try transfer_raw(&buffers[1], 1);
    var entries: [3][512]u8 = undefined;
    var params: [2048]u8 = undefined;
    const batch = "base_insertValidatedTransactions";
    // A malformed entry fails the call; nothing before it was inserted.
    const malformed = try std.fmt.bufPrint(&params, "[{s},{{\"raw\":\"0x01\"}}]", .{
        try validated_entry(&entries[0], sender_at, first),
    });
    try expect_contains(try insert_request(h, batch, malformed), "\"error\"");
    try testing.expect(h.api.pool.?.get(primitives.keccak256(first)) == null);
    const mixed = try std.fmt.bufPrint(&params, "[{s},{s},{s}]", .{
        try validated_entry(&entries[0], sender_at, first),
        try validated_entry(&entries[1], sender_at, first),
        try validated_entry(&entries[2], sender_at, second[0 .. second.len - 1]),
    });
    const text = try insert_request(h, batch, mixed);
    try expect_contains(text, "\"result\":[null,{\"code\":-32603");
    try expect_contains(text, "already imported\"},{\"code\":-32602");
    try expect_contains(text, "invalid transaction: ");
    try expect_contains(try insert_request(h, batch, "[]"), "\"result\":[]");
}

test "eth: seeded fuzz of base_insertValidatedTransactions against a pool model" {
    var prng = Prng.init(0x6976);
    const h = try Harness.create();
    defer h.destroy();
    var next_nonce: u64 = 0;
    for (0..8) |_| {
        var buffers: [6][256]u8 = undefined;
        var entries: [6][512]u8 = undefined;
        var params: [4096]u8 = undefined;
        var stream: std.Io.Writer = .fixed(&params);
        var expected: [6]enum { added, duplicate, invalid } = undefined;
        const count = prng.range(1, 6);
        try stream.writeAll("[");
        for (0..count) |index| {
            if (index > 0) try stream.writeAll(",");
            const pick = prng.below(3);
            const nonce = if (pick == 1 and next_nonce > 0) next_nonce - 1 else next_nonce;
            var raw = try transfer_raw(&buffers[index], nonce);
            if (pick == 2) raw = raw[0 .. raw.len - 1];
            expected[index] = if (pick == 2) .invalid else if (nonce < next_nonce)
                .duplicate
            else
                .added;
            if (expected[index] == .added) next_nonce += 1;
            try stream.writeAll(try validated_entry(&entries[index], sender_at, raw));
        }
        try stream.writeAll("]");
        const text = try insert_request(h, "base_insertValidatedTransactions", stream.buffered());
        var nulls: usize = 0;
        var duplicates: usize = 0;
        var invalids: usize = 0;
        for (expected[0..count]) |want| switch (want) {
            .added => nulls += 1,
            .duplicate => duplicates += 1,
            .invalid => invalids += 1,
        };
        try testing.expectEqual(nulls, count_of(text, "null"));
        try testing.expectEqual(duplicates, count_of(text, "already imported"));
        try testing.expectEqual(invalids, count_of(text, "invalid transaction"));
    }
}

fn fuzz_validated_item(_: void, smith: *testing.Smith) anyerror!void {
    const bytes = smith.value([64]u8);
    const length = smith.value(u8) % bytes.len;
    var scanner = json.Scanner.init(bytes[0..length]);
    var space: [64]u8 = undefined;
    const first = scanner.next() catch return;
    if (first.tag != .object_begin) return;
    const item = rpc_insert_validated.parse_item(&scanner, &space) catch return;
    try testing.expect(item.raw.len > 0);
}

const rpc_insert_validated = @import("insert_validated.zig");

test "eth: fuzz base_insertValidatedTransaction entries" {
    try testing.fuzz({}, fuzz_validated_item, .{});
}

fn chain_account(context: *anyopaque, address: [20]u8) txpool.Account {
    const h: *Harness = @ptrCast(@alignCast(context));
    const account = h.node.db.get_account(address) orelse return .{ .nonce = 0, .balance = 0 };
    return .{ .nonce = account.nonce, .balance = account.balance };
}

test "eth: base_sendRawTransactionValidity through the pool sink stores the predicates" {
    const h = try Harness.create();
    defer h.destroy();
    var store = try txpool.validity_store.Store.init(testing.allocator, 4, 256);
    defer store.deinit(testing.allocator);
    var sink: txpool.validity_store.PoolSink = .{
        .pool = h.api.pool.?,
        .store = &store,
        .accounts = .{ .context = h, .account = chain_account },
    };
    h.api.validity_sink = .of_pool_sink(&sink);
    var buffer: [256]u8 = undefined;
    const raw = try transfer_raw(&buffer, 0);
    const predicates = "[{\"type\":\"block_number\",\"params\":" ++
        "{\"op\":\"<=\",\"value\":\"0x10\"}}]";
    try expect_contains(try validity_request(h, raw, predicates), "\"result\":\"0x");
    const hash = primitives.keccak256(raw);
    try testing.expect(h.api.pool.?.get(hash) != null);
    try testing.expectEqual(@as(usize, 1), store.get(hash).?.len);
    // The same transaction again: the pool refuses it and the store keeps one entry.
    try expect_contains(try validity_request(h, raw, predicates), "AlreadyKnown");
    try testing.expectEqual(@as(u32, 1), store.count());
    // Past block 0x10 it is evicted from both.
    try testing.expectEqual(@as(u32, 1), store.prune(h.api.pool.?, 0x11));
    try testing.expect(h.api.pool.?.get(hash) == null);
}

fn raw_hex_result(out: []u8, raw: []const u8) ![]const u8 {
    return std.fmt.bufPrint(out, "\"result\":\"0x{x}\"", .{raw});
}

test "eth: eth_getRawTransaction* return EIP-2718 bytes from the pool and the chain" {
    const h = try Harness.create();
    defer h.destroy();
    var buffer: [256]u8 = undefined;
    const raw = try transfer_raw(&buffer, 0);
    try expect_contains(try send_raw(h, raw), "\"result\":\"0x");
    var expected: [600]u8 = undefined;
    const want = try raw_hex_result(&expected, raw);
    var body: [256]u8 = undefined;
    const by_hash_format = request_prefix_format ++
        "eth_getRawTransactionByHash\",\"params\":[\"0x{x}\"]}}";
    const hash = primitives.keccak256(raw).bytes;
    const by_hash = try std.fmt.bufPrint(&body, by_hash_format, .{&hash});
    try expect_contains(try h.request_runtime(by_hash), want); // Pooled.
    const block = try h.mine(12);
    try expect_contains(try h.request_runtime(by_hash), want); // Mined.
    const by_number = "eth_getRawTransactionByBlockNumberAndIndex";
    try expect_contains(try h.request(by_number, "[\"latest\",\"0x0\"]"), want);
    try expect_contains(try h.request(by_number, "[\"latest\",\"0x1\"]"), "\"result\":null");
    const by_block_hash = try std.fmt.bufPrint(&body, request_prefix_format ++
        "eth_getRawTransactionByBlockHashAndIndex\",\"params\":[\"0x{x}\",\"0x0\"]}}", .{
        &block.bytes,
    });
    try expect_contains(try h.request_runtime(by_block_hash), want);
    const unknown = try std.fmt.bufPrint(&body, by_hash_format, .{&@as([32]u8, @splat(7))});
    try expect_contains(try h.request_runtime(unknown), "\"result\":null");
    try expect_contains(try h.request("eth_mining", "[]"), "\"result\":false");
    try expect_contains(try h.request("eth_hashrate", "[]"), "\"result\":\"0x0\"");
    try expect_contains(try h.request("eth_protocolVersion", "[]"), "\"result\":\"0x44\"");
}

test "eth: seeded fuzz of eth_getRawTransactionByBlockNumberAndIndex" {
    var prng = Prng.init(0x7277);
    const h = try Harness.create();
    defer h.destroy();
    var buffers: [6][256]u8 = undefined;
    var raws: [6][]const u8 = undefined;
    const count = prng.range(1, 6);
    for (raws[0..count], 0..) |*raw, nonce| {
        raw.* = try transfer_raw(&buffers[nonce], nonce);
        try expect_contains(try send_raw(h, raw.*), "\"result\":\"0x");
    }
    _ = try h.mine(12);
    for (0..32) |_| {
        const index = prng.below(count + 3);
        var body: [256]u8 = undefined;
        const text = try h.request_runtime(try std.fmt.bufPrint(&body, request_prefix_format ++
            "eth_getRawTransactionByBlockNumberAndIndex\",\"params\":[\"latest\",\"0x{x}\"]}}", .{
            index,
        }));
        if (index >= count) {
            try expect_contains(text, "\"result\":null");
            continue;
        }
        // Pool order may differ from submission order: the bytes are one of the sent ones.
        var found = false;
        for (raws[0..count]) |raw| {
            var expected: [600]u8 = undefined;
            if (std.mem.indexOf(u8, text, try raw_hex_result(&expected, raw)) != null) found = true;
        }
        try testing.expect(found);
    }
}

fn fuzz_raw_by_index(_: void, smith: *testing.Smith) anyerror!void {
    const h = try Harness.create();
    defer h.destroy();
    var body: [256]u8 = undefined;
    const text = try h.request_runtime(try std.fmt.bufPrint(&body, request_prefix_format ++
        "eth_getRawTransactionByBlockNumberAndIndex\",\"params\":[\"latest\",\"0x{x}\"]}}", .{
        smith.value(u64),
    }));
    try expect_contains(text, "\"result\":null"); // The genesis block has no transactions.
}

test "eth: fuzz eth_getRawTransactionByBlockNumberAndIndex indexes" {
    try testing.fuzz({}, fuzz_raw_by_index, .{});
}

const transfer_sender_hex = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

fn sender_nonce_request(h: *Harness, sender_hex: []const u8, nonce: u64) ![]const u8 {
    var body: [256]u8 = undefined;
    return h.request_runtime(try std.fmt.bufPrint(&body, request_prefix_format ++
        "eth_getTransactionBySenderAndNonce\",\"params\":[\"{s}\",\"0x{x}\"]}}", .{
        sender_hex, nonce,
    }));
}

fn expect_hash_of(text: []const u8, raw: []const u8) !void {
    var expected: [80]u8 = undefined;
    const hash = primitives.keccak256(raw).bytes;
    try expect_contains(text, try std.fmt.bufPrint(&expected, "\"hash\":\"0x{x}\"", .{&hash}));
}

/// Mines `blocks` blocks of one transfer each (nonces 0..blocks), then pools nonce `blocks`.
fn sender_nonce_chain(h: *Harness, buffers: [][256]u8, raws: [][]const u8, blocks: u64) !void {
    std.debug.assert(raws.len == blocks + 1);
    for (raws, 0..) |*raw, nonce| {
        raw.* = try transfer_raw(&buffers[nonce], nonce);
        try expect_contains(try send_raw(h, raw.*), "\"result\":\"0x");
        if (nonce < blocks) _ = try h.mine(12 + 2 * nonce);
    }
}

test "eth: eth_getTransactionBySenderAndNonce finds pooled and mined transactions" {
    const h = try Harness.create();
    defer h.destroy();
    var buffers: [4][256]u8 = undefined;
    var raws: [4][]const u8 = undefined;
    try sender_nonce_chain(h, &buffers, &raws, 3);
    for (raws, 0..) |raw, nonce| {
        const text = try sender_nonce_request(h, transfer_sender_hex, nonce);
        try expect_hash_of(text, raw);
        const mined = if (nonce < 3) "\"blockNumber\":\"0x" else "\"blockNumber\":null";
        try expect_contains(text, mined);
    }
    try expect_contains(try sender_nonce_request(h, transfer_sender_hex, 4), "\"result\":null");
    const stranger = "0x00000000000000000000000000000000000000aa";
    try expect_contains(try sender_nonce_request(h, stranger, 0), "\"result\":null");
}

fn sender_nonce_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    const h = try Harness.create();
    defer h.destroy();
    var store = try meter_history();
    defer store.deinit(testing.allocator);
    if (prng.chance(2, 3)) {
        try h.node.db.trie().track_changes(testing.allocator);
        try h.node.chain.attach_history(&store);
    }
    // Up to 12 blocks against an 8-block window: some lookups fall below it.
    const blocks = prng.range(1, 12);
    var buffers: [13][256]u8 = undefined;
    var raws: [13][]const u8 = undefined;
    try sender_nonce_chain(h, buffers[0 .. blocks + 1], raws[0 .. blocks + 1], blocks);
    for (0..8) |_| {
        const nonce = prng.below(blocks + 3);
        const text = try sender_nonce_request(h, transfer_sender_hex, nonce);
        if (nonce <= blocks) try expect_hash_of(text, raws[nonce]) else {
            try expect_contains(text, "\"result\":null");
        }
    }
}

test "eth: seeded fuzz of eth_getTransactionBySenderAndNonce" {
    for (0..6) |seed| try sender_nonce_scenario(seed);
}

fn fuzz_sender_nonce(_: void, smith: *testing.Smith) anyerror!void {
    const h = try Harness.create();
    defer h.destroy();
    const text = try sender_nonce_request(h, transfer_sender_hex, smith.value(u64));
    try expect_contains(text, "\"result\":null"); // Nothing sent: no nonce matches.
}

test "eth: fuzz eth_getTransactionBySenderAndNonce nonces" {
    try testing.fuzz({}, fuzz_sender_nonce, .{});
}

// ---- eth_createAccessList (reth's AccessListInspector) and base_meterBundle opcodeGas ----

inline fn address_hex(comptime byte: []const u8) []const u8 {
    const zeros: [38]u8 = @splat('0');
    return "\"0x" ++ zeros ++ byte ++ "\"";
}

inline fn slot_hex(comptime byte: []const u8) []const u8 {
    const zeros: [62]u8 = @splat('0');
    return "\"0x" ++ zeros ++ byte ++ "\"";
}

/// 0x41 reads its slot 7, the balance of 0x44 and calls 0x42, which reads its slot 1 and
/// the code size of 0x55 and reverts; 0x41 then stops.
fn put_access_list_contracts(h: *Harness) !void {
    const caller = [_]u8{
        0x60, 0x07, 0x54, 0x50, 0x60, 0x44, 0x31, 0x50, // PUSH1 7 SLOAD POP PUSH1 0x44 BALANCE POP
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x42, 0x5a, // PUSH0 x5 PUSH1 0x42 GAS
        0xf1, 0x50, 0x00, // CALL POP STOP
    };
    // PUSH1 1 SLOAD POP PUSH1 0x55 EXTCODESIZE POP PUSH0 PUSH0 REVERT.
    const reverter = [_]u8{ 0x60, 0x01, 0x54, 0x50, 0x60, 0x55, 0x3b, 0x50, 0x5f, 0x5f, 0xfd };
    var address: [20]u8 = @splat(0);
    address[19] = 0x41;
    try h.node.db.put_account(address, 0, 1, &caller);
    address[19] = 0x42;
    try h.node.db.put_account(address, 0, 1, &reverter);
    _ = try h.mine(12);
}

test "eth: eth_createAccessList follows reth's access list inspector" {
    const h = try Harness.create();
    defer h.destroy();
    try put_access_list_contracts(h);
    // The request's untouched 0x66 stays; its seeded slot 9 of the excluded `to` stays too
    // (geth, Nethermind: only a slotless excluded account goes), as does the slot `to`
    // reads; the reverted frame's accesses stay.
    const call = "[{\"to\":" ++ address_hex("41") ++ ",\"accessList\":[{\"address\":" ++
        address_hex("66") ++ ",\"storageKeys\":[" ++ slot_hex("01") ++ "]},{\"address\":" ++
        address_hex("41") ++ ",\"storageKeys\":[" ++ slot_hex("09") ++ "]}]}]";
    // Second run: 21000 + 5 * 2400 + 4 * 1900 intrinsic; 0x41 runs 327 gas with every
    // access warm, 0x42 214 (PUSH1 3, SLOAD 100, POP 2, PUSH1 3, EXTCODESIZE 100, POP 2,
    // PUSH0 PUSH0 4): 41141.
    const expected = "\"result\":{\"accessList\":[{\"address\":" ++ address_hex("41") ++
        ",\"storageKeys\":[" ++ slot_hex("07") ++ "," ++ slot_hex("09") ++
        "]},{\"address\":" ++ address_hex("42") ++
        ",\"storageKeys\":[" ++ slot_hex("01") ++ "]},{\"address\":" ++ address_hex("44") ++
        ",\"storageKeys\":[]},{\"address\":" ++ address_hex("55") ++
        ",\"storageKeys\":[]},{\"address\":" ++ address_hex("66") ++ ",\"storageKeys\":[" ++
        slot_hex("01") ++ "]}],\"gasUsed\":\"0xa0b5\"}";
    try testing.expectEqualStrings(expected, try h.request("eth_createAccessList", call));
}

test "eth: eth_createAccessList converges past a failed run, with its gas and error" {
    const h = try Harness.create();
    defer h.destroy();
    try put_access_list_contracts(h);
    const call = "[{\"to\":" ++ address_hex("42") ++ ",\"accessList\":[{\"address\":" ++
        address_hex("77") ++ ",\"storageKeys\":[]}]}]";
    // The failed run lists more, so it runs again with that list (geth, Nethermind); the
    // gas is that run's: 21000 + 3 * 2400 + 1900 intrinsic; PUSH1 3, warm SLOAD 100, POP 2,
    // PUSH1 3, warm EXTCODESIZE 100, POP 2, PUSH0 PUSH0 4: 30314.
    const expected = "\"result\":{\"accessList\":[{\"address\":" ++ address_hex("42") ++
        ",\"storageKeys\":[" ++ slot_hex("01") ++ "]},{\"address\":" ++ address_hex("55") ++
        ",\"storageKeys\":[]},{\"address\":" ++ address_hex("77") ++
        ",\"storageKeys\":[]}],\"gasUsed\":\"0x766a\",\"error\":\"execution reverted\"}";
    try testing.expectEqualStrings(expected, try h.request("eth_createAccessList", call));
}

test "eth: eth_createAccessList keeps the callee's slot when the next run stops sooner" {
    const h = try Harness.create();
    defer h.destroy();
    // KECCAK256 of 6 KiB (1835 gas with its PUSHes and memory), POP, SLOAD(0), then loop
    // until out of gas. The first run reads slot 0; with the list attached (4300 more
    // intrinsic gas) the second runs out of gas before the SLOAD. As geth and Nethermind,
    // the callee's listed slot stays, so the list converges on that run.
    const code = [_]u8{ 0x61, 0x18, 0x00, 0x5f, 0x20, 0x50, 0x5f, 0x54, 0x5b, 0x60, 0x08, 0x56 };
    var contract: [20]u8 = @splat(0);
    contract[19] = 0x5a;
    try h.node.db.put_account(contract, 0, 1, &code);
    _ = try h.mine(1);
    const call = "[{\"to\":" ++ address_hex("5a") ++ ",\"gas\":\"0x6590\"}]";
    const expected = "\"result\":{\"accessList\":[{\"address\":" ++ address_hex("5a") ++
        ",\"storageKeys\":[" ++ slot_hex("00") ++ "]}],\"gasUsed\":\"0x6590\",\"error\":";
    try expect_contains(try h.request("eth_createAccessList", call), expected);
}

test "eth: base_meterBundle reports precompile opcodeGas" {
    const h = try Harness.create();
    defer h.destroy();
    // BN254_ADD and RIPEMD160 twice without input, then BN254_ADD on (1, 0), not a curve
    // point, with 0x1000 gas, which it spends.
    const code = [_]u8{
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x06, 0x5a, 0xf1, 0x50, // CALL 0x06
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x03, 0x5a, 0xf1, 0x50, // CALL 0x03
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 0x03, 0x5a, 0xf1, 0x50, // CALL 0x03
        0x60, 0x01, 0x5f, 0x52, // PUSH1 1 PUSH0 MSTORE
        0x5f, 0x5f, 0x60, 0x40,
        0x5f, 0x5f, 0x60, 0x06,
        0x61, 0x10, 0x00, 0xf1,
        0x50, 0x00,
    };
    var contract: [20]u8 = @splat(0);
    contract[19] = 0x48;
    try h.node.db.put_account(contract, 0, 1, &code);
    _ = try h.mine(12);
    var sha256: [20]u8 = @splat(0);
    sha256[19] = 0x02;
    var buffers: [3][256]u8 = undefined;
    const raws = [_][]const u8{
        try contract_call_raw(&buffers[0], 0, contract),
        // The transaction's own call counts: SHA256 of nothing costs 60.
        try contract_call_raw(&buffers[1], 1, sha256),
        try transfer_raw(&buffers[2], 2),
    };
    const text = try meter_bundle_request(h, &raws);
    const entry = "{\"contractAddress\":";
    try expect_contains(text, "\"opcodeGas\":[" ++ entry ++ address_hex("03") ++
        ",\"opcode\":\"RIPEMD160\",\"count\":2,\"gasUsed\":1200}," ++ entry ++
        address_hex("06") ++ ",\"opcode\":\"BN254_ADD\",\"count\":2,\"gasUsed\":4246}]}");
    try expect_contains(text, "\"opcodeGas\":[" ++ entry ++ address_hex("02") ++
        ",\"opcode\":\"SHA256\",\"count\":1,\"gasUsed\":60}]}");
    // Nothing metered: no `opcodeGas`.
    try testing.expectEqual(@as(usize, 2), count_of(text, "opcodeGas"));
}
