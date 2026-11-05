//! eth namespace tests through the JSON-RPC router on a fixture node: values, blocks,
//! receipts, raw transaction submission, calls, gas estimation, logs, and a fuzz of
//! arbitrary request bodies (never crash, always valid JSON).

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
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
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try fixture.Node.create_for(spec);
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
    try expect_contains(text, "\"error\":{\"code\":3,\"message\":\"execution reverted\"}");
    try expect_contains(text, "\"number\":\"0x2\",\"timestamp\":\"0x1000\"");
    try expect_contains(text, "\"number\":\"0x3\",\"timestamp\":\"0x100c\"");
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
    try expect_contains(try h.request("eth_simulateV1", gas), "\"code\":-38015");
    const backwards = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"number\":\"0x0\"}}]}]";
    try expect_contains(try h.request("eth_simulateV1", backwards), "\"code\":-38020");
    const validation = "[{\"blockStateCalls\":[],\"validation\":true}]";
    try expect_contains(try h.request("eth_simulateV1", validation), "not supported");
    const fee = "[{\"blockStateCalls\":[{\"blockOverrides\":{\"baseFeePerGas\":\"0x1\"}}]}]";
    try expect_contains(try h.request("eth_simulateV1", fee), "unsupported block override");
    try expect_contains(try h.request("eth_simulateV1", "[{}]"), "invalid params");
    const empty = try h.request("eth_simulateV1", "[{\"blockStateCalls\":[]}]");
    try testing.expectEqualStrings("\"result\":[]", empty);
}

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
    const pairing = "\"BLS12_PAIRING_CHECK\":\"0x000000000000000000000000000000000000000F\"";
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
