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
    // An explicit gas above the cap is still the caller's error.
    const over = try h.request("eth_call", "[{" ++ to ++ ",\"gas\":\"0x1c9c380\"},\"latest\"]");
    try expect_contains(over, "gas_cap_exceeded");
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
    // The default struct logger is not supported.
    const default = try h.request("debug_traceBlockByNumber", "[\"latest\"]");
    try expect_contains(default, "only callTracer");
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
    ), "only callTracer");
    // The executor's tracer is detached afterwards: a plain call still runs.
    try expect_contains(try h.request("eth_call", "[{\"to\":" ++ caller_at ++ "}]"), "result");
    try testing.expect(h.node.chain.executor.machine.tracer == null);
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
    try expect_contains(changes[0 .. changes.len - post.len], word_zero);
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
    try expect_contains(try h.request("eth_call", call ++ "null,{\"bogus\":1}]"), "-32602");
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
const hex_01 = "0101010101010101010101010101010101010101010101010101010101010101";
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
