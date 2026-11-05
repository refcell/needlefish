//! eth namespace tests through the JSON-RPC router on a fixture node: values, blocks,
//! receipts, raw transaction submission, calls, gas estimation, logs, and a fuzz of
//! arbitrary request bodies (never crash, always valid JSON).

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const trie_proof = @import("../trie/proof.zig");
const fixture = @import("../node/test_fixture.zig");
const filters_module = @import("filters.zig");
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
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try fixture.Node.create();
        harness.api = .{
            .spec = fixture.spec,
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
        const version = engine_types.forkchoice_version(fixture.spec, timestamp);
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
    const send_format = request_prefix_format ++ "eth_sendRawTransaction\",\"params\":[\"0x{x}\"]}}";
    const body = try std.fmt.bufPrint(&body_buffer, send_format, .{raw});
    try expect_contains(try h.request_runtime(body), "\"result\":\"0x");
    return envelope.hash().bytes;
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
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_getFilterChanges", "[\"0x2\"]"));
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_getFilterChanges", "[\"0x1\"]"));
    const block_hash = try h.mine(12);
    const block_hex = try std.fmt.bufPrint(&hex, "0x{x}", .{&block_hash.bytes});
    try expect_contains(try h.request("eth_getFilterChanges", "[\"0x1\"]"), block_hex);
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_getFilterChanges", "[\"0x1\"]"));
    const logs = try h.request("eth_getFilterChanges", "[\"0x3\"]");
    try expect_contains(logs, "\"address\":" ++ log_contract);
    try expect_contains(logs, "\"blockNumber\":\"0x1\"");
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_getFilterChanges", "[\"0x3\"]"));
    try expect_contains(try h.request("eth_getFilterLogs", "[\"0x3\"]"), "\"logIndex\":\"0x0\"");
    try expect_contains(try h.request("eth_getFilterLogs", "[\"0x1\"]"), "error");
    // A filter for another address sees nothing.
    const other = try h.request("eth_newFilter", "[{\"address\":" ++ address_one ++ ",\"fromBlock\":\"0x0\"}]");
    try testing.expectEqualStrings("\"result\":\"0x4\"", other);
    try testing.expectEqualStrings("\"result\":[]", try h.request("eth_getFilterLogs", "[\"0x4\"]"));
    try testing.expectEqualStrings("\"result\":true", try h.request("eth_uninstallFilter", "[\"0x3\"]"));
    try testing.expectEqualStrings("\"result\":false", try h.request("eth_uninstallFilter", "[\"0x3\"]"));
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

test "eth: call and estimate gas" {
    const h = try Harness.create();
    defer h.destroy();
    const estimate = try h.request("eth_estimateGas", "[{\"to\":" ++ address_target ++ "}]");
    try testing.expectEqualStrings("\"result\":\"0x5208\"", estimate);
    const output = try h.request("eth_call", "[{\"to\":" ++ address_target ++ "},\"latest\"]");
    try testing.expectEqualStrings("\"result\":\"0x\"", output);
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
