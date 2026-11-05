//! Flashblocks RPC tests. The consumer node (canonical genesis) serves the flashblocks
//! router over its pending state; the producer node, which imported the same blocks, serves
//! the plain eth router. Pending answers must equal the producer's canonical answers byte
//! for byte (blocks, receipts, balances, nonces), non-pending tags must fall through to the
//! consumer's canonical state, and pubsub must notify the latest flashblock. Seeded and
//! `std.testing.fuzz` request shapes never crash and always answer valid JSON.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const eth = @import("../rpc/eth.zig");
const fixture = @import("../node/test_fixture.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const harness_module = @import("state_executor_test.zig");
const flashblocks_rpc = @import("rpc.zig");
const pubsub = @import("pubsub.zig");

const Harness = harness_module.Harness;
const request_prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"";
const response_prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,";

/// RPC context over a harness: the flashblocks router on the consumer, the eth router on
/// the producer (heap-pinned).
const Rpc = struct {
    harness: *Harness,
    consumer_eth: eth.Api,
    producer_eth: eth.Api,
    api: flashblocks_rpc.Api,
    subscriptions: pubsub.Subscriptions = .{},
    items: [64][]const u8 = undefined,
    consumer_scratch: [1 << 16]u8 = undefined,
    producer_scratch: [1 << 16]u8 = undefined,
    out: [1 << 16]u8 = undefined,
    expected: [1 << 16]u8 = undefined,

    fn create() !*Rpc {
        const context = try testing.allocator.create(Rpc);
        errdefer testing.allocator.destroy(context);
        context.harness = try Harness.create();
        const consumer = context.harness.consumer;
        const producer = context.harness.producer;
        context.consumer_eth = .{
            .spec = consumer.spec,
            .chain = &consumer.chain,
            .pool = &consumer.pool,
            .scratch = &context.consumer_scratch,
        };
        context.producer_eth = .{
            .spec = producer.spec,
            .chain = &producer.chain,
            .pool = &producer.pool,
            .scratch = &context.producer_scratch,
        };
        context.subscriptions = .{};
        context.api = .{
            .eth = &context.consumer_eth,
            .pending = &context.harness.processor.pending,
            .state = context.harness.builder,
            .items = &context.items,
        };
        return context;
    }

    fn destroy(context: *Rpc) void {
        context.harness.destroy();
        testing.allocator.destroy(context);
    }

    /// The `result`/`error` part of the flashblocks router's answer.
    fn pending(context: *Rpc, body: []const u8) ![]const u8 {
        var out: std.Io.Writer = .fixed(&context.out);
        _ = flashblocks_rpc.Router.handle(&context.api, body, &out);
        return strip(out.buffered());
    }

    /// The same for the producer's plain eth router.
    fn canonical(context: *Rpc, body: []const u8) ![]const u8 {
        var out: std.Io.Writer = .fixed(&context.expected);
        _ = eth.Router.handle(&context.producer_eth, body, &out);
        return strip(out.buffered());
    }
};

fn strip(text: []const u8) ![]const u8 {
    try json.validate(text);
    try testing.expect(std.mem.startsWith(u8, text, response_prefix));
    return text[response_prefix.len .. text.len - 1];
}

fn body_of(buffer: []u8, method: []const u8, params: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}\",\"params\":{s}}}", .{
        request_prefix,
        method,
        params,
    }) catch unreachable;
}

fn hex_of(buffer: []u8, bytes: []const u8) []const u8 {
    assert(buffer.len >= 2 + bytes.len * 2);
    buffer[0] = '0';
    buffer[1] = 'x';
    _ = std.fmt.bufPrint(buffer[2..], "{x}", .{bytes}) catch unreachable;
    return buffer[0 .. 2 + bytes.len * 2];
}

/// `text` without its `"size"` field, copied into `out`.
fn without_size(out: []u8, text: []const u8) []const u8 {
    const start = std.mem.indexOf(u8, text, ",\"size\":\"").?;
    const value_start = start + ",\"size\":\"".len;
    const end = std.mem.indexOfScalarPos(u8, text, value_start, '"').? + 1;
    @memcpy(out[0..start], text[0..start]);
    const tail = text[end..];
    @memcpy(out[start..][0..tail.len], tail);
    return out[0 .. start + tail.len];
}

/// One block of three transfers and a deposit, pending on the consumer, canonical on
/// the producer.
fn produce_transfers(context: *Rpc) !void {
    const harness = context.harness;
    var buffers: [3][256]u8 = undefined;
    for (&buffers, 0..) |*buffer, n| try fixture.submit(harness.producer, 1, n, 5, buffer);
    var deposit_buffer: [256]u8 = undefined;
    const deposits = [_][]const u8{harness_module.deposit(&deposit_buffer, 1)};
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.transactions = &deposits;
    _ = try harness_module.produce_block(harness, harness.genesis(), &attributes, 2, 1);
}

test "flashblocks rpc: the pending block and receipts equal the producer's canonical ones" {
    const context = try Rpc.create();
    defer context.destroy();
    var body_buffer: [512]u8 = undefined;
    try testing.expectEqualStrings(
        try context.canonical(body_of(&body_buffer, "eth_getBlockByNumber", "[\"0x0\",false]")),
        try context.pending(body_of(&body_buffer, "eth_getBlockByNumber", "[\"pending\",false]")),
    );
    try produce_transfers(context);
    const view = flashblocks_rpc.pending_view(&context.api).?;
    const header = flashblocks_rpc.pending_header(&context.api, view);
    try testing.expectEqualSlices(u8, &view.record.hash.bytes, &header.hash().bytes);
    for ([_][]const u8{ "false", "true" }) |full| {
        var params: [64]u8 = undefined;
        const pending_params = try std.fmt.bufPrint(&params, "[\"pending\",{s}]", .{full});
        const want = try context.canonical(body_of(
            &body_buffer,
            "eth_getBlockByNumber",
            try std.fmt.bufPrint(params[32..], "[\"0x1\",{s}]", .{full}),
        ));
        try testing.expect(std.mem.indexOf(u8, want, "\"number\":\"0x1\"") != null);
        var want_copy: [1 << 15]u8 = undefined;
        const want_size = without_size(&want_copy, want);
        const pending_body = body_of(&body_buffer, "eth_getBlockByNumber", pending_params);
        const got = try context.pending(pending_body);
        // The eth lane reports the stored record's length as `size`; the pending block
        // reports its RLP block size.
        var got_copy: [1 << 15]u8 = undefined;
        try testing.expectEqualStrings(want_size, without_size(&got_copy, got));
    }
    for (view.block.hashes()) |hash| {
        var hex: [66]u8 = undefined;
        var params: [80]u8 = undefined;
        const text = try std.fmt.bufPrint(&params, "[\"{s}\"]", .{hex_of(&hex, &hash.bytes)});
        const receipt_body = body_of(&body_buffer, "eth_getTransactionReceipt", text);
        const want = try context.canonical(receipt_body);
        const got = try context.pending(receipt_body);
        try testing.expectEqualStrings(want, got);
    }
    // "latest" is still the consumer's canonical genesis.
    const latest_body = body_of(&body_buffer, "eth_getBlockByNumber", "[\"latest\",false]");
    const latest = try context.pending(latest_body);
    try testing.expect(std.mem.indexOf(u8, latest, "\"number\":\"0x0\"") != null);
}

test "flashblocks rpc: pending balances, nonces and calls; other tags fall through" {
    const context = try Rpc.create();
    defer context.destroy();
    try produce_transfers(context);
    var body_buffer: [512]u8 = undefined;
    var hex: [42]u8 = undefined;
    var params: [256]u8 = undefined;
    const recipient = hex_of(&hex, &fixture.address_of(9).bytes);
    for ([_][]const u8{ "eth_getBalance", "eth_getTransactionCount" }) |method| {
        for ([_][]const u8{ "\"pending\"", "\"latest\"" }) |tag| {
            for ([_]u8{ 1, 9 }) |n| {
                var address_hex: [42]u8 = undefined;
                const address = hex_of(&address_hex, &fixture.address_of(n).bytes);
                const text = try std.fmt.bufPrint(&params, "[\"{s}\",{s}]", .{ address, tag });
                const got = try context.pending(body_of(&body_buffer, method, text));
                // Pending equals the producer's head; latest equals the consumer's genesis.
                if (tag[1] == 'p') {
                    const want = try context.canonical(body_of(&body_buffer, method, text));
                    try testing.expectEqualStrings(want, got);
                } else {
                    const zero = n == 9 or std.mem.eql(u8, method, "eth_getTransactionCount");
                    if (zero) try testing.expectEqualStrings("\"result\":\"0x0\"", got);
                }
            }
        }
    }
    // Address 9 holds 15 wei only in the pending state.
    const call_object = "{{\"from\":\"{s}\",\"to\":\"{s}\",\"gas\":\"0x186a0\",\"value\":\"0xf\"}}";
    var to_hex: [42]u8 = undefined;
    const to = hex_of(&to_hex, &fixture.address_of(8).bytes);
    const pending_call = try std.fmt.bufPrint(&params, "[" ++ call_object ++ ",\"pending\"]", .{
        recipient,
        to,
    });
    const pending_result = try context.pending(body_of(&body_buffer, "eth_call", pending_call));
    try testing.expectEqualStrings("\"result\":\"0x\"", pending_result);
    const latest_call = try std.fmt.bufPrint(&params, "[" ++ call_object ++ ",\"latest\"]", .{
        recipient,
        to,
    });
    const latest_result = try context.pending(body_of(&body_buffer, "eth_call", latest_call));
    try testing.expect(std.mem.startsWith(u8, latest_result, "\"error\""));
}

// Init code returning the runtime `PUSH1 0 PUSH1 0 LOG0 STOP` (an empty log).
const log_init_code = [_]u8{
    0x60, 0x06, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x06, 0x60, 0x00, 0xf3,
    0x60, 0x00, 0x60, 0x00, 0xa0, 0x00,
};

const Sink = struct {
    messages: u32 = 0,
    logs: u32 = 0,
    hashes: u32 = 0,
    blocks: u32 = 0,
    full: u32 = 0,

    pub fn send(sink: *Sink, message: []const u8) !void {
        try json.validate(message);
        try testing.expect(std.mem.indexOf(u8, message, "\"eth_subscription\"") != null);
        sink.messages += 1;
        const result = std.mem.indexOf(u8, message, "\"result\":").? + "\"result\":".len;
        const value = message[result..];
        if (std.mem.startsWith(u8, value, "\"0x")) sink.hashes += 1;
        if (std.mem.indexOf(u8, value, "\"logIndex\"") != null and
            std.mem.indexOf(u8, value, "\"cumulativeGasUsed\"") == null and
            std.mem.indexOf(u8, value, "\"uncles\"") == null) sink.logs += 1;
        if (std.mem.indexOf(u8, value, "\"uncles\"") != null) sink.blocks += 1;
        if (std.mem.indexOf(u8, value, "\"cumulativeGasUsed\"") != null) sink.full += 1;
    }
};

fn subscribe(context: *Rpc, params: []const u8) ![]const u8 {
    var body_buffer: [512]u8 = undefined;
    return context.pending(body_of(&body_buffer, "eth_subscribe", params));
}

test "flashblocks rpc: pubsub notifies the latest flashblock" {
    const context = try Rpc.create();
    defer context.destroy();
    const harness = context.harness;
    // Over HTTP (no subscription table) subscribing fails.
    const refused = try subscribe(context, "[\"newFlashblocks\"]");
    try testing.expect(std.mem.startsWith(u8, refused, "\"error\""));
    context.api.subscriptions = &context.subscriptions;
    const first_id = try subscribe(context, "[\"newFlashblocks\"]");
    try testing.expectEqualStrings("\"result\":\"0x1\"", first_id);
    _ = try subscribe(context, "[\"newFlashblockTransactions\"]");
    _ = try subscribe(context, "[\"newFlashblockTransactions\",true]");
    _ = try subscribe(context, "[\"pendingLogs\",{\"topics\":[]}]");
    _ = try subscribe(context, "[\"newFlashblockTransactions\",{\"topics\":[]}]");
    const standard = try subscribe(context, "[\"newHeads\"]");
    try testing.expect(std.mem.startsWith(u8, standard, "\"error\""));
    try testing.expectEqual(@as(u32, 5), context.subscriptions.count);
    // Block 1 deploys the logging contract, block 2 calls it twice (one flashblock).
    var create_buffer: [256]u8 = undefined;
    const producer = harness.producer;
    try harness_module.submit(producer, 2, 0, .create, &log_init_code, 200_000, &create_buffer);
    const attributes = fixture.attributes_l2(2, 0xfe);
    const first = try harness_module.produce_block(harness, harness.genesis(), &attributes, 1, 1);
    const contract = primitives.create_address(fixture.address_of(2), 0);
    var call_buffers: [2][256]u8 = undefined;
    for (&call_buffers, 1..) |*buffer, nonce| {
        try harness_module.submit(producer, 2, nonce, .{ .call = contract }, &.{}, 100_000, buffer);
    }
    const second_attributes = fixture.attributes_l2(4, 0xfd);
    _ = try harness_module.produce_block(harness, first, &second_attributes, 1, 2);
    var sink: Sink = .{};
    var buffer: [1 << 15]u8 = undefined;
    const sent = try pubsub.notify(&context.api, &context.subscriptions, &buffer, &sink);
    // One block, two hashes, two full, two logs, two filtered (full) transactions.
    try testing.expectEqual(@as(u32, 9), sent);
    try testing.expectEqual(sent, sink.messages);
    try testing.expectEqual(@as(u32, 1), sink.blocks);
    try testing.expectEqual(@as(u32, 2), sink.hashes);
    try testing.expectEqual(@as(u32, 2), sink.logs);
    try testing.expectEqual(@as(u32, 4), sink.full);
    var body_buffer: [128]u8 = undefined;
    const removed = try context.pending(body_of(&body_buffer, "eth_unsubscribe", "[\"0x1\"]"));
    try testing.expectEqualStrings("\"result\":true", removed);
    const again = try context.pending(body_of(&body_buffer, "eth_unsubscribe", "[\"0x1\"]"));
    try testing.expectEqualStrings("\"result\":false", again);
}

const method_names = [_][]const u8{
    "eth_getBalance",
    "eth_getBlockByNumber",
    "eth_getTransactionReceipt",
    "eth_getTransactionCount",
    "eth_call",
    "eth_subscribe",
    "eth_unsubscribe",
    "eth_blockNumber",
};

const param_pieces = [_][]const u8{
    "\"pending\"",
    "\"latest\"",
    "\"0x1\"",
    "true",
    "null",
    "{}",
    "{\"to\":\"0x1111111111111111111111111111111111111111\"}",
    "\"0x0000000000000000000000000000000000000001\"",
    "\"newFlashblocks\"",
    "\"pendingLogs\"",
    "\"newFlashblockTransactions\"",
    "{\"topics\":[null]}",
    "[]",
    "1",
};

fn random_requests(context: *Rpc, prng: *Prng) !void {
    var body: [1024]u8 = undefined;
    for (0..48) |_| {
        var writer: std.Io.Writer = .fixed(&body);
        const method = method_names[prng.below(method_names.len)];
        try writer.print("{s}{s}\",\"params\":[", .{ request_prefix, method });
        const count = prng.below(4);
        for (0..count) |index| {
            if (index > 0) try writer.writeAll(",");
            try writer.writeAll(param_pieces[prng.below(param_pieces.len)]);
        }
        try writer.writeAll("]}");
        try fuzz_body(context, writer.buffered());
    }
}

fn fuzz_body(context: *Rpc, body: []const u8) !void {
    var out: std.Io.Writer = .fixed(&context.out);
    const outcome = flashblocks_rpc.Router.handle(&context.api, body, &out);
    if (outcome == .response) try json.validate(out.buffered());
}

test "flashblocks rpc: seeded fuzz of request shapes" {
    const context = try Rpc.create();
    defer context.destroy();
    context.api.subscriptions = &context.subscriptions;
    var prng = Prng.init(0xf1a5);
    try random_requests(context, &prng);
    try produce_transfers(context);
    try random_requests(context, &prng);
}

fn fuzz_rpc(context: *Rpc, smith: *testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    const len = smith.slice(&bytes);
    try fuzz_body(context, bytes[0..len]);
    var prng = Prng.init(smith.value(u64));
    try random_requests(context, &prng);
}

test "flashblocks rpc: fuzz" {
    const context = try Rpc.create();
    defer context.destroy();
    context.api.subscriptions = &context.subscriptions;
    try produce_transfers(context);
    try testing.fuzz(context, fuzz_rpc, .{});
}
