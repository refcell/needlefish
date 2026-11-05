//! Engine API JSON tests: a builder node and a follower node exchange blocks only through
//! the JSON-RPC router (forkchoiceUpdated + getPayload on one side, newPayload +
//! forkchoiceUpdated on the other), plus error codes and a fuzz of request bodies.

const std = @import("std");
const testing = std.testing;
const json = @import("../../utilities/json/root.zig");
const fixture = @import("../node/test_fixture.zig");
const eth = @import("eth.zig");
const engine_rpc = @import("engine.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Peer = struct {
    node: *fixture.Node,
    eth_api: eth.Api,
    api: engine_rpc.EngineApi,
    scratch: [1 << 16]u8 = undefined,
    out: [1 << 17]u8 = undefined,
    body: [1 << 17]u8 = undefined,

    fn create() !*Peer {
        const peer = try testing.allocator.create(Peer);
        errdefer testing.allocator.destroy(peer);
        peer.node = try fixture.Node.create();
        errdefer peer.node.destroy();
        peer.eth_api = .{
            .spec = fixture.spec,
            .chain = &peer.node.chain,
            .pool = &peer.node.pool,
            .scratch = &peer.scratch,
        };
        const engine = &peer.node.engine;
        peer.api = try engine_rpc.EngineApi.init(testing.allocator, engine, &peer.eth_api, .{
            .bytes = 1 << 16,
            .transactions_max = 64,
        });
        return peer;
    }

    fn destroy(peer: *Peer) void {
        peer.api.deinit(testing.allocator);
        peer.node.destroy();
        testing.allocator.destroy(peer);
    }

    /// Routes one request; returns the text after `"id":1,` minus the closing brace.
    fn call(peer: *Peer, method: []const u8, params: []const u8) ![]const u8 {
        const body = try std.fmt.bufPrint(
            &peer.body,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}",
            .{ method, params },
        );
        var out: std.Io.Writer = .fixed(&peer.out);
        _ = engine_rpc.Router.handle(&peer.api, body, &out);
        const text = out.buffered();
        try json.validate(text);
        const prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,";
        try testing.expect(std.mem.startsWith(u8, text, prefix));
        return text[prefix.len .. text.len - 1];
    }
};

fn hex32(hash: [32]u8) [66]u8 {
    var out: [66]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "0x{x}", .{&hash}) catch unreachable;
    return out;
}

fn forkchoice_params(buffer: []u8, head: [32]u8, attributes: ?u64) ![]const u8 {
    const h = hex32(head);
    const zero = hex32(@splat(0));
    if (attributes) |timestamp| return std.fmt.bufPrint(buffer,
        \\[{{"headBlockHash":"{s}","safeBlockHash":"{s}","finalizedBlockHash":"{s}"}},
        \\{{"timestamp":"0x{x}","prevRandao":"{s}","suggestedFeeRecipient":
        \\"0x0000000000000000000000000000000000000007","withdrawals":[],
        \\"parentBeaconBlockRoot":"{s}"}}]
    , .{ h, zero, zero, timestamp, zero, zero });
    return std.fmt.bufPrint(buffer,
        \\[{{"headBlockHash":"{s}","safeBlockHash":"{s}","finalizedBlockHash":"{s}"}},null]
    , .{ h, zero, zero });
}

/// Extracts `"name":"value"` (string values only) from a flat JSON text.
fn field(text: []const u8, comptime name: []const u8) ?[]const u8 {
    const key = "\"" ++ name ++ "\":\"";
    const start = (std.mem.indexOf(u8, text, key) orelse return null) + key.len;
    const end = std.mem.indexOfScalarPos(u8, text, start, '"') orelse return null;
    return text[start..end];
}

/// The raw JSON object value of `"executionPayload"`.
fn payload_object(text: []const u8) ![]const u8 {
    const key = "\"executionPayload\":";
    const start = (std.mem.indexOf(u8, text, key) orelse return error.NoPayload) + key.len;
    var scanner = json.Scanner.init(text[start..]);
    const first = try scanner.next();
    try scanner.skip(first);
    return text[start..][0..scanner.offset()];
}

test "engine rpc: follower imports builder blocks through JSON" {
    const builder = try Peer.create();
    defer builder.destroy();
    const follower = try Peer.create();
    defer follower.destroy();
    var tx_buffer: [256]u8 = undefined;
    var params: [1 << 17]u8 = undefined;
    var head = builder.node.chain.head_hash();
    for (0..3) |i| {
        try fixture.submit(builder.node, 1, i, 1000, &tx_buffer);
        const timestamp = 12 * (i + 1);
        const started = try builder.call(
            "engine_forkchoiceUpdatedV3",
            try forkchoice_params(&params, head, timestamp),
        );
        try testing.expect(std.mem.indexOf(u8, started, "\"VALID\"") != null);
        const id = field(started, "payloadId").?;
        const id_params = try std.fmt.bufPrint(&params, "[\"{s}\"]", .{id});
        const envelope = try builder.call("engine_getPayloadV4", id_params);
        const object = try payload_object(envelope);
        const zero = hex32(@splat(0));
        const new_params = try std.fmt.bufPrint(&params, "[{s},[],\"{s}\",[]]", .{ object, zero });
        const status = try follower.call("engine_newPayloadV4", new_params);
        try testing.expect(std.mem.indexOf(u8, status, "\"status\":\"VALID\"") != null);
        const hash_text = field(object, "blockHash").?;
        head = try json.parse_fixed(32, hash_text);
        for ([_]*Peer{ builder, follower }) |peer| {
            const applied = try peer.call(
                "engine_forkchoiceUpdatedV3",
                try forkchoice_params(&params, head, null),
            );
            try testing.expect(std.mem.indexOf(u8, applied, "\"VALID\"") != null);
        }
    }
    try testing.expectEqualSlices(u8, &head, &follower.node.chain.head_hash());
    const number = try follower.call("eth_blockNumber", "[]");
    try testing.expectEqualStrings("\"result\":\"0x3\"", number);
}

test "engine rpc: error codes" {
    const peer = try Peer.create();
    defer peer.destroy();
    const unknown = try peer.call("engine_getPayloadV3", "[\"0x0102030405060708\"]");
    try testing.expect(std.mem.indexOf(u8, unknown, "-38001") != null);
    const bad = try peer.call("engine_newPayloadV3", "[{\"blockNumber\":\"0x1\"},[],\"0x00\"]");
    try testing.expect(std.mem.indexOf(u8, bad, "-32602") != null);
    var params: [4096]u8 = undefined;
    const syncing = try peer.call(
        "engine_forkchoiceUpdatedV3",
        try forkchoice_params(&params, @splat(0xab), null),
    );
    try testing.expect(std.mem.indexOf(u8, syncing, "\"SYNCING\"") != null);
    const capabilities = try peer.call("engine_exchangeCapabilities", "[[]]");
    try testing.expect(std.mem.indexOf(u8, capabilities, "engine_newPayloadV4") != null);
}

fn route_arbitrary(peer: *Peer, body: []const u8) !void {
    var out: std.Io.Writer = .fixed(&peer.out);
    const outcome = engine_rpc.Router.handle(&peer.api, body, &out);
    if (outcome == .response) try json.validate(out.buffered());
}

test "engine rpc: seeded fuzz of mutated engine requests" {
    const peer = try Peer.create();
    defer peer.destroy();
    var prng = Prng.init(0xe61);
    var params: [4096]u8 = undefined;
    const seed = try forkchoice_params(&params, peer.node.chain.head_hash(), 12);
    var body: [4096]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &body,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"engine_forkchoiceUpdatedV3\",\"params\":{s}}}",
        .{seed},
    );
    var mutated: [4096]u8 = undefined;
    for (0..300) |_| {
        @memcpy(mutated[0..text.len], text);
        for (0..prng.range(1, 3)) |_| {
            mutated[prng.below(text.len)] = @intCast(prng.range(0x20, 0x7e));
        }
        try route_arbitrary(peer, mutated[0..text.len]);
    }
}
