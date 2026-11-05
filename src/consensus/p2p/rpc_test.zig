//! `opp2p_*` RPC tests: a service with two simulated connections, driven through the
//! JSON-RPC router like an HTTP request would be.

const std = @import("std");
const p2p_rpc = @import("rpc.zig");
const service_module = @import("service.zig");
const enr = @import("peers/enr.zig");
const peer_id = @import("peers/peer_id.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const ip = @import("peers/ip.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Service = service_module.Service;
const testing = std.testing;

pub const Fixture = struct {
    rollup: rollup_config.RollupConfig,
    prng: Prng,
    service: *Service,
    peers: [2]peer_id.PeerId,
    buffer: [16 * 1024]u8 = undefined,

    pub fn init(fixture: *Fixture) !void {
        fixture.rollup = .{ .l2_chain_id = 8453 };
        fixture.rollup.upgrades.set(.ecotone, 0);
        fixture.prng = Prng.init(9);
        var secret: secp256k1.SecretKey = @splat(0);
        secret[31] = 11;
        const record = try enr.build(secret, .{
            .ip4 = .{ 10, 0, 0, 1 },
            .tcp = 9222,
            .udp = 9223,
            .opstack = .{ .chain_id = 8453 },
        });
        fixture.service = try Service.create(testing.allocator, .{
            .rollup = &fixture.rollup,
            .unsafe_block_signer = .zero,
            .disc = .{ .chain_id = 8453 },
            .mcache = .{ .entries_max = 16, .arena_bytes = 1 << 16 },
        }, secret, record, fixture.prng.random());
        for (&fixture.peers, 0..) |*peer, index| {
            var peer_secret: secp256k1.SecretKey = @splat(0);
            peer_secret[31] = @intCast(20 + index);
            peer.* = peer_id.from_public_key(try secp256k1.public_key(peer_secret));
            const direction: @import("libp2p/connections.zig").Direction =
                if (index == 0) .inbound else .outbound;
            if (direction == .inbound) {
                try testing.expect(fixture.service.reserve_inbound(null));
            } else {
                try fixture.service.limits.begin(.outbound);
            }
            const address: ip.Address = .{ .ip4 = .{ 10, 0, 1, @intCast(index) } };
            _ = try fixture.service.on_connected(peer.*, direction, address, 0);
        }
    }

    pub fn deinit(fixture: *Fixture) void {
        fixture.service.destroy(testing.allocator);
    }

    pub fn call(fixture: *Fixture, body: []const u8) []const u8 {
        var out: std.Io.Writer = .fixed(&fixture.buffer);
        _ = p2p_rpc.Router.handle(fixture.service, body, &out);
        return out.buffered();
    }

    fn peer_text(fixture: *Fixture, index: usize, output: []u8) []const u8 {
        return fixture.peers[index].format(output);
    }
};

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "p2p rpc: self, counts, peers, and stats" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const self_reply = fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_self","params":[]}
    );
    try expect_contains(self_reply, "\"peerID\":\"16Uiu2");
    try expect_contains(self_reply, "\"ENR\":\"enr:-");
    try expect_contains(self_reply, "\"chainID\":8453");
    try expect_contains(self_reply, "\"userAgent\":\"base\"");
    try expect_contains(self_reply, "\"nodeID\":\"0x");
    try expect_contains(self_reply, "\"addresses\":[\"/ip4/10.0.0.1/tcp/9222/p2p/16Uiu2");
    try expect_contains(self_reply, "\"/meshsub/1.2.0\"");
    const count = fixture.call(
        \\{"jsonrpc":"2.0","id":2,"method":"opp2p_peerCount","params":[]}
    );
    try expect_contains(count, "\"connectedGossip\":2");
    const dump = fixture.call(
        \\{"jsonrpc":"2.0","id":3,"method":"opp2p_peers","params":[true]}
    );
    try expect_contains(dump, "\"totalConnected\":2");
    var text: [peer_id.text_length_max]u8 = undefined;
    try expect_contains(dump, fixture.peer_text(1, &text));
    try expect_contains(dump, "\"direction\":2");
    try expect_contains(dump, "\"bannedIPS\":[]");
    const stats = fixture.call(
        \\{"jsonrpc":"2.0","id":4,"method":"opp2p_peerStats","params":[]}
    );
    try expect_contains(stats, "\"connected\":2");
    try expect_contains(stats, "\"maxPeerCount\":30");
    const table = fixture.call(
        \\{"jsonrpc":"2.0","id":5,"method":"opp2p_discoveryTable","params":[]}
    );
    try expect_contains(table, "\"result\":[]");
}

test "p2p rpc: block lists, protection, and disconnects" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var text: [peer_id.text_length_max]u8 = undefined;
    const peer = fixture.peer_text(0, &text);
    var body: [512]u8 = undefined;
    const block = try std.fmt.bufPrint(&body,
        \\{{"jsonrpc":"2.0","id":1,"method":"opp2p_blockPeer","params":["{s}"]}}
    , .{peer});
    try expect_contains(fixture.call(block), "\"result\":null");
    try testing.expect(fixture.service.pop_command().? == .disconnect);
    const listed = fixture.call(
        \\{"jsonrpc":"2.0","id":2,"method":"opp2p_listBlockedPeers","params":[]}
    );
    try expect_contains(listed, peer);
    _ = fixture.call(
        \\{"jsonrpc":"2.0","id":3,"method":"opp2p_blockAddr","params":["1.2.3.4"]}
    );
    _ = fixture.call(
        \\{"jsonrpc":"2.0","id":4,"method":"opp2p_blockSubnet","params":["10.9.0.0/16"]}
    );
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":5,"method":"opp2p_listBlockedAddrs","params":[]}
    ), "\"1.2.3.4\"");
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":6,"method":"opp2p_listBlockedSubnets","params":[]}
    ), "\"10.9.0.0/16\"");
    _ = fixture.call(
        \\{"jsonrpc":"2.0","id":7,"method":"opp2p_unblockAddr","params":["1.2.3.4"]}
    );
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":8,"method":"opp2p_listBlockedAddrs","params":[]}
    ), "\"result\":[]");
    const protect = try std.fmt.bufPrint(&body,
        \\{{"jsonrpc":"2.0","id":9,"method":"opp2p_protectPeer","params":["{s}"]}}
    , .{fixture.peer_text(1, &text)});
    _ = fixture.call(protect);
    try testing.expect(fixture.service.gater.protected_peers.contains(fixture.peers[1]));
    const disconnect = try std.fmt.bufPrint(&body,
        \\{{"jsonrpc":"2.0","id":10,"method":"opp2p_disconnectPeer","params":["{s}"]}}
    , .{fixture.peer_text(1, &text)});
    _ = fixture.call(disconnect);
    try testing.expect(fixture.service.pop_command().? == .disconnect);
}

test "p2p rpc: invalid params and connectPeer" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_blockPeer","params":["nope"]}
    ), "-32602");
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":2,"method":"opp2p_blockSubnet","params":["10.0.0.0/40"]}
    ), "-32602");
    try expect_contains(fixture.call(
        \\{"jsonrpc":"2.0","id":3,"method":"opp2p_connectPeer","params":["/ip4/1.2.3.4/tcp/1"]}
    ), "-32602");
    var secret: secp256k1.SecretKey = @splat(0);
    secret[31] = 40;
    const remote = peer_id.from_public_key(try secp256k1.public_key(secret));
    var text: [peer_id.text_length_max]u8 = undefined;
    var body: [512]u8 = undefined;
    const connect = try std.fmt.bufPrint(&body,
        \\{{"jsonrpc":"2.0","id":4,"method":"opp2p_connectPeer","params":["/ip4/1.2.3.4/tcp/9222/p2p/{s}"]}}
    , .{remote.format(&text)});
    try expect_contains(fixture.call(connect), "\"result\":null");
    try testing.expect(fixture.service.pop_command().? == .dial);
}

test "p2p rpc: subnet parsing" {
    const subnet = try p2p_rpc.parse_subnet("192.168.0.0/24");
    try testing.expectEqual(@as(u8, 24), subnet.prefix_bits);
    try testing.expectError(error.Invalid, p2p_rpc.parse_subnet("192.168.0.0"));
    try testing.expectError(error.Invalid, p2p_rpc.parse_subnet("::/129"));
    _ = try p2p_rpc.parse_subnet("fd00::/8");
}

test "p2p rpc: seeded fuzz of methods and params" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const params = [_][]const u8{
        "[]",            "[true]", "[\"1.2.3.4\"]",   "[\"10.0.0.0/8\"]",
        "[\"::1\"]",     "[1]",    "[\"16Uiu2HAm\"]", "[\"/ip4/1.1.1.1\"]",
        "[\"a\",\"b\"]", "{}",     "[null]",          "[\"fd00::/7\"]",
    };
    var prng = Prng.init(77);
    const random = prng.random();
    var body: [512]u8 = undefined;
    for (0..2000) |_| {
        const method = p2p_rpc.methods[random.uintLessThan(usize, p2p_rpc.methods.len)];
        const param = params[random.uintLessThan(usize, params.len)];
        const request = try std.fmt.bufPrint(&body,
            \\{{"jsonrpc":"2.0","id":1,"method":"{s}","params":{s}}}
        , .{ method.name, param });
        const reply = fixture.call(request);
        try @import("../../utilities/json/root.zig").validate(reply);
        while (fixture.service.pop_command()) |_| {}
    }
}

test "p2p rpc: peers carry identify and ping data" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var message: @import("libp2p/identify.zig").Identify = .{
        .agent_version = "op-node/v1.9.0",
        .protocol_version = "",
    };
    message.protocols[0] = "/meshsub/1.1.0";
    message.protocols_count = 1;
    const multiaddr = @import("peers/multiaddr.zig");
    message.listen_addresses[0] = try multiaddr.parse("/ip4/10.0.1.0/tcp/9222");
    message.listen_addresses_count = 1;
    const slot = fixture.service.slot_of(&fixture.peers[0]).?;
    fixture.service.on_ping(slot, 1_500_000, 3 * std.time.ns_per_s);
    fixture.service.on_identified(slot, &message);
    const dump = fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_peers","params":[true]}
    );
    try expect_contains(dump, "\"userAgent\":\"op-node/v1.9.0\"");
    try expect_contains(dump, "\"addresses\":[\"/ip4/10.0.1.0/tcp/9222\"]");
    try expect_contains(dump, "\"protocols\":[\"/meshsub/1.1.0\"]");
    try expect_contains(dump, "\"latency\":1500000");
    try expect_contains(dump, "\"protocols\":null");
}

test "p2p rpc: peers(false) keeps identified peers after they disconnect" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const message: @import("libp2p/identify.zig").Identify = .{
        .agent_version = "base-consensus/gone",
        .protocol_version = "",
    };
    const service = fixture.service;
    const slot = service.slot_of(&fixture.peers[0]).?;
    service.on_identified(slot, &message);
    service.on_disconnected(slot, 5 * std.time.ns_per_s);
    const connected = fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_peers","params":[true]}
    );
    try testing.expect(std.mem.indexOf(u8, connected, "base-consensus/gone") == null);
    const all = fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_peers","params":[false]}
    );
    try expect_contains(all, "\"userAgent\":\"base-consensus/gone\"");
    try expect_contains(all, "\"connectedness\":0");
    // Banned while disconnected: CannotConnect.
    var text: [@import("peers/peer_id.zig").text_length_max]u8 = undefined;
    var body: [256]u8 = undefined;
    const block_request = try std.fmt.bufPrint(&body,
        \\{{"jsonrpc":"2.0","id":2,"method":"opp2p_blockPeer","params":["{s}"]}}
    , .{fixture.peers[0].format(&text)});
    _ = fixture.call(block_request);
    while (service.pop_command()) |_| {}
    const banned = fixture.call(
        \\{"jsonrpc":"2.0","id":3,"method":"opp2p_peers","params":[false]}
    );
    try expect_contains(banned, "\"connectedness\":3");
}

test "p2p rpc: peer info truncates long identify fields" {
    const long_agent: [200]u8 = @splat('a');
    var message: @import("libp2p/identify.zig").Identify = .{ .agent_version = &long_agent };
    for (0..20) |index| message.protocols[index] = "/p";
    message.protocols_count = 20;
    const info = service_module.PeerInfo.from_identify(&message);
    const agent = info.agent_version.slice();
    try testing.expectEqual(@as(usize, service_module.PeerInfo.text_max), agent.len);
    try testing.expectEqual(@as(u8, service_module.PeerInfo.protocols_max), info.protocols_count);
}

fn fuzz_peer_info(_: void, input: []const u8) anyerror!void {
    const message = @import("libp2p/identify.zig").decode(input) catch return;
    const info = service_module.PeerInfo.from_identify(&message);
    try testing.expect(info.protocols_count <= service_module.PeerInfo.protocols_max);
    try testing.expect(info.addresses_count <= service_module.PeerInfo.addresses_max);
    try testing.expect(info.agent_version.slice().len <= service_module.PeerInfo.text_max);
}

test "p2p rpc: fuzz peer info from identify bytes" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run_bytes({}, fuzz_peer_info, fuzz.Options{ .input_size_max = 4096, .corpus = &.{} });
}

const InnerContext = struct { answer: u64 };

const utilities_rpc = @import("../../utilities/rpc/root.zig");

fn inner_answer(
    context: *const InnerContext,
    call: *utilities_rpc.Call,
) utilities_rpc.HandlerError!void {
    try call.params.finish();
    try call.writer.integer(context.answer);
}

const TestMerged = p2p_rpc.Merged(*const InnerContext, &.{
    .{ .name = "test_answer", .handler = inner_answer },
});

test "p2p rpc: merged router serves inner and opp2p methods, batches included" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const inner: InnerContext = .{ .answer = 42 };
    var storage: [16 * 1024]u8 = undefined;
    const batch =
        \\[{"jsonrpc":"2.0","id":1,"method":"test_answer","params":[]},
        \\ {"jsonrpc":"2.0","id":2,"method":"opp2p_peerCount","params":[]}]
    ;
    var out = std.Io.Writer.fixed(&storage);
    const on: TestMerged.Context = .{ .inner = &inner, .p2p = fixture.service };
    _ = TestMerged.Router.handle(&on, batch, &out);
    try expect_contains(out.buffered(), "\"id\":1,\"result\":42");
    try expect_contains(out.buffered(), "\"connectedGossip\":2");
    // p2p off: the opp2p method is unknown, the inner one still answers.
    out = std.Io.Writer.fixed(&storage);
    const off: TestMerged.Context = .{ .inner = &inner, .p2p = null };
    _ = TestMerged.Router.handle(&off, batch, &out);
    try expect_contains(out.buffered(), "\"id\":1,\"result\":42");
    try expect_contains(out.buffered(), "-32601");
}
