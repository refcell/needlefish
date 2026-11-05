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
