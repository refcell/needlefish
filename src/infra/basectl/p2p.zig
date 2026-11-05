//! `basectl p2p`: the node's peer-to-peer identity and peer counts on both layers
//! (base/base `commands/p2p.rs` info/peer-count paths). Consensus layer: `opp2p_self` and
//! `opp2p_peerStats`; execution layer: `admin_nodeInfo` and `net_peerCount`. Each read is
//! independent, so one missing method shows as unavailable without hiding the others.
//! Peer mutation (add/remove/ban) is not ported.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;
const Text = types.Text;

pub const addresses_max = 4;

pub const ClIdentity = struct {
    peer_id: Text(64),
    user_agent: ?Text(64) = null,
    enr: ?Text(512) = null,
    addresses: types.List(Text(128), addresses_max) = .{},
};

/// `opp2p_peerStats` (base/base `PeerStats`).
pub const PeerStats = struct {
    connected: u32,
    table: u32,
    banned: u32,
    known: u32,
};

pub const ElIdentity = struct {
    enode: Text(256),
    name: ?Text(128) = null,
};

pub const Report = struct {
    network: []const u8,
    cl_identity: types.Probe(ClIdentity),
    cl_peers: types.Probe(PeerStats),
    el_identity: types.Probe(ElIdentity),
    el_peers: types.Probe(u64),

    /// True when no read succeeded: the command then fails.
    pub fn all_failed(report: *const Report) bool {
        return report.cl_identity == .failed and report.cl_peers == .failed and
            report.el_identity == .failed and report.el_peers == .failed;
    }
};

pub fn decode_cl_identity(value: json.Value) DecodeError!ClIdentity {
    var identity: ClIdentity = .{
        .peer_id = try types.decode_string(64, try rpc.field(value, "peerID")),
    };
    if (try types.optional_field(value, "userAgent")) |agent| {
        identity.user_agent = try types.decode_string(64, agent);
    }
    if (try types.optional_field(value, "ENR")) |enr| {
        identity.enr = try types.decode_string(512, enr);
    }
    if (try types.optional_field(value, "addresses")) |addresses| {
        if (addresses != .array) return error.MalformedResponse;
        for (addresses.array.items) |address| {
            // Extra addresses beyond the display bound are dropped, not an error.
            if (!identity.addresses.push(try types.decode_string(128, address))) break;
        }
    }
    assert(identity.addresses.count <= addresses_max);
    return identity;
}

pub fn decode_peer_stats(value: json.Value) DecodeError!PeerStats {
    var stats: PeerStats = undefined;
    inline for (.{ "connected", "table", "banned", "known" }) |name| {
        const number = try rpc.number(try rpc.field(value, name));
        @field(stats, name) = std.math.cast(u32, number) orelse return error.MalformedResponse;
    }
    assert(value == .object);
    return stats;
}

pub fn decode_el_identity(value: json.Value) DecodeError!ElIdentity {
    var identity: ElIdentity = .{
        .enode = try types.decode_string(256, try rpc.field(value, "enode")),
    };
    if (try types.optional_field(value, "name")) |name| {
        identity.name = try types.decode_string(128, name);
    }
    assert(value == .object);
    return identity;
}

pub fn fetch(context: *const types.Context) types.Fetched(Report) {
    assert(context.network.len > 0);
    const cl = context.rollup.client;
    const el = context.l2.client;
    const report: Report = .{
        .network = context.network,
        .cl_identity = types.probe(ClIdentity, cl, "opp2p_self", "[]", decode_cl_identity),
        .cl_peers = types.probe(PeerStats, cl, "opp2p_peerStats", "[]", decode_peer_stats),
        .el_identity = types.probe(ElIdentity, el, "admin_nodeInfo", "[]", decode_el_identity),
        .el_peers = types.probe(u64, el, "net_peerCount", "[]", types.decode_number),
    };
    if (report.all_failed()) {
        return .{ .failed = .{ .what = "p2p reads", .failure = report.el_peers.failed } };
    }
    return .{ .ok = report };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.network.len > 0);
    try types.row(writer, "network", "{s}", .{report.network});
    switch (report.cl_identity) {
        .failed => |failure| try types.row(writer, "cl peer id", "{s}", .{failure.text()}),
        .ok => |*identity| {
            try types.row(writer, "cl peer id", "{s}", .{identity.peer_id.slice()});
            if (identity.user_agent) |*agent| {
                try types.row(writer, "cl user agent", "{s}", .{agent.slice()});
            }
            for (identity.addresses.slice()) |*address| {
                try types.row(writer, "cl address", "{s}", .{address.slice()});
            }
            if (identity.enr) |*enr| try types.row(writer, "cl enr", "{s}", .{enr.slice()});
        },
    }
    switch (report.cl_peers) {
        .failed => |failure| try types.row(writer, "cl peers", "{s}", .{failure.text()}),
        .ok => |stats| try types.row(writer, "cl peers", "{d} connected ({d} table, {d} " ++
            "banned, {d} known)", .{ stats.connected, stats.table, stats.banned, stats.known }),
    }
    switch (report.el_identity) {
        .failed => |failure| try types.row(writer, "el enode", "{s}", .{failure.text()}),
        .ok => |*identity| {
            try types.row(writer, "el enode", "{s}", .{identity.enode.slice()});
            if (identity.name) |*name| try types.row(writer, "el client", "{s}", .{name.slice()});
        },
    }
    switch (report.el_peers) {
        .failed => |failure| try types.row(writer, "el peers", "{s}", .{failure.text()}),
        .ok => |count| try types.row(writer, "el peers", "{d} connected", .{count}),
    }
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

pub const sample_self =
    \\{"peerID":"16Uiu2HAm","userAgent":"base","ENR":"enr:-abc",
    \\"addresses":["/ip4/127.0.0.1/tcp/9222","/ip4/10.0.0.1/tcp/9222"]}
;
pub const sample_peer_stats =
    \\{"connected":3,"table":10,"blocksTopic":3,"banned":0,"known":5}
;

test "basectl p2p: partial availability renders every row" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "opp2p_self", .result = sample_self },
        .{ .method = "opp2p_peerStats", .result = sample_peer_stats },
        .{ .method = "net_peerCount", .result = "\"0x2\"" },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .rollup = .{ .client = &client },
        .l2 = .{ .client = &client },
    };
    const report = fetch(&context).ok;
    try testing.expectEqual(@as(u32, 3), report.cl_peers.ok.connected);
    try testing.expectEqual(types.Failure.unavailable, report.el_identity.failed);
    var buffer: [2048]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    const peers_row = "cl peers              3 connected (10 table";
    try testing.expect(std.mem.indexOf(u8, out, peers_row) != null);
    try testing.expect(std.mem.indexOf(u8, out, "el enode              unavailable") != null);
    try testing.expect(std.mem.indexOf(u8, out, "el peers              2 connected\n") != null);
    try testing.expectEqual(@as(u16, 2), report.cl_identity.ok.addresses.count);
}

test "basectl p2p: no reads succeed" {
    var fake: FakeTransport = .{ .answers = &.{}, .transport_down = true };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .rollup = .{ .client = &client },
        .l2 = .{ .client = &client },
    };
    try testing.expectEqual(types.Failure.transport, fetch(&context).failed.failure);
}
