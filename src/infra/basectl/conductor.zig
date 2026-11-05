//! `basectl conductor`: one HA conductor node's leadership and control-loop state plus the
//! raft membership it reports (base/base `commands/conductor.rs` status path). Reads
//! `conductor_leader`, `conductor_active`, `conductor_paused`, `conductor_stopped`,
//! `conductor_sequencerHealthy`, `conductor_leaderWithID`, and
//! `conductor_clusterMembership` from the conductor RPC, and the sequencer's activity,
//! heads, and peer counts from the rollup and L2 RPCs. Leadership transfer and
//! pause/resume are not ported.
//!
//! `NodeStatus` is shared with `basectl sequencer`.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");
const sync_status = @import("sync_status.zig");
const p2p = @import("p2p.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;
const Probe = types.Probe;
const Text = types.Text;
const probe = types.probe;
const decode_bool = types.decode_bool;

pub const servers_max = 16;

pub const Server = struct {
    id: Text(64),
    addr: Text(128),
    suffrage: Text(16),
};

pub const Membership = struct {
    servers: types.List(Server, servers_max) = .{},
    version: u64,
};

/// Everything basectl reads about one sequencer node and its conductor.
pub const NodeStatus = struct {
    is_leader: Probe(bool),
    conductor_active: Probe(bool),
    conductor_paused: Probe(bool),
    conductor_stopped: Probe(bool),
    sequencer_healthy: Probe(bool),
    leader: Probe(Server),
    membership: Probe(Membership),
    sequencer_active: Probe(bool),
    sync: Probe(sync_status.SyncStatus),
    cl_peers: Probe(p2p.PeerStats),
    el_peers: Probe(u64),

    pub fn unsafe_l2(status: *const NodeStatus) ?u64 {
        const sync = status.sync.get() orelse return null;
        return sync.unsafe_l2.number;
    }

    pub fn safe_l2(status: *const NodeStatus) ?u64 {
        const sync = status.sync.get() orelse return null;
        return sync.safe_l2.number;
    }

    pub fn cl_peer_count(status: *const NodeStatus) ?u64 {
        const stats = status.cl_peers.get() orelse return null;
        return stats.connected;
    }

    /// `leader`, `follower`, or `unknown` (base/base `SequencerRole`).
    pub fn role(status: *const NodeStatus) []const u8 {
        const is_leader = status.is_leader.get() orelse return "unknown";
        return if (is_leader) "leader" else "follower";
    }
};

pub const Report = struct {
    network: []const u8,
    node_name: []const u8,
    node: NodeStatus,
};

pub fn decode_server(value: json.Value) DecodeError!Server {
    const suffrage = try rpc.field(value, "suffrage");
    const server: Server = .{
        .id = try types.decode_string(64, try rpc.field(value, "id")),
        .addr = try types.decode_string(128, try rpc.field(value, "addr")),
        .suffrage = switch (suffrage) {
            .string => |text| .init(text),
            .integer => |code| .init(switch (code) {
                0 => "voter",
                1 => "nonvoter",
                else => return error.MalformedResponse,
            }),
            else => return error.MalformedResponse,
        },
    };
    assert(server.id.length <= 64);
    return server;
}

pub fn decode_membership(value: json.Value) DecodeError!Membership {
    var membership: Membership = .{ .version = try rpc.number(try rpc.field(value, "version")) };
    const servers = try rpc.field(value, "servers");
    if (servers != .array) return error.MalformedResponse;
    for (servers.array.items) |item| {
        if (!membership.servers.push(try decode_server(item))) return error.MalformedResponse;
    }
    assert(membership.servers.count <= servers_max);
    return membership;
}

pub fn fetch_node(context: *const types.Context) NodeStatus {
    const conductor = context.conductor.client;
    const rollup = context.rollup.client;
    const status: NodeStatus = .{
        .is_leader = probe(bool, conductor, "conductor_leader", "[]", decode_bool),
        .conductor_active = probe(bool, conductor, "conductor_active", "[]", decode_bool),
        .conductor_paused = probe(bool, conductor, "conductor_paused", "[]", decode_bool),
        .conductor_stopped = probe(bool, conductor, "conductor_stopped", "[]", decode_bool),
        .sequencer_healthy = types.probe(
            bool,
            conductor,
            "conductor_sequencerHealthy",
            "[]",
            types.decode_bool,
        ),
        .leader = types.probe(Server, conductor, "conductor_leaderWithID", "[]", decode_server),
        .membership = types.probe(
            Membership,
            conductor,
            "conductor_clusterMembership",
            "[]",
            decode_membership,
        ),
        .sequencer_active = probe(bool, rollup, "admin_sequencerActive", "[]", decode_bool),
        .sync = types.probe(
            sync_status.SyncStatus,
            rollup,
            "optimism_syncStatus",
            "[]",
            sync_status.decode_sync_status,
        ),
        .cl_peers = probe(p2p.PeerStats, rollup, "opp2p_peerStats", "[]", p2p.decode_peer_stats),
        .el_peers = probe(u64, context.l2.client, "net_peerCount", "[]", types.decode_number),
    };
    assert(status.is_leader != .failed or status.is_leader.failed != .not_configured or
        conductor == null);
    return status;
}

pub fn fetch(context: *const types.Context, node_name: []const u8) types.Fetched(Report) {
    assert(node_name.len > 0);
    const node = fetch_node(context);
    const conductor_failed = node.is_leader == .failed and node.conductor_active == .failed and
        node.conductor_paused == .failed and node.membership == .failed;
    if (conductor_failed) {
        return .{ .failed = .{ .what = "conductor rpc", .failure = node.is_leader.failed } };
    }
    return .{ .ok = .{ .network = context.network, .node_name = node_name, .node = node } };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    const node = &report.node;
    assert(report.node_name.len > 0);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "source", "flags", .{});
    switch (node.membership) {
        .ok => |*membership| {
            try types.row(writer, "nodes", "{d}", .{membership.servers.count});
            try types.row(writer, "membership_version", "{d}", .{membership.version});
        },
        .failed => |failure| {
            try types.row(writer, "nodes", "1", .{});
            try types.row(writer, "membership_error", "{s}", .{failure.text()});
        },
    }
    try leader_row(writer, report);
    const paused = node.conductor_paused.get();
    try types.row(writer, "paused", "{d}/{d} known paused", .{
        @intFromBool(paused orelse false),
        @intFromBool(paused != null),
    });
    var key_buffer: [80]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buffer, "node.{s}", .{report.node_name}) catch "node";
    try types.row(writer, key, "leader={s} conductor_active={s} conductor_paused={s} " ++
        "conductor_stopped={s} sequencer_active={s} sequencer_healthy={s} unsafe={f} " ++
        "safe={f} cl_peers={f} el_peers={f}", .{
        types.bool_text(node.is_leader.get()),
        types.bool_text(node.conductor_active.get()),
        types.bool_text(paused),
        types.bool_text(node.conductor_stopped.get()),
        types.bool_text(node.sequencer_active.get()),
        types.bool_text(node.sequencer_healthy.get()),
        types.optional_number(node.unsafe_l2()),
        types.optional_number(node.safe_l2()),
        types.optional_number(node.cl_peer_count()),
        types.optional_number(node.el_peers.get()),
    });
    if (node.membership.get()) |membership| {
        for (membership.servers.slice()) |*server| {
            try types.row(writer, "member", "{s} addr={s} suffrage={s}", .{
                server.id.slice(), server.addr.slice(), server.suffrage.slice(),
            });
        }
    }
}

/// The leader's raft id when known, else this node's name when it reports leadership.
pub fn leader_row(writer: *Writer, report: *const Report) !void {
    assert(report.node_name.len > 0);
    if (report.node.leader.get()) |leader| {
        return types.row(writer, "leader", "{s}", .{leader.id.slice()});
    }
    const is_leader = report.node.is_leader.get() orelse false;
    try types.row(writer, "leader", "{s}", .{if (is_leader) report.node_name else "unknown"});
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

pub const sample_membership =
    \\{"servers":[{"id":"seq-0","addr":"seq-0:5051","suffrage":0},
    \\{"id":"seq-1","addr":"seq-1:5051","suffrage":"Nonvoter"}],"version":7}
;

test "basectl conductor: status and membership" {
    var text: [2048]u8 = undefined;
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "conductor_leader", .result = "true" },
        .{ .method = "conductor_active", .result = "true" },
        .{ .method = "conductor_paused", .result = "false" },
        .{ .method = "conductor_stopped", .result = "false" },
        .{ .method = "conductor_sequencerHealthy", .result = "true" },
        .{ .method = "conductor_clusterMembership", .result = sample_membership },
        .{ .method = "admin_sequencerActive", .result = "true" },
        .{
            .method = "optimism_syncStatus",
            .result = sync_status.sample_sync_status(&text, 50, 40, 30, 5),
        },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .conductor = .{ .client = &client },
        .rollup = .{ .client = &client },
    };
    const report = fetch(&context, "local").ok;
    try testing.expectEqualStrings("leader", report.node.role());
    var buffer: [2048]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "nodes                 2\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "leader                local\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "paused                0/1 known paused\n") !=
        null);
    try testing.expect(std.mem.indexOf(u8, out, "node.local            leader=true " ++
        "conductor_active=true conductor_paused=false conductor_stopped=false " ++
        "sequencer_active=true sequencer_healthy=true unsafe=50 safe=40 cl_peers=unknown " ++
        "el_peers=unknown\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "seq-1 addr=seq-1:5051 suffrage=Nonvoter") != null);
}

test "basectl conductor: unconfigured conductor fails" {
    const context: types.Context = .{};
    try testing.expectEqual(types.Failure.not_configured, fetch(&context, "x").failed.failure);
}
