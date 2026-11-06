//! `basectl node-metrics`: the per-node metrics base/base shares between its conductor and
//! sequencer JSON (`commands/node_metrics.rs`, `NodeMetricsJson::from_status`), projected
//! from one node's `conductor.NodeStatus`: leadership and conductor state, sequencer
//! activity and health, CL heads and L1 cursor, CL peers, and the EL's block, sync state,
//! and peers. A field is null ("unknown" in text) when its read failed or its endpoint is
//! not configured, as upstream's `Option`s are.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const conductor = @import("conductor.zig");

const Writer = types.Writer;
const Hash = types.Hash;

pub const NodeMetrics = struct {
    is_leader: ?bool = null,
    sequencer_active: ?bool = null,
    sequencer_healthy: ?bool = null,
    conductor_paused: ?bool = null,
    unsafe_l2_block: ?u64 = null,
    unsafe_l2_hash: ?Hash = null,
    safe_l2_block: ?u64 = null,
    safe_l2_hash: ?Hash = null,
    finalized_l2_block: ?u64 = null,
    current_l1_block: ?u64 = null,
    head_l1_block: ?u64 = null,
    cl_peer_count: ?u64 = null,
    el_block: ?u64 = null,
    el_syncing: ?bool = null,
    el_peer_count: ?u64 = null,

    /// Projects the shared fields from an optionally polled node status.
    pub fn from_status(status: ?*const conductor.NodeStatus) NodeMetrics {
        const node = status orelse return .{};
        const sync = node.sync.get();
        const metrics: NodeMetrics = .{
            .is_leader = node.is_leader.get(),
            .sequencer_active = node.sequencer_active.get(),
            .sequencer_healthy = node.sequencer_healthy.get(),
            .conductor_paused = node.conductor_paused.get(),
            .unsafe_l2_block = if (sync) |value| value.unsafe_l2.number else null,
            .unsafe_l2_hash = if (sync) |value| value.unsafe_l2.hash else null,
            .safe_l2_block = if (sync) |value| value.safe_l2.number else null,
            .safe_l2_hash = if (sync) |value| value.safe_l2.hash else null,
            .finalized_l2_block = if (sync) |value| value.finalized_l2.number else null,
            .current_l1_block = if (sync) |value| value.current_l1.number else null,
            .head_l1_block = if (sync) |value| value.head_l1.number else null,
            .cl_peer_count = node.cl_peer_count(),
            .el_block = node.el_block.get(),
            .el_syncing = node.el_syncing.get(),
            .el_peer_count = node.el_peers.get(),
        };
        assert((metrics.unsafe_l2_block == null) == (sync == null));
        assert((metrics.unsafe_l2_hash == null) == (sync == null));
        return metrics;
    }

    /// True when not a single field could be read.
    pub fn empty(metrics: *const NodeMetrics) bool {
        inline for (@typeInfo(NodeMetrics).@"struct".field_names) |name| {
            if (@field(metrics, name) != null) return false;
        }
        return true;
    }
};

pub const Report = struct {
    network: []const u8,
    node_name: []const u8,
    metrics: NodeMetrics,
};

/// Fails only when every read failed (nothing reachable or configured).
pub fn fetch(context: *const types.Context, node_name: []const u8) types.Fetched(Report) {
    assert(node_name.len > 0);
    const node = conductor.fetch_node(context);
    const metrics = NodeMetrics.from_status(&node);
    if (metrics.empty()) {
        const failure = switch (node.sync) {
            .failed => |value| value,
            .ok => unreachable, // A decoded sync status fills the head fields.
        };
        return .{ .failed = .{ .what = "node rpcs", .failure = failure } };
    }
    assert(!metrics.empty());
    return .{ .ok = .{ .network = context.network, .node_name = node_name, .metrics = metrics } };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.network.len > 0 and report.node_name.len > 0);
    const metrics = &report.metrics;
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "node", "{s}", .{report.node_name});
    inline for (@typeInfo(NodeMetrics).@"struct".field_names) |name| {
        const value = @field(metrics, name);
        switch (@TypeOf(value)) {
            ?bool => try types.row(writer, name, "{s}", .{types.bool_text(value)}),
            ?u64 => try types.row(writer, name, "{f}", .{types.optional_number(value)}),
            ?Hash => if (value) |hash| {
                try types.row(writer, name, "{f}", .{hash});
            } else {
                try types.row(writer, name, "unknown", .{});
            },
            else => comptime unreachable,
        }
    }
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;
const sync_status = @import("sync_status.zig");

test "basectl node-metrics: projection, text, and json" {
    var text: [2048]u8 = undefined;
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "conductor_leader", .result = "false" },
        .{ .method = "conductor_paused", .result = "true" },
        .{ .method = "admin_sequencerActive", .result = "false" },
        .{
            .method = "optimism_syncStatus",
            .result = sync_status.sample_sync_status(&text, 50, 40, 30, 5),
        },
        .{ .method = "eth_blockNumber", .result = "\"0x33\"" },
        .{ .method = "eth_syncing", .result = "false" },
        .{ .method = "net_peerCount", .result = "\"0x3\"" },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .conductor = .{ .client = &client },
        .rollup = .{ .client = &client },
        .l2 = .{ .client = &client },
    };
    const report = fetch(&context, "seq-0").ok;
    const metrics = report.metrics;
    try testing.expectEqual(@as(?bool, false), metrics.is_leader);
    try testing.expectEqual(@as(?bool, null), metrics.sequencer_healthy);
    try testing.expectEqual(@as(?u64, 50), metrics.unsafe_l2_block);
    try testing.expectEqual(@as(?u64, 51), metrics.el_block);
    try testing.expectEqual(@as(?bool, false), metrics.el_syncing);
    try testing.expectEqual(@as(?u64, null), metrics.cl_peer_count);
    var buffer: [4096]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.startsWith(u8, out, "network               devnet\n" ++
        "node                  seq-0\n" ++
        "is_leader             false\n" ++
        "sequencer_active      false\n" ++
        "sequencer_healthy     unknown\n" ++
        "conductor_paused      true\n" ++
        "unsafe_l2_block       50\n"));
    try testing.expect(std.mem.indexOf(u8, out, "el_peer_count         3\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "cl_peer_count         unknown\n") != null);
    writer = .fixed(&buffer);
    try types.render_json(report, &writer);
    const json_text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, json_text, "\"el_block\": 51,") != null);
    try testing.expect(std.mem.indexOf(u8, json_text, "\"sequencer_healthy\": null,") != null);
    try testing.expect(std.mem.indexOf(u8, json_text, "\"safe_l2_hash\": \"0x") != null);
}

test "basectl node-metrics: no status projects nothing; nothing reachable fails" {
    try testing.expect(NodeMetrics.from_status(null).empty());
    const unconfigured: types.Context = .{};
    try testing.expectEqual(
        types.Failure.not_configured,
        fetch(&unconfigured, "x").failed.failure,
    );
    var fake: FakeTransport = .{ .answers = &.{}, .transport_down = true };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const down: types.Context = .{ .rollup = .{ .client = &client }, .l2 = .{ .client = &client } };
    try testing.expectEqual(types.Failure.transport, fetch(&down, "x").failed.failure);
}

test "basectl node-metrics: eth_syncing decoding" {
    const json = std.json;
    try testing.expect(!try conductor.decode_syncing(.{ .bool = false }));
    var object: json.ObjectMap = .empty;
    try testing.expect(try conductor.decode_syncing(.{ .object = object }));
    object.deinit(testing.allocator);
    try testing.expectError(error.MalformedResponse, conductor.decode_syncing(.{ .integer = 1 }));
}
