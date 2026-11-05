//! `basectl sequencer`: whether a node is sequencing, its role under a conductor, heads,
//! and peer counts (base/base `commands/sequencer.rs` status path, one node). Reads
//! `admin_sequencerActive` and `optimism_syncStatus` from the rollup RPC and, when a
//! conductor RPC is given, leadership and health from it. Start/stop are not ported.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const conductor = @import("conductor.zig");
const sync_status = @import("sync_status.zig");

const Writer = types.Writer;

pub const Report = conductor.Report;

pub fn fetch(context: *const types.Context, node_name: []const u8) types.Fetched(Report) {
    assert(node_name.len > 0);
    const node = conductor.fetch_node(context);
    if (node.sequencer_active == .failed and node.sync == .failed) {
        return .{ .failed = .{ .what = "rollup rpc", .failure = node.sequencer_active.failed } };
    }
    assert(node.sequencer_active != .failed or node.sync != .failed);
    return .{ .ok = .{ .network = context.network, .node_name = node_name, .node = node } };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    const node = &report.node;
    assert(report.node_name.len > 0);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "source", "flags", .{});
    try types.row(writer, "nodes", "1", .{});
    if (node.membership.get()) |membership| {
        try types.row(writer, "membership_version", "{d}", .{membership.version});
    }
    try conductor.leader_row(writer, report);
    const sync = node.sync.get();
    var key_buffer: [80]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buffer, "node.{s}", .{report.node_name}) catch "node";
    try types.row(writer, key, "role={s} active={s} healthy={s} paused={s} unsafe={f} " ++
        "safe={f} finalized={f} current_l1={f} head_l1={f} cl_peers={f} el_peers={f}", .{
        node.role(),
        types.bool_text(node.sequencer_active.get()),
        types.bool_text(node.sequencer_healthy.get()),
        types.bool_text(node.conductor_paused.get()),
        types.optional_number(node.unsafe_l2()),
        types.optional_number(node.safe_l2()),
        types.optional_number(if (sync) |status| status.finalized_l2.number else null),
        types.optional_number(if (sync) |status| status.current_l1.number else null),
        types.optional_number(if (sync) |status| status.head_l1.number else null),
        types.optional_number(node.cl_peer_count()),
        types.optional_number(node.el_peers.get()),
    });
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

test "basectl sequencer: standalone node without a conductor" {
    var text: [2048]u8 = undefined;
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "admin_sequencerActive", .result = "true" },
        .{
            .method = "optimism_syncStatus",
            .result = sync_status.sample_sync_status(&text, 50, 40, 30, 5),
        },
        .{ .method = "net_peerCount", .result = "\"0x0\"" },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .rollup = .{ .client = &client },
        .l2 = .{ .client = &client },
    };
    const report = fetch(&context, "local").ok;
    var buffer: [2048]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "node.local            " ++
        "role=unknown active=true healthy=unknown paused=unknown unsafe=50 safe=40 " ++
        "finalized=30 current_l1=5 head_l1=5 cl_peers=unknown el_peers=0\n") != null);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "leader                unknown\n") !=
        null);
}

test "basectl sequencer: rollup rpc down fails" {
    var fake: FakeTransport = .{ .answers = &.{}, .transport_down = true };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{ .rollup = .{ .client = &client } };
    try testing.expectEqual(types.Failure.transport, fetch(&context, "local").failed.failure);
}
