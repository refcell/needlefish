//! p2p metrics tests: registration, Prometheus rendering, and updates from a service with
//! two simulated connections.

const std = @import("std");
const metrics = @import("../../utilities/metrics/root.zig");
const p2p_metrics = @import("metrics.zig");
const Fixture = @import("rpc_test.zig").Fixture;
const validity = @import("gossip/validity.zig");

const testing = std.testing;

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "p2p metrics: register, update, and render" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var registry: metrics.Registry(64) = .{};
    var cells: p2p_metrics.Metrics = .{};
    try cells.register(&registry);
    try testing.expectEqual(@as(u32, p2p_metrics.Metrics.entries_count), registry.count);
    try testing.expectError(error.DuplicateMetric, cells.register(&registry));

    cells.update(fixture.service, .{ .accepted = 1, .dialed = 1, .bytes_received = 99 });
    fixture.service.gossip.stats.accepted = 3;
    fixture.service.gossip.stats.rejected = 1;
    fixture.service.gossip.stats.failed[@backingInt(validity.Reason.invalid_signer)] = 1;
    fixture.service.gossip.stats.versions[2] = 4;
    cells.update(fixture.service, .{ .accepted = 1, .dialed = 2, .bytes_received = 120 });

    var buffer: [16 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try registry.write_prometheus(&out);
    const text = out.buffered();
    try expect_contains(text, "base_node_gossip_peer_count 2\n");
    try expect_contains(text, "base_node_gossipsub_connection{type=\"connected\"} 3\n");
    try expect_contains(text, "base_node_block_validation_total 4\n");
    try expect_contains(text, "base_node_block_validation_failed{reason=\"invalid_signer\"} 1\n");
    try expect_contains(text, "base_node_block_validation_failed{reason=\"block_seen\"} 0\n");
    try expect_contains(text, "base_node_block_version{version=\"v3\"} 4\n");
    try expect_contains(text, "base_node_p2p_bytes_received 120\n");
    try expect_contains(text, "base_node_block_topic_subscribed{version=\"v1\"} 1\n");
    try expect_contains(text, "# TYPE base_node_block_topic_peers gauge\n");
}
