//! p2p metrics tests: registration, Prometheus rendering, and updates from a service with
//! two simulated connections.

const std = @import("std");
const metrics = @import("../../utilities/metrics/root.zig");
const p2p_metrics = @import("metrics.zig");
const Fixture = @import("rpc_test.zig").Fixture;
const validity = @import("gossip/validity.zig");
const DialError = @import("service.zig").DialError;

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
    var registry: metrics.Registry(128) = .{};
    var cells: p2p_metrics.Metrics = .{};
    try cells.register(&registry);
    try testing.expectEqual(@as(u32, p2p_metrics.Metrics.entries_count), registry.count);
    try testing.expectError(error.DuplicateMetric, cells.register(&registry));

    cells.update(fixture.service, .{ .accepted = 1, .dialed = 1, .bytes_received = 99 });
    fixture.service.gossip.stats.accepted = 3;
    fixture.service.gossip.stats.rejected = 1;
    fixture.service.gossip.stats.failed[@backingInt(validity.Reason.invalid_signer)] = 1;
    fixture.service.gossip.stats.versions[2] = 4;
    fixture.service.stats.dial_errors[@backingInt(DialError.blocked_subnet)] = 2;
    fixture.service.on_ping(0, 1000, 45 * std.time.ns_per_s);
    cells.update(fixture.service, .{ .accepted = 1, .dialed = 2, .bytes_received = 120 });

    _ = fixture.call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"opp2p_peerCount\"}");
    cells.update(fixture.service, .{ .accepted = 1, .dialed = 2, .bytes_received = 120 });
    var buffer: [32 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try registry.write_prometheus(&out);
    const text = out.buffered();
    try expect_contains(text, "base_node_gossip_peer_count 2\n");
    try expect_contains(text, "base_node_gossipsub_connection{type=\"connected\"} 3\n");
    try expect_contains(text, "base_node_block_validation_total 4\n");
    try expect_contains(text, "base_node_block_validation_failed{reason=\"invalid_signer\"} 1\n");
    try expect_contains(text, "base_node_block_validation_failed{reason=\"block_seen\"} 0\n");
    try expect_contains(text, "base_node_block_version{version=\"v3\"} 4\n");
    try expect_contains(text, "base_node_dial_peer_error{type=\"blocked_subnet\"} 2\n");
    try expect_contains(text, "base_node_inbound_connection_error{type=\"blocked_peer\"} 0\n");
    try expect_contains(text, "base_node_p2p_bytes_received 120\n");
    try expect_contains(text, "# TYPE base_node_peer_scores histogram\n");
    try expect_contains(text, "base_node_disc_discovery_peer_count ");
    try expect_contains(text, "base_node_disc_discovery_event{type=\"discovered\"} ");
    try expect_contains(text, "base_node_disc_discovery_dropped{reason=\"closed\"} 0\n");
    try expect_contains(text, "base_node_disc_find_node_request ");
    try expect_contains(text, "base_node_rpc_calls{method=\"opp2p_peerCount\"} 1\n");
    try expect_contains(text, "base_node_rpc_calls{method=\"opp2p_self\"} 0\n");
    try expect_contains(text, "base_node_gossip_event{type=\"slow_peer\"} 0\n");
    try expect_contains(text, "base_node_block_topic_retirements_total{version=\"v3\"} 0\n");
    try expect_contains(
        text,
        "base_node_block_topic_blocked_total{version=\"v1\",direction=\"outbound\"} 0\n",
    );
    try expect_contains(text, "base_node_peer_scores_count 1\n");
    try expect_contains(
        text,
        "base_node_gossip_peer_connection_duration_seconds_bucket{le=\"60\"} 1\n",
    );
    try expect_contains(text, "base_node_block_topic_subscribed{version=\"v1\"} 1\n");
    try expect_contains(text, "# TYPE base_node_block_topic_peers gauge\n");
}
