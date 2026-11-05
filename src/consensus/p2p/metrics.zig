//! Prometheus metrics for the p2p stack, named after base/base
//! (`crates/consensus/gossip/src/metrics/mod.rs`, `disc/src/metrics.rs`, scope `base_node`).
//!
//! The p2p state machines keep plain `Stats` counters; `Metrics.update` copies them (and
//! derived gauges such as per-topic peer counts) into registry cells, so the hot paths never
//! touch atomics. Call `update` before serving a scrape, or on every service tick.
//! Label sets follow base/base. `block_validation_*` count decoded envelopes only (decode
//! failures are rejected before validation, as in base/base); validation duration is not
//! exported because the state machines have no wall clock.

const std = @import("std");
const assert = std.debug.assert;
const metrics = @import("../../utilities/metrics/root.zig");
const service_module = @import("service.zig");
const router_module = @import("gossip/router.zig");
const validity = @import("gossip/validity.zig");

const Service = service_module.Service;
const Counter = metrics.Counter;
const Gauge = metrics.Gauge;

const versions = [_][]const u8{ "v1", "v2", "v3", "v4" };
const version_labels = [versions.len][1]metrics.Label{
    .{.{ .name = "version", .value = versions[0] }},
    .{.{ .name = "version", .value = versions[1] }},
    .{.{ .name = "version", .value = versions[2] }},
    .{.{ .name = "version", .value = versions[3] }},
};
const connection_types = [_][]const u8{ "connected", "outgoing_error", "incoming_error", "closed" };
const connection_labels = [connection_types.len][1]metrics.Label{
    .{.{ .name = "type", .value = connection_types[0] }},
    .{.{ .name = "type", .value = connection_types[1] }},
    .{.{ .name = "type", .value = connection_types[2] }},
    .{.{ .name = "type", .value = connection_types[3] }},
};

const reasons = std.meta.fieldNames(validity.Reason);
const reason_labels = labels: {
    var labels: [reasons.len][1]metrics.Label = undefined;
    for (reasons, &labels) |name, *label| label.* = .{.{ .name = "reason", .value = name }};
    break :labels labels;
};

const dial_errors = std.meta.fieldNames(service_module.DialError);
const dial_error_labels = type_labels(dial_errors);
const inbound_errors = std.meta.fieldNames(service_module.InboundError);
const inbound_error_labels = type_labels(inbound_errors);

fn type_labels(comptime names: []const [:0]const u8) [names.len][1]metrics.Label {
    var labels: [names.len][1]metrics.Label = undefined;
    for (names, &labels) |name, *label| label.* = .{.{ .name = "type", .value = name }};
    return labels;
}

/// Transport counters `update` reads (a copy of `Transport(IO).Stats`).
pub const TransportStats = struct {
    accepted: u64 = 0,
    dialed: u64 = 0,
    dial_failures: u64 = 0,
    closed: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
};

pub const Metrics = struct {
    gossip_peer_count: Gauge = .{},
    discovery_peer_count: Gauge = .{},
    banned_peers: Gauge = .{},
    dial_peer: Gauge = .{},
    dial_peer_error: [dial_errors.len]Gauge = @splat(.{}),
    inbound_connection_error: [inbound_errors.len]Gauge = @splat(.{}),
    unsafe_block_published: Gauge = .{},
    block_topic_subscribed: [versions.len]Gauge = @splat(.{}),
    block_topic_peers: [versions.len]Gauge = @splat(.{}),
    block_topic_mesh_peers: [versions.len]Gauge = @splat(.{}),
    gossipsub_connection: [connection_types.len]Gauge = @splat(.{}),
    block_validation_total: Counter = .{},
    block_validation_success: Counter = .{},
    block_validation_failed: [reasons.len]Counter = @splat(.{}),
    block_version: [versions.len]Counter = @splat(.{}),
    p2p_bytes_received: Counter = .{},
    p2p_bytes_sent: Counter = .{},

    pub const entries_count = 9 + 4 * versions.len + connection_types.len + reasons.len +
        dial_errors.len + inbound_errors.len;

    /// Registers every metric. `registry` is a `*metrics.Registry(capacity)`; `metrics`
    /// must not move afterwards.
    pub fn register(self: *Metrics, registry: anytype) metrics.RegisterError!void {
        const count_before = registry.count;
        try registry.gauge("base_node_gossip_peer_count", "Number of peers connected to " ++
            "the libp2p gossip Swarm", &self.gossip_peer_count);
        try registry.gauge("base_node_discovery_peer_count", "Number of peers connected to " ++
            "the discv5 service", &self.discovery_peer_count);
        try registry.gauge(
            "base_node_banned_peers",
            "Number of peers banned by the gater",
            &self.banned_peers,
        );
        try registry.gauge(
            "base_node_dial_peer",
            "Number of peers dialed by the libp2p Swarm",
            &self.dial_peer,
        );
        try register_typed(registry, "base_node_dial_peer_error", "Number of errors when " ++
            "dialing peers", &self.dial_peer_error, &dial_error_labels);
        const inbound_help = "Number of inbound connection rejections by the connection gate";
        try register_typed(registry, "base_node_inbound_connection_error", inbound_help, &self
            .inbound_connection_error, &inbound_error_labels);
        try registry.gauge(
            "base_node_unsafe_block_published",
            "Number of NetworkPayloadEnvelope gossipped out through the libp2p Swarm",
            &self.unsafe_block_published,
        );
        try register_versions(registry, "base_node_block_topic_subscribed", "Whether the " ++
            "local node is subscribed to a block topic (0 or 1)", &self.block_topic_subscribed);
        try register_versions(registry, "base_node_block_topic_peers", "Number of connected " ++
            "peers advertising a block topic", &self.block_topic_peers);
        try register_versions(registry, "base_node_block_topic_mesh_peers", "Number of peers " ++
            "in the local block topic mesh", &self.block_topic_mesh_peers);
        for (&self.gossipsub_connection, &connection_labels) |*gauge, *labels| {
            try registry.register(.{
                .name = "base_node_gossipsub_connection",
                .help = "Connections made to the libp2p Swarm",
                .labels = labels,
                .metric = .{ .gauge = gauge },
            });
        }
        try self.register_validation(registry);
        try registry.counter("base_node_p2p_bytes_received", "Bytes received on p2p " ++
            "TCP connections", &self.p2p_bytes_received);
        try registry.counter(
            "base_node_p2p_bytes_sent",
            "Bytes sent on p2p TCP connections",
            &self.p2p_bytes_sent,
        );
        assert(registry.count - count_before == entries_count);
    }

    fn register_validation(self: *Metrics, registry: anytype) metrics.RegisterError!void {
        const count_before = registry.count;
        try registry.counter(
            "base_node_block_validation_total",
            "Gossiped blocks validated",
            &self.block_validation_total,
        );
        try registry.counter(
            "base_node_block_validation_success",
            "Gossiped blocks accepted",
            &self.block_validation_success,
        );
        for (&self.block_validation_failed, &reason_labels) |*counter, *labels| {
            try registry.register(.{
                .name = "base_node_block_validation_failed",
                .help = "Number of failed block validations by reason",
                .labels = labels,
                .metric = .{ .counter = counter },
            });
        }
        for (&self.block_version, &version_labels) |*counter, *labels| {
            try registry.register(.{
                .name = "base_node_block_version",
                .help = "Distribution of block versions",
                .labels = labels,
                .metric = .{ .counter = counter },
            });
        }
        assert(registry.count - count_before == 2 + reasons.len + versions.len);
    }

    /// Copies the current service and transport state into the registry cells.
    pub fn update(self: *Metrics, service: *const Service, transport: TransportStats) void {
        self.gossip_peer_count.set(service.connected_count());
        self.discovery_peer_count.set(service.discovery.table.live_count());
        self.banned_peers.set(@intCast(service.gater.blocked_peers.slice().len));
        self.dial_peer.set(@intCast(service.stats.dials));
        for (&self.dial_peer_error, service.stats.dial_errors) |*gauge, count| {
            gauge.set(@intCast(count));
        }
        for (&self.inbound_connection_error, service.stats.inbound_errors) |*gauge, count| {
            gauge.set(@intCast(count));
        }
        const gossip = service.gossip;
        self.unsafe_block_published.set(@intCast(gossip.stats.published));
        const router = &gossip.router;
        for (gossip.topics, 0..) |topic, version| {
            self.block_topic_subscribed[version].set(@intFromBool(router.is_subscribed(topic)));
            self.block_topic_mesh_peers[version].set(@popCount(router.mesh[topic]));
            self.block_topic_peers[version].set(topic_peers(service, topic));
        }
        self.gossipsub_connection[0].set(@intCast(transport.accepted + transport.dialed));
        self.gossipsub_connection[1].set(@intCast(transport.dial_failures));
        self.gossipsub_connection[2].set(@intCast(service.stats.inbound_refused));
        self.gossipsub_connection[3].set(@intCast(transport.closed));
        var failed: u64 = 0;
        for (&self.block_validation_failed, gossip.stats.failed) |*counter, count| {
            store(counter, count);
            failed += count;
        }
        for (&self.block_version, gossip.stats.versions) |*counter, count| store(counter, count);
        store(&self.block_validation_total, gossip.stats.accepted + failed);
        store(&self.block_validation_success, gossip.stats.accepted);
        store(&self.p2p_bytes_received, transport.bytes_received);
        store(&self.p2p_bytes_sent, transport.bytes_sent);
        assert(self.block_validation_total.get() >= self.block_validation_success.get());
    }
};

fn register_typed(
    registry: anytype,
    name: []const u8,
    help: []const u8,
    gauges: []Gauge,
    labels: []const [1]metrics.Label,
) metrics.RegisterError!void {
    assert(gauges.len == labels.len and gauges.len > 0);
    for (gauges, labels) |*gauge, *label| {
        try registry.register(.{
            .name = name,
            .help = help,
            .labels = label,
            .metric = .{ .gauge = gauge },
        });
    }
}

fn register_versions(
    registry: anytype,
    name: []const u8,
    help: []const u8,
    gauges: *[versions.len]Gauge,
) metrics.RegisterError!void {
    assert(name.len > 0);
    for (gauges, &version_labels) |*gauge, *labels| {
        try registry.register(.{
            .name = name,
            .help = help,
            .labels = labels,
            .metric = .{ .gauge = gauge },
        });
    }
}

fn topic_peers(service: *const Service, topic: u8) i64 {
    assert(topic < 8);
    var count: i64 = 0;
    for (&service.connected, 0..) |*connection, slot| {
        if (!connection.active) continue;
        const topics = service.gossip.router.peer(@intCast(slot)).topics;
        count += @intFromBool(topics & (@as(u8, 1) << @intCast(topic)) != 0);
    }
    assert(count >= 0);
    return count;
}

/// Counters mirror monotonic stats, so a store never moves them backwards.
fn store(counter: *Counter, value: u64) void {
    assert(value >= counter.get());
    counter.value.store(value, .monotonic);
}

test {
    _ = @import("metrics_test.zig");
}
