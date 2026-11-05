//! Consensus node metrics in Prometheus text format on `GET /metrics` (base/base
//! `--metrics.enabled/addr/port`, default port 9090).
//!
//! Names follow base/base's `base_node` namespace where a metric maps directly:
//! `base_node_block_labels{label=...}` (head numbers, labels `unsafe`, `local-safe`, `safe`,
//! `finalized`), `base_node_engine_task_queue_depth` and `base_node_engine_reset_count`.
//! Driver activity is exported as `base_node_*_total` counters. `record` samples the
//! node each tick: counters advance by the growth of the driver's monotonic stats.

const std = @import("std");
const assert = std.debug.assert;

const utilities_metrics = @import("../../utilities/metrics/root.zig");
const http = @import("../../utilities/http/root.zig");
const driver_module = @import("driver.zig");
const engine_state = @import("../engine/state.zig");

const Counter = utilities_metrics.Counter;
const Gauge = utilities_metrics.Gauge;
const Label = utilities_metrics.Label;

pub const default_port: u16 = 9090;
pub const Registry = utilities_metrics.Registry(24);

/// Everything `record` samples, gathered by the node.
pub const Sample = struct {
    sync_state: engine_state.SyncState,
    l1_head: u64,
    queue_depth: u32,
    stats: driver_module.Stats,
    peers: u32 = 0,
};

const label_unsafe = [_]Label{.{ .name = "label", .value = "unsafe" }};
const label_local_safe = [_]Label{.{ .name = "label", .value = "local-safe" }};
const label_safe = [_]Label{.{ .name = "label", .value = "safe" }};
const label_finalized = [_]Label{.{ .name = "label", .value = "finalized" }};

pub const Metrics = struct {
    unsafe_head: Gauge = .{},
    local_safe_head: Gauge = .{},
    safe_head: Gauge = .{},
    finalized_head: Gauge = .{},
    l1_head: Gauge = .{},
    queue_depth: Gauge = .{},
    peers: Gauge = .{},
    resets: Counter = .{},
    consolidated: Counter = .{},
    sealed: Counter = .{},
    finalized: Counter = .{},
    unsafe_queued: Counter = .{},
    unsafe_ignored: Counter = .{},
    engine_failures: Counter = .{},
    derivation_failures: Counter = .{},
    critical_errors: Counter = .{},
    el_sync_probes: Counter = .{},
    registry: Registry = .{},

    /// `metrics` must not move afterwards: the registry points into it.
    pub fn register(metrics: *Metrics) utilities_metrics.RegisterError!void {
        assert(metrics.registry.count == 0);
        const r = &metrics.registry;
        const labels_help = "Blockchain head labels";
        try metrics.head(labels_help, &label_unsafe, &metrics.unsafe_head);
        try metrics.head(labels_help, &label_local_safe, &metrics.local_safe_head);
        try metrics.head(labels_help, &label_safe, &metrics.safe_head);
        try metrics.head(labels_help, &label_finalized, &metrics.finalized_head);
        try r.gauge("base_node_l1_head", "Latest L1 block number seen.", &metrics.l1_head);
        const depth_help = "Number of tasks currently pending in the engine task queue";
        try r.gauge("base_node_engine_task_queue_depth", depth_help, &metrics.queue_depth);
        try r.gauge("base_node_peer_count", "Connected p2p peers.", &metrics.peers);
        try r.counter("base_node_engine_reset_count", "Engine reset count", &metrics.resets);
        try metrics.counters();
        assert(metrics.registry.count == 17);
    }

    fn head(metrics: *Metrics, help: []const u8, labels: []const Label, gauge: *Gauge) !void {
        try metrics.registry.register(.{
            .name = "base_node_block_labels",
            .help = help,
            .labels = labels,
            .metric = .{ .gauge = gauge },
        });
    }

    fn counters(metrics: *Metrics) !void {
        const r = &metrics.registry;
        const consolidated = &metrics.consolidated;
        try r.counter("base_node_consolidated_total", "Derived safe blocks.", consolidated);
        try r.counter("base_node_sealed_total", "Sequenced blocks sealed.", &metrics.sealed);
        const finalized = &metrics.finalized;
        try r.counter("base_node_finalized_total", "Finalize tasks done.", finalized);
        const queued = &metrics.unsafe_queued;
        try r.counter("base_node_unsafe_payloads_queued_total", "Unsafe payloads queued.", queued);
        const ignored = &metrics.unsafe_ignored;
        const ignored_name = "base_node_unsafe_payloads_ignored_total";
        try r.counter(ignored_name, "Unsafe payloads ignored.", ignored);
        const engine = &metrics.engine_failures;
        try r.counter("base_node_engine_failures_total", "Failed engine tasks.", engine);
        const derivation = &metrics.derivation_failures;
        try r.counter("base_node_derivation_failures_total", "Derivation resets.", derivation);
        const critical = &metrics.critical_errors;
        try r.counter("base_node_critical_errors_total", "Critical errors.", critical);
        const probes = &metrics.el_sync_probes;
        try r.counter("base_node_el_sync_probes_total", "EL sync probes sent.", probes);
    }

    pub fn record(metrics: *Metrics, sample: *const Sample) void {
        const state = &sample.sync_state;
        metrics.unsafe_head.set(clamp(state.unsafe_head.block_info.number));
        metrics.local_safe_head.set(clamp(state.local_safe_head.block_info.number));
        metrics.safe_head.set(clamp(state.safe_head.block_info.number));
        metrics.finalized_head.set(clamp(state.finalized_head.block_info.number));
        metrics.l1_head.set(clamp(sample.l1_head));
        metrics.queue_depth.set(sample.queue_depth);
        metrics.peers.set(sample.peers);
        const stats = &sample.stats;
        advance(&metrics.resets, stats.resets);
        advance(&metrics.consolidated, stats.consolidated);
        advance(&metrics.sealed, stats.sealed);
        advance(&metrics.finalized, stats.finalized);
        advance(&metrics.unsafe_queued, stats.unsafe_queued);
        advance(&metrics.unsafe_ignored, stats.unsafe_ignored);
        advance(&metrics.engine_failures, stats.engine_failures);
        advance(&metrics.derivation_failures, stats.derivation_failures);
        advance(&metrics.critical_errors, stats.critical_errors);
        advance(&metrics.el_sync_probes, stats.el_sync_probes);
        assert(metrics.resets.get() >= stats.resets);
    }

    /// HTTP handler: `GET /metrics` renders the registry; anything else is 404/405.
    pub fn handle(
        metrics: *Metrics,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        assert(metrics.registry.count > 0);
        const target = request.target;
        const path_end = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
        if (!std.mem.eql(u8, target[0..path_end], "/metrics")) return response.fail(404);
        if (request.method != .GET and request.method != .HEAD) return response.fail(405);
        response.content_type = "text/plain; version=0.0.4";
        metrics.registry.write_prometheus(response.writer()) catch return response.fail(500);
    }
};

fn clamp(value: u64) i64 {
    return @intCast(@min(value, std.math.maxInt(i64)));
}

/// Moves a counter up to a monotonic total (never down).
fn advance(counter: *Counter, total: u64) void {
    const current = counter.get();
    if (total > current) counter.add(total - current);
    assert(counter.get() >= current);
}

const testing = std.testing;

fn render(metrics: *Metrics, buffer: []u8) ![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    try metrics.registry.write_prometheus(&out);
    return out.buffered();
}

test "metrics: block labels, queue depth and driver counters" {
    var metrics: Metrics = .{};
    try metrics.register();
    var sample: Sample = .{
        .sync_state = .{
            .unsafe_head = .{ .block_info = .{ .number = 12 } },
            .local_safe_head = .{ .block_info = .{ .number = 9 } },
            .safe_head = .{ .block_info = .{ .number = 8 } },
            .finalized_head = .{ .block_info = .{ .number = 4 } },
        },
        .l1_head = 30,
        .queue_depth = 2,
        .stats = .{ .resets = 1, .consolidated = 5, .sealed = 3 },
    };
    metrics.record(&sample);
    sample.stats.consolidated = 7;
    metrics.record(&sample);
    var buffer: [8192]u8 = undefined;
    const text = try render(&metrics, &buffer);
    const expected = [_][]const u8{
        "base_node_block_labels{label=\"unsafe\"} 12",
        "base_node_block_labels{label=\"local-safe\"} 9",
        "base_node_block_labels{label=\"safe\"} 8",
        "base_node_block_labels{label=\"finalized\"} 4",
        "base_node_l1_head 30",
        "base_node_engine_task_queue_depth 2",
        "base_node_engine_reset_count 1",
        "base_node_consolidated_total 7",
        "base_node_sealed_total 3",
    };
    for (expected) |line| {
        if (std.mem.indexOf(u8, text, line) == null) {
            std.debug.print("missing {s} in\n{s}\n", .{ line, text });
            return error.TestExpectedEqual;
        }
    }
    // One HELP/TYPE block for the labeled family.
    const families = std.mem.count(u8, text, "# TYPE base_node_block_labels");
    try testing.expectEqual(@as(usize, 1), families);
}

test "metrics: seeded fuzz, counters follow monotonic totals" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x3e7);
    var metrics: Metrics = .{};
    try metrics.register();
    var sample: Sample = .{ .sync_state = .{}, .l1_head = 0, .queue_depth = 0, .stats = .{} };
    for (0..512) |_| {
        sample.stats.consolidated += prng.below(4);
        sample.stats.resets += prng.below(2);
        sample.queue_depth = @intCast(prng.below(64));
        sample.l1_head = prng.int(u64);
        metrics.record(&sample);
        try testing.expectEqual(sample.stats.consolidated, metrics.consolidated.get());
        try testing.expectEqual(sample.stats.resets, metrics.resets.get());
        try testing.expect(metrics.l1_head.get() >= 0);
    }
}
