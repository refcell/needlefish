//! Prometheus metrics for a tx_manager user (base/base `TxMetrics`): sends submitted,
//! confirmed, failed by reason, fee bumps, sends pending, and submit-to-completion latency.
//!
//! Caller-driven, like the manager itself: call `on_submit` after a send is accepted,
//! `on_completion` with each taken completion, and `set_pending` once per tick, then
//! `register` the metrics in a `utilities/metrics` registry. All metrics are fixed fields.

const std = @import("std");
const assert = std.debug.assert;

const metrics = @import("../../utilities/metrics/root.zig");
const manager = @import("manager.zig");

const Failure = manager.Failure;
const failure_count = std.enums.values(Failure).len;

/// Latency buckets in seconds: 200 ms L2 blocks up to a stuck send.
const latency_bounds_s = [_]f64{ 0.2, 0.4, 0.6, 1, 2, 4, 8, 16, 32, 64, 128 };

/// Entries `register` adds.
pub const entries_count = 6 + failure_count;

pub const Metrics = struct {
    submitted: metrics.Counter = .{},
    confirmed: metrics.Counter = .{},
    /// Mined at depth but the receipt reports execution failure.
    reverted: metrics.Counter = .{},
    failed: [failure_count]metrics.Counter = @splat(.{}),
    bumps: metrics.Counter = .{},
    pending: metrics.Gauge = .{},
    latency: metrics.Histogram = .init(&latency_bounds_s),

    pub fn on_submit(tx_metrics: *Metrics) void {
        tx_metrics.submitted.increment();
        assert(tx_metrics.submitted.get() > 0);
    }

    pub fn on_completion(
        tx_metrics: *Metrics,
        completion: manager.Completion,
        now_ms: u64,
    ) void {
        const done_before = tx_metrics.done_count();
        switch (completion.outcome) {
            .confirmed => |confirmed| if (confirmed.success)
                tx_metrics.confirmed.increment()
            else
                tx_metrics.reverted.increment(),
            .failed => |failure| tx_metrics.failed[@backingInt(failure)].increment(),
        }
        tx_metrics.bumps.add(completion.bump_count);
        const latency_ms = now_ms -| completion.submitted_at_ms;
        tx_metrics.latency.observe_ns(latency_ms * std.time.ns_per_ms);
        assert(tx_metrics.done_count() == done_before + 1);
    }

    pub fn set_pending(tx_metrics: *Metrics, pending_count: u32) void {
        tx_metrics.pending.set(pending_count);
        assert(tx_metrics.pending.get() >= 0);
    }

    /// Sends confirmed or failed so far.
    pub fn done_count(tx_metrics: *const Metrics) u64 {
        var total = tx_metrics.confirmed.get() + tx_metrics.reverted.get();
        for (&tx_metrics.failed) |*counter| total += counter.get();
        return total;
    }

    /// Adds `entries_count` entries named `tx_manager_*` to `registry`.
    pub fn register(tx_metrics: *Metrics, registry: anytype) !void {
        const count_before = registry.count;
        try registry.counter(
            "tx_manager_submitted_total",
            "Sends accepted by the transaction manager.",
            &tx_metrics.submitted,
        );
        try registry.register(outcome_entry("confirmed", &tx_metrics.confirmed));
        try registry.register(outcome_entry("reverted", &tx_metrics.reverted));
        inline for (comptime std.enums.values(Failure)) |failure| {
            const counter = &tx_metrics.failed[@backingInt(failure)];
            try registry.register(outcome_entry("failed_" ++ @tagName(failure), counter));
        }
        try registry.counter(
            "tx_manager_bumps_total",
            "Fee bumps of completed sends.",
            &tx_metrics.bumps,
        );
        try registry.gauge("tx_manager_pending", "Sends in flight.", &tx_metrics.pending);
        try registry.histogram(
            "tx_manager_completion_seconds",
            "Time from submit to confirmation or failure.",
            &tx_metrics.latency,
        );
        assert(registry.count == count_before + entries_count);
    }

    fn outcome_entry(comptime outcome: []const u8, counter: *metrics.Counter) metrics.Entry {
        const labels = [_]metrics.Label{.{ .name = "outcome", .value = outcome }};
        return .{
            .name = "tx_manager_completed_total",
            .help = "Sends completed, by outcome.",
            .labels = &labels,
            .metric = .{ .counter = counter },
        };
    }
};

const testing = std.testing;

fn completion_of(outcome: manager.Outcome, bumps: u64, submitted_at_ms: u64) manager.Completion {
    return .{
        .id = 1,
        .nonce = 0,
        .outcome = outcome,
        .publish_error = null,
        .bump_count = bumps,
        .submitted_at_ms = submitted_at_ms,
    };
}

test "tx_manager metrics: counts outcomes, bumps, and latency" {
    var tx_metrics: Metrics = .{};
    var registry: metrics.Registry(entries_count) = .{};
    try tx_metrics.register(&registry);
    tx_metrics.on_submit();
    tx_metrics.on_submit();
    tx_metrics.set_pending(2);
    const confirmed: manager.Outcome = .{ .confirmed = .{ .hash = @splat(0), .block_number = 7 } };
    tx_metrics.on_completion(completion_of(confirmed, 1, 1000), 1300);
    tx_metrics.on_completion(completion_of(.{ .failed = .send_timeout }, 2, 1000), 61_000);
    const reverted: manager.Outcome = .{ .confirmed = .{
        .hash = @splat(1),
        .block_number = 8,
        .success = false,
    } };
    tx_metrics.on_completion(completion_of(reverted, 0, 1000), 1100);
    tx_metrics.set_pending(0);
    try testing.expectEqual(@as(u64, 3), tx_metrics.done_count());
    try testing.expectEqual(@as(u64, 3), tx_metrics.bumps.get());
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try registry.write_prometheus(&writer);
    const text = writer.buffered();
    const expected = [_][]const u8{
        "tx_manager_submitted_total 2",
        "tx_manager_completed_total{outcome=\"confirmed\"} 1",
        "tx_manager_completed_total{outcome=\"failed_send_timeout\"} 1",
        "tx_manager_completed_total{outcome=\"failed_nonce_too_low\"} 0",
        "tx_manager_pending 0",
        "tx_manager_completion_seconds_bucket{le=\"0.4\"} 2",
        "tx_manager_completed_total{outcome=\"reverted\"} 1",
        "tx_manager_completion_seconds_count 3",
    };
    for (expected) |line| {
        if (std.mem.indexOf(u8, text, line) == null) {
            std.debug.print("missing {s} in\n{s}\n", .{ line, text });
            return error.TestUnexpectedResult;
        }
    }
}
