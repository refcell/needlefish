//! Standalone balance monitor (`base balance-monitor`): polls one account's balance with
//! `utilities/balance_monitor` and serves it over HTTP.
//!
//! base/base ships balance monitoring as a library layer inside the batcher, proposer, and
//! challenger. needlefish also exposes it as a tool so an operator can watch any signer
//! account (for example a withdrawer or load-test funder) without running a service.
//!
//! Endpoints on one HTTP server:
//!   GET /         liveness (`utilities/health`)
//!   GET /healthz  version (`utilities/health`)
//!   GET /readyz   200 once a balance was read within `stale_after_intervals` polls, else 503
//!   GET /metrics  Prometheus text: balance (gwei and wei-as-float), reads, failures, skips,
//!                 and seconds since the last successful read.

const std = @import("std");
const assert = std.debug.assert;

const balance_monitor = @import("../../utilities/balance_monitor/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const health = @import("../../utilities/health/root.zig");
const http = @import("../../utilities/http/root.zig");

pub const Address = balance_monitor.Address;

pub const Options = struct {
    monitor: balance_monitor.Options = .{},
    /// Readiness fails when the last successful read is older than this many intervals.
    stale_after_intervals: u32 = 3,
    version: []const u8 = "unknown",
};

pub fn Exporter(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Monitor = balance_monitor.Monitor(IO);

        monitor: Monitor,
        io: *IO,
        options: Options,
        registry: metrics.Registry(8) = .{},
        balance_gwei: metrics.Gauge = .{},
        updates: metrics.Counter = .{},
        failures: metrics.Counter = .{},
        polls_skipped: metrics.Counter = .{},
        last_update_age_s: metrics.Gauge = .{},

        /// In place: the monitor and the registry keep pointers into `exporter`.
        pub fn init(
            exporter: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            endpoint: Address,
            account: [20]u8,
            options: Options,
        ) !void {
            assert(options.stale_after_intervals > 0);
            exporter.* = .{ .monitor = undefined, .io = io, .options = options };
            try exporter.monitor.init(allocator, io, endpoint, account, options.monitor);
            errdefer exporter.monitor.deinit();
            const registry = &exporter.registry;
            try registry.gauge(
                "balance_monitor_balance_gwei",
                "Account balance in gwei (last successful read).",
                &exporter.balance_gwei,
            );
            try registry.counter(
                "balance_monitor_reads_total",
                "Successful balance reads.",
                &exporter.updates,
            );
            try registry.counter(
                "balance_monitor_failures_total",
                "Failed balance reads.",
                &exporter.failures,
            );
            try registry.counter(
                "balance_monitor_polls_skipped_total",
                "Polls skipped because the previous read was still in flight.",
                &exporter.polls_skipped,
            );
            try registry.gauge(
                "balance_monitor_last_read_age_seconds",
                "Seconds since the last successful read (-1 before the first).",
                &exporter.last_update_age_s,
            );
            assert(registry.count == 5);
        }

        pub fn deinit(exporter: *Self) void {
            exporter.monitor.deinit();
            exporter.* = undefined;
        }

        pub fn start(exporter: *Self) void {
            exporter.monitor.start();
        }

        pub fn stop(exporter: *Self) void {
            exporter.monitor.stop();
        }

        pub fn stopped(exporter: *const Self) bool {
            return exporter.monitor.stopped();
        }

        /// True once a read succeeded within the staleness window.
        pub fn ready(exporter: *const Self) bool {
            if (exporter.monitor.updates == 0) return false;
            const now_ns = exporter.io.now_monotonic_ns();
            assert(now_ns >= exporter.monitor.last_update_ns);
            const age_ns = now_ns - exporter.monitor.last_update_ns;
            const window_ns = exporter.options.monitor.poll_interval_ns *|
                exporter.options.stale_after_intervals;
            return age_ns <= window_ns;
        }

        /// HTTP handler for `http.Server`.
        pub fn handle(
            exporter: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (health.respond(exporter.options.version, request, response)) return;
            const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse
                request.target.len;
            const path = request.target[0..path_end];
            if (request.method != .GET and request.method != .HEAD) return response.fail(405);
            if (std.mem.eql(u8, path, "/readyz")) {
                response.content_type = "text/plain";
                response.status = if (exporter.ready()) 200 else 503;
                return;
            }
            if (!std.mem.eql(u8, path, "/metrics")) return response.fail(404);
            exporter.sync();
            response.content_type = "text/plain; version=0.0.4";
            exporter.registry.write_prometheus(response.writer()) catch response.fail(500);
        }

        /// Copies the monitor's counters into the metrics (pull model: only on scrape).
        fn sync(exporter: *Self) void {
            const monitor = &exporter.monitor;
            sync_counter(&exporter.updates, monitor.updates);
            sync_counter(&exporter.failures, monitor.failures);
            sync_counter(&exporter.polls_skipped, monitor.polls_skipped);
            const gwei = monitor.balance / 1_000_000_000;
            exporter.balance_gwei.set(@intCast(@min(gwei, std.math.maxInt(i64))));
            if (monitor.updates == 0) {
                exporter.last_update_age_s.set(-1);
                return;
            }
            const now_ns = exporter.io.now_monotonic_ns();
            const age_s = (now_ns - monitor.last_update_ns) / std.time.ns_per_s;
            exporter.last_update_age_s.set(@intCast(@min(age_s, std.math.maxInt(i64))));
        }

        fn sync_counter(counter: *metrics.Counter, value: u64) void {
            const current = counter.get();
            assert(value >= current);
            counter.add(value - current);
            assert(counter.get() == value);
        }
    };
}

test {
    _ = @import("tests.zig");
}
