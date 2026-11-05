//! The proposer's HTTP endpoints (base/base `crates/proof/proposer` health server and
//! metrics): liveness (`/`, `/healthz`), readiness (`/readyz`: a tick made progress within
//! `stale_after_intervals` poll intervals), and Prometheus `/metrics` with the pipeline
//! and collector counters. The service loop calls `observe` after every tick; scrapes read
//! the copied values only, so the handler never touches the pipeline.

const std = @import("std");
const assert = std.debug.assert;

const metrics = @import("../../utilities/metrics/root.zig");
const health = @import("../../utilities/health/root.zig");
const http = @import("../../utilities/http/root.zig");
const pipeline_module = @import("pipeline.zig");
const collector_module = @import("collector.zig");

pub const Clock = struct {
    context: *anyopaque,
    now_ns: *const fn (context: *anyopaque) u64,
};

pub const Options = struct {
    version: []const u8,
    poll_interval_ns: u64,
    stale_after_intervals: u32 = 5,
};

const counter_names = [_][2][]const u8{
    .{ "base_proposer_ticks_total", "Pipeline ticks." },
    .{ "base_proposer_ticks_skipped_total", "Ticks skipped (chain or prover unavailable)." },
    .{ "base_proposer_restarts_total", "Pipeline restarts from fresh on-chain state." },
    .{ "base_proposer_proofs_ready_total", "Proofs the prover finished." },
    .{ "base_proposer_proofs_failed_total", "Proofs the prover failed." },
    .{ "base_proposer_root_mismatches_total", "Proofs whose root differed from the chain." },
    .{ "base_proposer_games_created_total", "Dispute games this proposer created." },
    .{ "base_proposer_games_adopted_total", "Games found already created by someone else." },
    .{ "base_proposer_submit_failures_total", "Game creations that failed or were dropped." },
};
const counters_count = counter_names.len;

pub const Exporter = struct {
    clock: Clock,
    options: Options,
    registry: metrics.Registry(counters_count + 1) = .{},
    counters: [counters_count]metrics.Counter = @splat(.{}),
    last_progress_age_s: metrics.Gauge = .{},
    /// When a tick last made progress (not skipped); null before the first.
    progress_ns: ?u64 = null,

    /// In place: the registry keeps pointers into `exporter`.
    pub fn init(exporter: *Exporter, clock: Clock, options: Options) !void {
        assert(options.poll_interval_ns > 0);
        assert(options.stale_after_intervals > 0);
        exporter.* = .{ .clock = clock, .options = options };
        for (counter_names, &exporter.counters) |names, *counter| {
            try exporter.registry.counter(names[0], names[1], counter);
        }
        try exporter.registry.gauge(
            "base_proposer_last_progress_age_seconds",
            "Seconds since a tick last made progress (-1 before the first).",
            &exporter.last_progress_age_s,
        );
        exporter.last_progress_age_s.set(-1);
        assert(exporter.registry.count == counters_count + 1);
    }

    /// Copies the counters after a tick; a tick that was not skipped counts as progress.
    pub fn observe(
        exporter: *Exporter,
        pipeline: pipeline_module.Pipeline.Stats,
        collector: collector_module.Collector.Stats,
    ) void {
        assert(pipeline.skipped <= pipeline.ticks);
        const values = [counters_count]u64{
            pipeline.ticks,          pipeline.skipped,        pipeline.restarts,
            collector.proofs_ready,  collector.proofs_failed, collector.root_mismatches,
            collector.games_created, collector.games_adopted, collector.submit_failures,
        };
        const progressed = pipeline.ticks - pipeline.skipped > exporter.progress_ticks();
        for (values, &exporter.counters) |value, *counter| {
            // Counters never go backwards: a restarted pipeline keeps its stats.
            assert(value >= counter.get());
            counter.add(value - counter.get());
        }
        if (progressed) exporter.progress_ns = exporter.clock.now_ns(exporter.clock.context);
    }

    fn progress_ticks(exporter: *const Exporter) u64 {
        const ticks = exporter.counters[0].get();
        const skipped = exporter.counters[1].get();
        assert(skipped <= ticks);
        return ticks - skipped;
    }

    /// True when a tick made progress within the staleness window.
    pub fn ready(exporter: *const Exporter) bool {
        const progress_ns = exporter.progress_ns orelse return false;
        const now_ns = exporter.clock.now_ns(exporter.clock.context);
        assert(now_ns >= progress_ns);
        const window_ns = exporter.options.poll_interval_ns *|
            exporter.options.stale_after_intervals;
        return now_ns - progress_ns <= window_ns;
    }

    pub fn handle(
        exporter: *Exporter,
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
        if (exporter.progress_ns) |progress_ns| {
            const now_ns = exporter.clock.now_ns(exporter.clock.context);
            const age_s = (now_ns - progress_ns) / std.time.ns_per_s;
            exporter.last_progress_age_s.set(@intCast(@min(age_s, std.math.maxInt(i64))));
        }
        response.content_type = "text/plain; version=0.0.4";
        exporter.registry.write_prometheus(response.writer()) catch response.fail(500);
    }
};

const testing = std.testing;

const FakeClock = struct {
    now_ns: u64 = 0,

    fn read(context: *anyopaque) u64 {
        const fake: *FakeClock = @ptrCast(@alignCast(context));
        return fake.now_ns;
    }

    fn clock(fake: *FakeClock) Clock {
        return .{ .context = fake, .now_ns = read };
    }
};

fn get(exporter: *Exporter, buffer: []u8, target: []const u8) http.ResponseBuilder {
    var response = http.ResponseBuilder.init(buffer);
    const request: http.Request = .{
        .method = .GET,
        .method_text = "GET",
        .target = target,
        .version = .http_1_1,
        .headers = .{},
        .body = "",
        .keep_alive = true,
    };
    exporter.handle(&request, &response);
    return response;
}

fn contains(response: *http.ResponseBuilder, needle: []const u8) bool {
    return std.mem.indexOf(u8, response.body.buffered(), needle) != null;
}

test "proposer exporter: readiness follows progress, metrics follow the pipeline" {
    var fake: FakeClock = .{ .now_ns = 100 * std.time.ns_per_s };
    var exporter: Exporter = undefined;
    try exporter.init(fake.clock(), .{
        .version = "v-test",
        .poll_interval_ns = std.time.ns_per_s,
        .stale_after_intervals = 3,
    });
    var buffer: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    var response = get(&exporter, &buffer, "/metrics");
    try testing.expect(contains(&response, "base_proposer_last_progress_age_seconds -1"));

    // A skipped tick is not progress.
    exporter.observe(.{ .ticks = 1, .skipped = 1 }, .{});
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    exporter.observe(.{ .ticks = 2, .skipped = 1 }, .{ .proofs_ready = 1, .games_created = 1 });
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/readyz").status);
    fake.now_ns += 2 * std.time.ns_per_s;
    response = get(&exporter, &buffer, "/metrics");
    try testing.expect(contains(&response, "base_proposer_ticks_total 2"));
    try testing.expect(contains(&response, "base_proposer_ticks_skipped_total 1"));
    try testing.expect(contains(&response, "base_proposer_games_created_total 1"));
    try testing.expect(contains(&response, "base_proposer_last_progress_age_seconds 2"));

    // Only skipped ticks for longer than the window: no longer ready.
    exporter.observe(.{ .ticks = 5, .skipped = 4 }, .{ .proofs_ready = 1, .games_created = 1 });
    fake.now_ns += 2 * std.time.ns_per_s;
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    exporter.observe(.{ .ticks = 6, .skipped = 4 }, .{ .proofs_ready = 2, .games_created = 1 });
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/readyz").status);
}

test "proposer exporter: health and unknown paths" {
    var fake: FakeClock = .{};
    var exporter: Exporter = undefined;
    try exporter.init(fake.clock(), .{ .version = "v-test", .poll_interval_ns = 1 });
    var buffer: [4096]u8 = undefined;
    var response = get(&exporter, &buffer, "/healthz");
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", response.body.buffered());
    try testing.expectEqual(@as(u16, 404), get(&exporter, &buffer, "/nope").status);
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/metrics?x=1").status);
}

test "proposer exporter: fuzz observations keep counters monotonic" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var fake: FakeClock = .{};
            var exporter: Exporter = undefined;
            try exporter.init(fake.clock(), .{ .version = "v", .poll_interval_ns = 10 });
            var stats: pipeline_module.Pipeline.Stats = .{};
            var collector: collector_module.Collector.Stats = .{};
            for (0..32) |_| {
                const skipped = smith.value(bool);
                stats.ticks += 1;
                if (skipped) stats.skipped += 1;
                collector.proofs_ready += smith.value(u8) % 3;
                fake.now_ns += smith.value(u8);
                exporter.observe(stats, collector);
                if (!skipped) try testing.expect(exporter.ready());
                try testing.expectEqual(stats.ticks, exporter.counters[0].get());
                try testing.expectEqual(collector.proofs_ready, exporter.counters[3].get());
            }
        }
    }.one, .{ .iterations = 500 });
}
