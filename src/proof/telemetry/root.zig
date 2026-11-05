//! Health, readiness and Prometheus metrics for the proof services (base/base's
//! `define_health_args`/`define_metrics_args` servers for the proposer and challenger):
//! liveness (`/`, `/healthz`), readiness (`/readyz`: progress within
//! `stale_after_intervals` poll intervals) and `/metrics`. `Exporter(Stats, prefix)`
//! registers every `u64` field of `Stats` as the counter `<prefix>_<field>_total`, with
//! help text from `Stats.descriptions`. The service loop calls `observe` after every step
//! with its stats and a monotonic progress count; scrapes read the copies only.

const std = @import("std");
const assert = std.debug.assert;

const metrics = @import("../../utilities/metrics/root.zig");
const health = @import("../../utilities/health/root.zig");
const http = @import("../../utilities/http/root.zig");

pub const Clock = struct {
    context: *anyopaque,
    now_ns: *const fn (context: *anyopaque) u64,

    fn read(clock: Clock) u64 {
        return clock.now_ns(clock.context);
    }
};

pub const Options = struct {
    version: []const u8,
    poll_interval_ns: u64,
    stale_after_intervals: u32 = 5,
};

pub fn Exporter(comptime Stats: type, comptime prefix: []const u8) type {
    const info = @typeInfo(Stats).@"struct";
    const names = info.field_names;
    comptime {
        assert(names.len > 0);
        for (names, info.field_types) |name, field_type| {
            assert(field_type == u64);
            // Every counter has help text.
            _ = @field(Stats.descriptions, name);
        }
    }
    return struct {
        const Self = @This();
        pub const counters_count = names.len;

        clock: Clock,
        options: Options,
        registry: metrics.Registry(counters_count + 1) = .{},
        counters: [counters_count]metrics.Counter = @splat(.{}),
        last_progress_age_s: metrics.Gauge = .{},
        /// When progress was last observed; null before the first.
        progress_ns: ?u64 = null,
        progress_last: u64 = 0,

        /// In place: the registry keeps pointers into `exporter`.
        pub fn init(exporter: *Self, clock: Clock, options: Options) !void {
            assert(options.poll_interval_ns > 0);
            assert(options.stale_after_intervals > 0);
            exporter.* = .{ .clock = clock, .options = options };
            inline for (names, &exporter.counters) |name, *slot| {
                const metric = prefix ++ "_" ++ name ++ "_total";
                try exporter.registry.counter(metric, @field(Stats.descriptions, name), slot);
            }
            try exporter.registry.gauge(
                prefix ++ "_last_progress_age_seconds",
                "Seconds since the service last made progress (-1 before the first).",
                &exporter.last_progress_age_s,
            );
            exporter.last_progress_age_s.set(-1);
            assert(exporter.registry.count == counters_count + 1);
        }

        /// Copies `stats` (counters never go backwards); a larger `progress` than last
        /// time marks progress now.
        pub fn observe(exporter: *Self, stats: Stats, progress: u64) void {
            assert(progress >= exporter.progress_last);
            inline for (names, &exporter.counters) |name, *slot| {
                const value = @field(stats, name);
                assert(value >= slot.get());
                slot.add(value - slot.get());
            }
            if (progress > exporter.progress_last) exporter.progress_ns = exporter.clock.read();
            exporter.progress_last = progress;
        }

        pub fn counter(exporter: *const Self, comptime field: []const u8) u64 {
            return exporter.counters[comptime std.meta.fieldIndex(Stats, field).?].get();
        }

        /// True when progress was observed within the staleness window.
        pub fn ready(exporter: *const Self) bool {
            const progress_ns = exporter.progress_ns orelse return false;
            const now_ns = exporter.clock.read();
            assert(now_ns >= progress_ns);
            const window_ns = exporter.options.poll_interval_ns *|
                exporter.options.stale_after_intervals;
            return now_ns - progress_ns <= window_ns;
        }

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
            if (exporter.progress_ns) |progress_ns| {
                const age_s = (exporter.clock.read() - progress_ns) / std.time.ns_per_s;
                exporter.last_progress_age_s.set(@intCast(@min(age_s, std.math.maxInt(i64))));
            }
            response.content_type = "text/plain; version=0.0.4";
            exporter.registry.write_prometheus(response.writer()) catch response.fail(500);
        }
    };
}

/// A settable clock for tests.
pub const FakeClock = struct {
    now_ns: u64 = 0,

    fn read_fake(context: *anyopaque) u64 {
        const fake: *FakeClock = @ptrCast(@alignCast(context));
        return fake.now_ns;
    }

    pub fn clock(fake: *FakeClock) Clock {
        return .{ .context = fake, .now_ns = read_fake };
    }
};

/// A GET of `target` against `exporter` (tests).
pub fn get(exporter: anytype, buffer: []u8, target: []const u8) http.ResponseBuilder {
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

pub fn contains(response: *http.ResponseBuilder, needle: []const u8) bool {
    return std.mem.indexOf(u8, response.body.buffered(), needle) != null;
}

const testing = std.testing;

const TestStats = struct {
    steps: u64 = 0,
    errors: u64 = 0,

    pub const descriptions = .{ .steps = "Steps.", .errors = "Failed steps." };
};
const TestExporter = Exporter(TestStats, "test_service");

test "telemetry: readiness follows progress, metrics follow the stats" {
    var fake: FakeClock = .{ .now_ns = 100 * std.time.ns_per_s };
    var exporter: TestExporter = undefined;
    try exporter.init(fake.clock(), .{
        .version = "v-test",
        .poll_interval_ns = std.time.ns_per_s,
        .stale_after_intervals = 3,
    });
    var buffer: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    var response = get(&exporter, &buffer, "/metrics");
    try testing.expect(contains(&response, "test_service_last_progress_age_seconds -1"));
    exporter.observe(.{ .steps = 1, .errors = 1 }, 0);
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    exporter.observe(.{ .steps = 2, .errors = 1 }, 1);
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/readyz").status);
    fake.now_ns += 2 * std.time.ns_per_s;
    response = get(&exporter, &buffer, "/metrics");
    try testing.expect(contains(&response, "# HELP test_service_errors_total Failed steps."));
    try testing.expect(contains(&response, "test_service_steps_total 2"));
    try testing.expect(contains(&response, "test_service_last_progress_age_seconds 2"));
    try testing.expectEqual(@as(u64, 1), exporter.counter("errors"));
    // No progress for longer than the window: no longer ready.
    exporter.observe(.{ .steps = 5, .errors = 4 }, 1);
    fake.now_ns += 2 * std.time.ns_per_s;
    try testing.expectEqual(@as(u16, 503), get(&exporter, &buffer, "/readyz").status);
    exporter.observe(.{ .steps = 6, .errors = 4 }, 2);
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/readyz").status);
}

test "telemetry: health and unknown paths" {
    var fake: FakeClock = .{};
    var exporter: TestExporter = undefined;
    try exporter.init(fake.clock(), .{ .version = "v-test", .poll_interval_ns = 1 });
    var buffer: [4096]u8 = undefined;
    var response = get(&exporter, &buffer, "/healthz");
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", response.body.buffered());
    try testing.expectEqual(@as(u16, 404), get(&exporter, &buffer, "/nope").status);
    try testing.expectEqual(@as(u16, 200), get(&exporter, &buffer, "/metrics?x=1").status);
}

test "telemetry: fuzz observations keep counters monotonic" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var fake: FakeClock = .{};
            var exporter: TestExporter = undefined;
            try exporter.init(fake.clock(), .{ .version = "v", .poll_interval_ns = 10 });
            var stats: TestStats = .{};
            var progress: u64 = 0;
            for (0..32) |_| {
                const progressed = smith.value(bool);
                stats.steps += 1;
                if (!progressed) stats.errors += 1;
                if (progressed) progress += 1;
                fake.now_ns += smith.value(u8);
                exporter.observe(stats, progress);
                if (progressed) try testing.expect(exporter.ready());
                try testing.expectEqual(stats.steps, exporter.counter("steps"));
                try testing.expectEqual(stats.errors, exporter.counter("errors"));
            }
        }
    }.one, .{ .iterations = 500 });
}
